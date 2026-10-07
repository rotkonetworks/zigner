//! zafu's one-round THORChain swap: ONE 0x04 batch carrying the move (V6,
//! ironwood -> the swap's own t-address, index 57) and the deposit that
//! spends the move's output before the move is signed or mined (V5 t->t
//! [vault, OP_RETURN memo, change]; its input is (move txid, 0), the txid read
//! from the unsigned move). The PCZT carries the input's value and script, so
//! nothing here needs the chain: the device signs both in one scan, through
//! the SHIPPED module0.wasm and the native code alike.
//!
//! Request from zafu (zafu-wasm 8cef107) over zcli's dumped move:
//!   tests/fixtures/swap_one_round_request.hex
//! With SWAP_ONE_ROUND_OUT set, the module's response is written there, for
//! zafu's batch test.

use module_host::ModuleRuntime;
use pczt::Pczt;
use pczt_signing::envelope::{self, SignRequest};

const BUNDLED_MODULE_WASM: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../android/src/main/assets/modules/module0.wasm"
);
const REQUEST: &str = include_str!("fixtures/swap_one_round_request.hex");
const MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

fn check(resp: &[u8]) {
    let messages = envelope::parse_response(resp).expect("batch response parses");
    assert_eq!(resp[2], envelope::TX_TYPE_PCZT_BATCH, "a batch answers as a batch");
    assert_eq!(messages.len(), 2);
    assert_eq!((&messages[0].id[..], &messages[1].id[..]), (&[0u8][..], &[1u8][..]));
    for m in &messages {
        assert_eq!(m.digest, envelope::integrity_digest(&m.signed_pczt));
    }
    let moved = Pczt::parse(&messages[0].signed_pczt).expect("signed move parses");
    assert!(!moved.ironwood().actions().is_empty());
    assert!(
        moved.ironwood().actions().iter().any(|a| a.spend().spend_auth_sig().is_some()),
        "the move's ironwood spend is authorized"
    );
    let deposit = Pczt::parse(&messages[1].signed_pczt).expect("signed deposit parses");
    assert_eq!(deposit.transparent().inputs().len(), 1);
    // the spend finalizer turns each input's signature into its script_sig,
    // and refuses an input left unsigned
    pczt::roles::spend_finalizer::SpendFinalizer::new(deposit)
        .finalize_spends()
        .expect("the deposit's input (the unmined move's output) is signed");
}

#[test]
fn one_batch_signs_the_move_and_its_deposit() {
    let payload = hex::decode(REQUEST.trim()).unwrap();
    let SignRequest::Batch(messages) = envelope::parse_request(&payload).unwrap() else {
        panic!("a 0x04 batch");
    };
    assert_eq!(messages.len(), 2);

    // what the review screen shows, one card per message
    let summaries = pczt_signing::summarize_request(&payload).expect("summaries");
    assert_eq!(summaries.len(), 2);
    eprintln!("move:    {:?}", summaries[0]);
    eprintln!("deposit: {:?}", summaries[1]);
    assert!(summaries[0].ironwood_actions > 0);
    assert!(summaries[0]
        .outputs
        .iter()
        .any(|(to, zat)| to == "t-script:76a914a115e87cc4120aa8d73e983b10c4f4f072e9106288ac" && *zat == 425_000));
    assert_eq!(summaries[1].transparent_inputs, 1);
    assert_eq!(summaries[1].fee_zat, Some(25_000));

    // native
    check(&pczt_signing::sign_request(&payload, MNEMONIC, 0, true).expect("native signs both"));

    // the shipped module, the bytes the device runs
    let wasm = std::fs::read(BUNDLED_MODULE_WASM).expect("module wasm");
    let mut rt = ModuleRuntime::load(&wasm).expect("load module");
    rt.summarize_request(&payload).expect("module summarizes both");
    let resp = rt.sign_request(&payload, MNEMONIC, 0, true).expect("module signs both");
    check(&resp);
    if let Ok(out) = std::env::var("SWAP_ONE_ROUND_OUT") {
        std::fs::write(out, hex::encode(&resp)).unwrap();
    }
}
