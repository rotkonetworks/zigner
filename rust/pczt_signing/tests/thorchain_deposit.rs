//! The THORChain deposit, as zafu builds it for a cold signer: a V5 t->t
//! [vault, OP_RETURN(memo), change] spending one swap's own fresh t-address
//! (zcli `build_unsigned_transparent_core`). The device must show the memo in
//! words, show the fee, find the key at a swap index past the old gap limit,
//! and sign every input or refuse.

mod common;

use common::{test_rng, MNEMONIC};
use pczt::{
    roles::{
        creator::Creator, io_finalizer::IoFinalizer, spend_finalizer::SpendFinalizer,
        tx_extractor::TransactionExtractor,
    },
    Pczt,
};
use pczt_signing::envelope::{self, RequestMessage, SignRequest};
use zcash_keys::keys::UnifiedSpendingKey;
use zcash_primitives::transaction::{
    builder::{BuildConfig, Builder, BundlePadding},
    fees::zip317,
    TxVersion,
};
use zcash_protocol::{consensus::MainNetwork, value::Zatoshis};
use zcash_transparent::{
    address::TransparentAddress,
    bundle as transparent,
    keys::{NonHardenedChildIndex, TransparentKeyScope},
};
use zip32::AccountId;

const MEMO: &str = "=:ETH.ETH:0x1111111111111111111111111111111111111111:3100000/1/0:zafu:0";
const FEE: u64 = 25_000;

/// the device seed's external key at `index` (the 0.29 secp the stack uses)
macro_rules! pubkey_at {
    ($index:expr) => {{
        let mnemonic = bip39::Mnemonic::parse_in(bip39::Language::English, MNEMONIC).unwrap();
        let usk =
            UnifiedSpendingKey::from_seed(&MainNetwork, &mnemonic.to_seed(""), AccountId::ZERO)
                .unwrap();
        usk.transparent()
            .to_account_pubkey()
            .derive_address_pubkey(
                TransparentKeyScope::custom(0).unwrap(),
                NonHardenedChildIndex::from_index($index).unwrap(),
            )
            .unwrap()
    }};
}

/// zafu's deposit for the swap at t-branch `index`: two coins of that one
/// address, the vault at vout 0, the memo, change back to the same address.
fn deposit_pczt(index: u32, vault: &TransparentAddress) -> Vec<u8> {
    deposit_pczt_for(pubkey_at!(index), vault)
}

fn deposit_pczt_for(pubkey: secp256k1::PublicKey, vault: &TransparentAddress) -> Vec<u8> {
    let own = TransparentAddress::from_pubkey(&pubkey);
    let mut builder = Builder::new(
        MainNetwork,
        3_400_000.into(),
        BuildConfig::Standard {
            sapling_anchor: None,
            orchard_anchor: None,
            ironwood_anchor: None,
            orchard_padding: BundlePadding::DEFAULT,
            ironwood_padding: BundlePadding::DEFAULT,
        },
    );
    builder
        .propose_version::<core::convert::Infallible>(TxVersion::V5)
        .unwrap();
    for (n, value) in [(0u8, 600_000u64), (1, 500_000)] {
        builder
            .add_transparent_p2pkh_input(
                pubkey,
                transparent::OutPoint::new([0x40 + n; 32], u32::from(n)),
                transparent::TxOut::new(Zatoshis::from_u64(value).unwrap(), own.script().into()),
            )
            .unwrap();
    }
    builder
        .add_transparent_output(vault, Zatoshis::const_from_u64(1_000_000))
        .unwrap();
    builder
        .add_transparent_null_data_output::<core::convert::Infallible>(MEMO.as_bytes())
        .unwrap();
    builder
        .add_transparent_output(&own, Zatoshis::const_from_u64(1_100_000 - 1_000_000 - FEE))
        .unwrap();
    let parts = builder
        .build_for_pczt(test_rng(), &zip317::FeeRule::standard())
        .unwrap()
        .pczt_parts;
    let pczt = Creator::build_from_parts(parts).unwrap();
    IoFinalizer::new(pczt)
        .finalize_io()
        .unwrap()
        .serialize()
        .unwrap()
}

fn request(pczt: Vec<u8>) -> Vec<u8> {
    envelope::encode_request(&SignRequest::Batch(vec![RequestMessage {
        id: b"thor-1".to_vec(),
        pczt_bytes: pczt,
    }]))
    .unwrap()
}

fn vault() -> TransparentAddress {
    TransparentAddress::PublicKeyHash([0x77; 20])
}

#[test]
fn deposit_review_and_sign() {
    // index 57: past the 20-key window the device used to search
    let payload = request(deposit_pczt(57, &vault()));
    let summary = &pczt_signing::summarize_request(&payload).expect("summarize")[0];

    assert_eq!(summary.transparent_inputs, 2);
    assert_eq!(summary.fee_zat, Some(FEE), "fee is shown, not unknown");
    let labels: Vec<&str> = summary.outputs.iter().map(|(l, _)| l.as_str()).collect();
    assert!(
        labels[0].starts_with("t-script:76a914"),
        "vault: {}",
        labels[0]
    );
    assert_eq!(
        labels[1],
        format!(
            "thorchain:swap to ETH.ETH, at least 0.031, paid to \
             0x1111111111111111111111111111111111111111|{MEMO}"
        )
    );
    assert!(
        labels[2].starts_with("change:76a914"),
        "change: {}",
        labels[2]
    );
    assert_eq!(summary.outputs[2].1, 75_000);

    let signed = pczt_signing::sign_request(&payload, MNEMONIC, 0, true).expect("signs");
    let responses = envelope::parse_response(&signed).expect("response");
    let finalized = SpendFinalizer::new(Pczt::parse(&responses[0].signed_pczt).unwrap())
        .finalize_spends()
        .expect("every input signed");
    let tx = TransactionExtractor::new(finalized)
        .extract()
        .expect("extract");
    let mut bytes = Vec::new();
    tx.write(&mut bytes).unwrap();
    assert_eq!(&bytes[0..4], &[0x05, 0x00, 0x00, 0x80], "v5");
}

#[test]
fn foreign_input_is_refused_not_passed_through() {
    // a key from another seed: the device owns neither input
    let mnemonic = bip39::Mnemonic::parse_in(
        bip39::Language::English,
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon \
         abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon \
         abandon abandon abandon art",
    )
    .unwrap();
    let usk = UnifiedSpendingKey::from_seed(&MainNetwork, &mnemonic.to_seed(""), AccountId::ZERO)
        .unwrap();
    let foreign = usk
        .transparent()
        .to_account_pubkey()
        .derive_address_pubkey(
            TransparentKeyScope::custom(0).unwrap(),
            NonHardenedChildIndex::from_index(0).unwrap(),
        )
        .unwrap();
    let pczt = deposit_pczt_for(foreign, &vault());
    let err = pczt_signing::sign_request(&request(pczt), MNEMONIC, 0, true)
        .expect_err("a foreign input must not come back unsigned");
    assert!(
        err.to_string().contains("not paid to this account's keys"),
        "{err}"
    );
}

/// The same deposit through the baked `module0.wasm` under wasmi: the bytes
/// and runtime the phone actually runs, including the head and output lines
/// the review screen parses.
#[test]
fn baked_module_reviews_and_signs_the_deposit() {
    let wasm = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../android/src/main/assets/modules/module0.wasm"
    ))
    .expect("module0.wasm");
    let mut rt = module_host::ModuleRuntime::load(&wasm).expect("load module");
    let payload = request(deposit_pczt(57, &vault()));

    let blob = rt.summarize_request(&payload).expect("module summarize");
    let text = String::from_utf8(blob).unwrap();
    let mut lines = text.trim_end_matches('\u{1e}').lines();
    let head = lines.next().unwrap();
    assert!(head.contains("t_inputs=2"), "{head}");
    assert!(head.contains(&format!("fee={FEE}")), "{head}");
    let outputs: Vec<&str> = lines.collect();
    assert_eq!(outputs.len(), 3, "{outputs:?}");
    assert_eq!(
        outputs[1],
        format!(
            "thorchain:swap to ETH.ETH, at least 0.031, paid to \
             0x1111111111111111111111111111111111111111|{MEMO}=0"
        )
    );
    assert!(outputs[2].starts_with("change:76a914") && outputs[2].ends_with("=75000"));

    let signed = rt
        .sign_request(&payload, MNEMONIC, 0, true)
        .expect("module signs");
    let responses = envelope::parse_response(&signed).expect("response");
    SpendFinalizer::new(Pczt::parse(&responses[0].signed_pczt).unwrap())
        .finalize_spends()
        .expect("every input signed by the module");
}
