//! End-to-end interop for the V5 (orchard) path: the wallet pipeline
//! produces and redacts the PCZT, THIS crate signs it as the cold signer,
//! and the extractor turns the result into a broadcastable transaction.
//! This is the exact seam Keystone occupies for zashi/vizor.
//!
//! The redaction is zafu's `redact_pczt_for_signer`, mirrored in
//! `tests/common/mod.rs` (see the note there on why it is no longer a
//! `zafu-wasm` dev-dependency).
//!
//! V5 ANTI-REGRESSION: this is the test that pins the shipped orchard
//! money path. It must keep passing byte-for-byte in behaviour across the
//! pczt 0.7 -> 0.9.2 move.
//!
//! Slow test: builds the orchard proving key + one Halo2 proof.

mod common;

use common::{redact_pczt_for_signer, MNEMONIC};
use pczt::{
    roles::{
        creator::Creator, io_finalizer::IoFinalizer, prover::Prover,
        spend_finalizer::SpendFinalizer, tx_extractor::TransactionExtractor,
    },
    Pczt,
};
use rand_core::OsRng;
use zcash_keys::keys::UnifiedSpendingKey;
use zcash_primitives::transaction::{
    builder::{BuildConfig, Builder, BundlePadding},
    fees::zip317,
};
use zcash_protocol::{consensus::MainNetwork, memo::MemoBytes, value::Zatoshis};
use zcash_transparent::{
    bundle as transparent,
    keys::{NonHardenedChildIndex, TransparentKeyScope},
};
use zip32::AccountId;

#[test]
fn wallet_produces_device_signs_wallet_extracts() {
    let params = MainNetwork;

    // The device seed owns the transparent input (m/44'/133'/0'/0/0).
    let mnemonic = bip39::Mnemonic::parse_in(bip39::Language::English, MNEMONIC).unwrap();
    let seed = mnemonic.to_seed("");
    let usk = UnifiedSpendingKey::from_seed(&params, &seed, AccountId::ZERO).unwrap();
    let scope = TransparentKeyScope::custom(0).unwrap();
    let child = NonHardenedChildIndex::from_index(0).unwrap();
    let t_pubkey = usk
        .transparent()
        .to_account_pubkey()
        .derive_address_pubkey(scope, child)
        .unwrap();

    let p2pkh = zcash_transparent::address::TransparentAddress::from_pubkey(&t_pubkey);
    let utxo = transparent::OutPoint::new([7u8; 32], 0);
    let coin = transparent::TxOut::new(Zatoshis::const_from_u64(1_000_000), p2pkh.script().into());

    // Orchard recipient (external party).
    let orchard_sk = orchard::keys::SpendingKey::from_bytes([9u8; 32]).unwrap();
    let recipient = orchard::keys::FullViewingKey::from(&orchard_sk)
        .address_at(0u32, orchard::keys::Scope::External);

    // ── wallet side: build ──
    // Target height sits in the NU6.2 window (mainnet NU6.2 = 3_364_600,
    // NU6.3 = 3_428_143), so the builder targets consensus branch Nu6_2 and
    // produces a TxVersion::V5 transaction with an `orchard_v2` bundle. That
    // is the shipped V5 shape this test exists to pin. (The old height of
    // 10_000_000 predated NU6.3 having an activation height at all; with the
    // 0.9.2 stack it would now suggest V6.)
    let mut builder = Builder::new(
        params,
        3_400_000.into(),
        BuildConfig::Standard {
            sapling_anchor: None,
            orchard_anchor: Some(orchard::Anchor::empty_tree()),
            // V5: no ironwood bundle at all.
            ironwood_anchor: None,
            orchard_padding: BundlePadding::DEFAULT,
            ironwood_padding: BundlePadding::DEFAULT,
        },
    );
    builder
        .add_transparent_p2pkh_input(t_pubkey, utxo, coin)
        .expect("add transparent input");
    builder
        .add_orchard_output::<zip317::FeeRule>(
            None,
            recipient,
            Zatoshis::const_from_u64(100_000),
            MemoBytes::empty(),
        )
        .expect("orchard output");
    builder
        .add_orchard_output::<zip317::FeeRule>(
            None,
            recipient,
            Zatoshis::const_from_u64(885_000),
            MemoBytes::empty(),
        )
        .expect("orchard change");

    let parts = builder
        .build_for_pczt(OsRng, &zip317::FeeRule::standard())
        .expect("build_for_pczt")
        .pczt_parts;

    let pczt = Creator::build_from_parts(parts).expect("Creator");
    let pczt = IoFinalizer::new(pczt).finalize_io().expect("IoFinalizer");
    let pczt = Prover::new(pczt)
        .create_orchard_proof(&orchard::circuit::ProvingKey::build(
            orchard::circuit::OrchardCircuitVersion::FixedPostNu6_2,
        ))
        .expect("orchard prove")
        .finish();

    // ── wallet side: redact + ship over the airgap ──
    let redacted = redact_pczt_for_signer(pczt);
    let over_the_qr = redacted.serialize().expect("serialize redacted PCZT");
    // V5 wire-format anti-regression: a V5 PCZT with an empty ironwood bundle
    // must still serialize in the v1 PCZT encoding, so wallets that predate
    // the v2 encoding keep working. (`Pczt::serialize` picks the minimal
    // encoding; PCZT_VERSION_1 == 1 in the 4-byte LE version after the
    // 4-byte magic.)
    assert_eq!(
        &over_the_qr[4..8],
        &[1, 0, 0, 0],
        "V5 PCZT must still use the v1 encoding over the QR"
    );

    // ── device side: THIS crate, through the full QR envelope ──
    use pczt_signing::envelope::{self, RequestMessage, SignRequest};

    // Batch of two (same PCZT twice - proving is the expensive part and the
    // envelope/batch machinery is what's under test here).
    let batch_payload = envelope::encode_request(&SignRequest::Batch(vec![
        RequestMessage {
            id: b"m-1".to_vec(),
            pczt_bytes: over_the_qr.clone(),
        },
        RequestMessage {
            id: b"m-2".to_vec(),
            pczt_bytes: over_the_qr.clone(),
        },
    ]))
    .expect("encode batch");

    // Confirmation summaries: what the user would see on-device.
    let summaries = pczt_signing::summarize_request(&batch_payload).expect("summaries");
    assert_eq!(summaries.len(), 2);
    assert_eq!(summaries[0].transparent_inputs, 1);
    assert!(summaries[0].orchard_actions >= 2);
    let orchard_total: u64 = summaries[0]
        .outputs
        .iter()
        .filter(|(l, _)| l.starts_with("orchard:"))
        .map(|(_, v)| v)
        .sum();
    assert_eq!(
        orchard_total, 985_000,
        "recipient+change values visible for confirmation"
    );

    // COMPACT fall-back: the SAME transparent-input PCZT asked for via the
    // compact tx_types (0x06) must be refused loudly - the signatures-only
    // response cannot express secp256k1 input signatures, so the wallet must
    // resend with 0x03/0x04. Shielded-only sends and the Ironwood migration -
    // the flows compact exists for - never hit this.
    let compact_payload = envelope::encode_request_full(
        &SignRequest::Batch(vec![
            RequestMessage {
                id: b"m-1".to_vec(),
                pczt_bytes: over_the_qr.clone(),
            },
            RequestMessage {
                id: b"m-2".to_vec(),
                pczt_bytes: over_the_qr.clone(),
            },
        ]),
        true,
    )
    .expect("encode compact batch");
    let compact_err = pczt_signing::sign_request(&compact_payload, MNEMONIC, 0, true)
        .expect_err("compact must refuse transparent inputs");
    assert!(
        format!("{compact_err}").contains("transparent inputs"),
        "unexpected compact refusal reason: {compact_err}"
    );

    let response_payload =
        pczt_signing::sign_request(&batch_payload, MNEMONIC, 0, true).expect("device signs batch");

    // ── wallet side: parse response, verify Keystone-parity digests ──
    let responses = envelope::parse_response(&response_payload).expect("parse response");
    assert_eq!(responses.len(), 2);
    assert_eq!(responses[0].id, b"m-1");
    assert_eq!(responses[1].id, b"m-2");
    for r in &responses {
        assert_eq!(r.digest, envelope::integrity_digest(&r.signed_pczt));
    }
    let signed_bytes = responses[0].signed_pczt.clone();

    // ── wallet side: finalize + extract ──
    let signed = Pczt::parse(&signed_bytes).expect("signed PCZT parses");
    let finalized = SpendFinalizer::new(signed)
        .finalize_spends()
        .expect("SpendFinalizer - fails if the device did not actually sign");
    let tx = TransactionExtractor::new(finalized)
        .with_orchard(&orchard::circuit::VerifyingKey::build(
            orchard::circuit::OrchardCircuitVersion::FixedPostNu6_2,
        ))
        .extract()
        .expect("extract broadcastable tx");
    let mut tx_bytes = Vec::new();
    tx.write(&mut tx_bytes).expect("serialize tx");

    assert!(tx_bytes.len() > 1000, "extracted tx suspiciously small");
    // v5 header sanity: version 5 | 1<<31 little-endian
    assert_eq!(&tx_bytes[0..4], &[0x05, 0x00, 0x00, 0x80]);
}
