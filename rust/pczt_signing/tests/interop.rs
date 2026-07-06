//! End-to-end interop: zafu's wallet pipeline produces and redacts the
//! PCZT, THIS crate signs it as the cold signer, and zafu's extractor
//! turns the result into a broadcastable transaction. This is the exact
//! seam Keystone occupies for zashi/vizor.
//!
//! Slow test: builds the orchard proving key + one Halo2 proof.

use pczt::{
    roles::{creator::Creator, io_finalizer::IoFinalizer, prover::Prover, spend_finalizer::SpendFinalizer},
    Pczt,
};
use rand_core::OsRng;
use zcash_keys::keys::UnifiedSpendingKey;
use zcash_primitives::transaction::{
    builder::{BuildConfig, Builder},
    fees::zip317,
};
use zcash_protocol::{consensus::MainNetwork, memo::MemoBytes, value::Zatoshis};
use zcash_transparent::{
    bundle as transparent,
    keys::{NonHardenedChildIndex, TransparentKeyScope},
};
use zip32::AccountId;

const MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

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
    let mut builder = Builder::new(
        params,
        10_000_000.into(),
        BuildConfig::Standard {
            sapling_anchor: None,
            orchard_anchor: Some(orchard::Anchor::empty_tree()),
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
        .create_orchard_proof(&orchard::circuit::ProvingKey::build())
        .expect("orchard prove")
        .finish();

    // ── wallet side: redact + ship over the airgap ──
    let redacted = zafu_wasm::redact_pczt_for_signer(pczt);
    let over_the_qr = redacted.serialize();

    // ── device side: THIS crate ──
    let signed_bytes =
        pczt_signing::sign_redacted_pczt(&over_the_qr, MNEMONIC, 0, true).expect("device signs");

    // ── wallet side: finalize + extract ──
    let signed = Pczt::parse(&signed_bytes).expect("signed PCZT parses");
    let finalized = SpendFinalizer::new(signed)
        .finalize_spends()
        .expect("SpendFinalizer - fails if the device did not actually sign");
    let tx_bytes = zafu_wasm::extract_signed_tx_from_pczt_bytes(&finalized.serialize())
        .expect("extract broadcastable tx");

    assert!(tx_bytes.len() > 1000, "extracted tx suspiciously small");
    // v5 header sanity: version 5 | 1<<31 little-endian
    assert_eq!(&tx_bytes[0..4], &[0x05, 0x00, 0x00, 0x80]);
}
