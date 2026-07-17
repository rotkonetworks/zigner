//! V6 / Ironwood interop (Valar NU6.3 forks): the wallet side builds a
//! V6 PCZT in the orchard -> ironwood migration shape (one orchard spend,
//! outputs into the new Ironwood pool), redacts it exactly the way
//! vizor's redact_pczt_for_signer does, and THIS crate signs it as the
//! cold signer through pczt_signing::sign_redacted_pczt.
//!
//! Mirrors tests/interop.rs in ../pczt_signing, minus proving and tx
//! extraction: the Signer role recomputes the sighash from effects, so
//! spend-auth signing is provable without building the Halo2 keys.
//!
//! The producer/redaction half lives in tests/common/mod.rs so the wasmi
//! module_host round-trip test (tests/v6_ironwood_module.rs) drives the
//! exact same redacted PCZT bytes.
//!
//! Only meaningful when built the way the forks require:
//!   RUSTFLAGS='--cfg zcash_unstable="nu6.3"' cargo test
//! Without the cfg this file compiles to nothing.

#![cfg(zcash_unstable = "nu6.3")]

mod common;

use common::{build_redacted_v6_migration, MNEMONIC};
use pczt::Pczt;

#[test]
fn wallet_builds_v6_migration_device_signs() {
    // -- wallet side: build + redact + ship over the airgap --
    let fx = build_redacted_v6_migration();
    let over_the_qr = fx.redacted_pczt.clone();
    let fee = fx.fee;
    let migrated = fx.migrated;

    // R3 viewing-key leak fix: the spend fvk must be ABSENT from the bytes that
    // cross the airgap. Assert the raw 96-byte fvk does not appear in the QR
    // payload; the device reconstructs it from the seed to sign.
    fn contains(haystack: &[u8], needle: &[u8]) -> bool {
        !needle.is_empty() && haystack.windows(needle.len()).any(|w| w == needle)
    }
    assert!(
        !contains(&over_the_qr, &fx.fvk_bytes),
        "redacted PCZT still leaks the spend viewing key (fvk) over the airgap"
    );

    // -- device side: confirmation summary --
    let summary = pczt_signing::summarize(&over_the_qr).expect("summary");
    assert!(
        summary.orchard_actions >= 1,
        "orchard spend context visible: {summary:?}"
    );
    assert!(
        summary.ironwood_actions >= 1,
        "ironwood actions visible: {summary:?}"
    );
    let ironwood_total: u64 = summary
        .outputs
        .iter()
        .filter(|(l, _)| l.starts_with("ironwood:"))
        .map(|(_, v)| v)
        .sum();
    assert_eq!(
        ironwood_total, migrated,
        "migrated value visible for confirmation"
    );

    // Fee correctness (FIX-B / R3 finding 2): the summary fee MUST equal
    // inputs - ALL outputs, INCLUDING the ironwood output. An ironwood-blind
    // fee (orchard value_sum only) would report ~the whole migrated amount as
    // fee, since the migrated value leaves the orchard pool. compute_fee_zat
    // sums every bundle value balance via fee_paid, so the confirmed fee is
    // the real network fee.
    assert_eq!(
        summary.fee_zat,
        Some(fee),
        "confirmed fee is inputs minus ALL outputs (incl ironwood), not the migrated amount: {summary:?}"
    );
    assert!(
        summary.fee_zat.unwrap() < migrated,
        "fee must be far below the migrated value, not ~equal to it (the ironwood-blind bug)"
    );

    // Head ABI (FIX-B / R3 finding 3): the wasm summary head must carry
    // ironwood_actions and the fee so the device confirmation head reflects
    // the migration. Drive the actual C ABI the module_host calls.
    let payload = pczt_signing::envelope::encode_request(&pczt_signing::envelope::SignRequest::Single(
        pczt_signing::envelope::RequestMessage {
            id: Vec::new(),
            pczt_bytes: over_the_qr.clone(),
        },
    ))
    .expect("encode single request");
    let summaries = pczt_signing::summarize_request(&payload).expect("summarize_request");
    assert_eq!(summaries.len(), 1);
    assert!(summaries[0].ironwood_actions >= 1, "head reports ironwood_actions");
    assert_eq!(summaries[0].fee_zat, Some(fee), "head reports canonical fee");

    // -- device side: sign --
    let signed_bytes =
        pczt_signing::sign_redacted_pczt(&over_the_qr, MNEMONIC, 0, false).expect("device signs");
    let signed = Pczt::parse(&signed_bytes).expect("signed PCZT parses");
    assert_eq!(
        *signed.global().tx_version(),
        zcash_protocol::constants::V6_TX_VERSION
    );

    // The migrated orchard spend carries our RedPallas spend-auth signature.
    assert!(
        signed
            .orchard()
            .actions()
            .iter()
            .any(|a| a.spend().spend_auth_sig().is_some()),
        "spend-auth signature landed on the migrated orchard spend"
    );

    // Every action in both bundles ends up signed: dummy/padding spends by
    // the wallet's IO finalizer, the real spend by this crate - and the
    // device pass must not have clobbered the dummy signatures.
    for (i, action) in signed.orchard().actions().iter().enumerate() {
        assert!(
            action.spend().spend_auth_sig().is_some(),
            "orchard action {i} unsigned"
        );
    }
    for (i, action) in signed.ironwood().actions().iter().enumerate() {
        assert!(
            action.spend().spend_auth_sig().is_some(),
            "ironwood action {i} unsigned"
        );
    }
}
