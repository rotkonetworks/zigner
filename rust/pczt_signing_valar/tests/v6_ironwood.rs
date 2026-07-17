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
//! Only meaningful when built the way the forks require:
//!   RUSTFLAGS='--cfg zcash_unstable="nu6.3"' cargo test
//! Without the cfg this file compiles to nothing.

#![cfg(zcash_unstable = "nu6.3")]

use pczt::{
    roles::{creator::Creator, io_finalizer::IoFinalizer, redactor::Redactor},
    Pczt,
};
use rand_core::OsRng;
use zcash_keys::keys::UnifiedSpendingKey;
use zcash_primitives::transaction::{
    builder::{BuildConfig, Builder},
    fees::zip317,
    TxVersion,
};
use zcash_protocol::{
    consensus::{BlockHeight, TestNetwork},
    local_consensus::LocalNetwork,
    memo::MemoBytes,
    value::Zatoshis,
};
use zip32::AccountId;

const MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

/// Regtest-style network with every upgrade, including NU6.3 / Ironwood,
/// active from the start - the builder then targets consensus branch
/// Nu6_3 and defaults to TxVersion::V6.
fn nu63_params() -> LocalNetwork {
    let h = |x: u32| Some(BlockHeight::from_u32(x));
    LocalNetwork {
        overwinter: h(1),
        sapling: h(1),
        blossom: h(1),
        heartwood: h(1),
        canopy: h(1),
        nu5: h(1),
        nu6: h(1),
        nu6_1: h(1),
        nu6_2: h(1),
        nu6_3: h(1),
    }
}

#[test]
fn wallet_builds_v6_migration_device_signs() {
    let params = nu63_params();
    let target_height = BlockHeight::from_u32(100);

    // The device seed owns the orchard note being migrated. LocalNetwork
    // reports Regtest (coin type 1), and sign_redacted_pczt(mainnet=false)
    // derives with TestNetwork (also coin type 1), so keys line up.
    let mnemonic = bip39::Mnemonic::parse_in(bip39::Language::English, MNEMONIC).unwrap();
    let seed = mnemonic.to_seed("");
    let usk = UnifiedSpendingKey::from_seed(&TestNetwork, &seed, AccountId::ZERO).unwrap();
    let fvk = orchard::keys::FullViewingKey::from(usk.orchard());

    // A spendable orchard note (legacy pool, V2 note plaintext) anchored
    // by a dummy witness - the same fixture shape vizor's denomination
    // split test uses.
    let note_value = 1_000_000u64;
    let rho = orchard::note::Rho::from_bytes(&[1u8; 32]).unwrap();
    let rseed = (0u8..=255)
        .find_map(|b| orchard::note::RandomSeed::from_bytes([b; 32], &rho).into_option())
        .expect("test rseed");
    let note: orchard::Note = Option::from(orchard::Note::from_parts(
        fvk.address_at(0u32, orchard::keys::Scope::External),
        orchard::value::NoteValue::from_raw(note_value),
        rho,
        rseed,
        orchard::note::NoteVersion::V2,
    ))
    .expect("test note");

    let zero = Option::from(orchard::tree::MerkleHashOrchard::from_bytes(&[0u8; 32]))
        .expect("zero merkle hash");
    let witness = orchard::tree::MerklePath::from_parts(0, [zero; 32]);
    let cmx: orchard::note::ExtractedNoteCommitment = note.commitment().into();
    let orchard_anchor = witness.root(cmx);

    // Migration destination: the wallet's own internal address in the
    // Ironwood pool (V3 note plaintexts), as the fork models it.
    let recipient = fvk.address_at(0u32, orchard::keys::Scope::Internal);
    let internal_ovk = Some(fvk.to_ovk(orchard::keys::Scope::Internal));

    // -- wallet side: build (mirrors vizor make_orchard_split_builder /
    //    create_orchard_to_ironwood_pczt_from_predicted_note) --
    let make_builder = |migrated: u64| {
        let mut builder = Builder::new(
            params,
            target_height,
            BuildConfig::Standard {
                sapling_anchor: None,
                orchard_anchor: Some(orchard_anchor),
                ironwood_anchor: Some(orchard::Anchor::empty_tree()),
            },
        );
        builder
            .propose_version::<zip317::FeeRule>(TxVersion::V6)
            .expect("propose V6");
        builder
            .add_orchard_spend::<zip317::FeeRule>(fvk.clone(), note, witness.clone())
            .expect("add orchard migration spend");
        builder
            .add_ironwood_output::<zip317::FeeRule>(
                internal_ovk.clone(),
                recipient,
                Zatoshis::const_from_u64(migrated),
                MemoBytes::empty(),
            )
            .expect("add ironwood migration output");
        builder
    };

    let fee = u64::from(
        make_builder(1)
            .get_fee(&zip317::FeeRule::standard())
            .expect("estimate migration fee"),
    );
    assert!(fee > 0 && fee < note_value, "sane fee: {fee}");
    let migrated = note_value - fee;

    let build_result = make_builder(migrated)
        .build_for_pczt(OsRng, &zip317::FeeRule::standard())
        .expect("build_for_pczt");
    assert_eq!(build_result.pczt_parts.version, TxVersion::V6);
    let spend_index = build_result
        .orchard_meta
        .spend_action_index(0)
        .expect("orchard spend action index");

    let pczt = Creator::build_from_parts(build_result.pczt_parts).expect("Creator");
    let pczt = IoFinalizer::new(pczt).finalize_io().expect("IoFinalizer");

    // -- wallet side: redact + ship over the airgap (exactly vizor's
    //    redact_pczt_for_signer for tx_version != 5) --
    let redacted = Redactor::new(pczt)
        .redact_global_with(|mut r| r.redact_proprietary("zcash_client_backend:proposal_info"))
        .redact_orchard_with(|mut r| {
            r.redact_actions(|mut ar| {
                ar.clear_spend_witness();
                ar.redact_output_proprietary("zcash_client_backend:output_info");
            });
        })
        .redact_ironwood_with(|mut r| {
            r.redact_actions(|mut ar| {
                ar.clear_spend_witness();
                ar.redact_output_proprietary("zcash_client_backend:output_info");
            });
        })
        .redact_sapling_with(|mut r| {
            r.redact_spends(|mut sr| sr.clear_witness());
            r.redact_outputs(|mut or| {
                or.redact_proprietary("zcash_client_backend:output_info");
            });
        })
        .redact_transparent_with(|mut r| {
            r.redact_outputs(|mut or| {
                or.redact_proprietary("zcash_client_backend:output_info");
            });
        })
        .finish();
    assert_eq!(
        *redacted.global().tx_version(),
        zcash_protocol::constants::V6_TX_VERSION
    );
    let over_the_qr = redacted.serialize();

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
    let spend_sig = signed.orchard().actions()[spend_index]
        .spend()
        .spend_auth_sig();
    assert!(
        spend_sig.is_some(),
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
