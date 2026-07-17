//! Shared V6 / Ironwood turnstile PCZT producer for the interop tests.
//!
//! This is the wallet-side (producer) half of the V6 migration contract,
//! factored out of `v6_ironwood.rs` so BOTH the native-signing test and the
//! wasmi `module_host` round-trip test drive the *same* redacted-for-signer
//! PCZT bytes: one orchard spend -> one ironwood output, branch id
//! 0x37a5165b (NU6.3), redacted exactly the way vizor's
//! `redact_pczt_for_signer` does.
//!
//! Only compiles under the NU6.3 cfg the forks require:
//!   RUSTFLAGS='--cfg zcash_unstable="nu6.3"' cargo test

#![cfg(zcash_unstable = "nu6.3")]
#![allow(dead_code)]

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

/// BIP-39 mnemonic of the wallet that owns the orchard note being migrated.
/// The device signs with this exact seed (mainnet = false).
pub const MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

/// Everything the signer-side tests need to assert against the redacted PCZT.
pub struct V6Fixture {
    /// The redacted-for-signer PCZT bytes - exactly what crosses the airgap.
    pub redacted_pczt: Vec<u8>,
    /// The note value being migrated out of the orchard pool (zatoshi).
    pub note_value: u64,
    /// The network fee (inputs - all outputs, incl ironwood).
    pub fee: u64,
    /// The value that lands in the ironwood pool (note_value - fee).
    pub migrated: u64,
    /// Raw 43-byte ironwood destination receiver (the wallet's own internal
    /// orchard address). Present in the redacted PCZT's ironwood output.
    pub ironwood_recipient: [u8; 43],
    /// The wallet's 96-byte orchard FullViewingKey - must NOT appear in the
    /// redacted bytes (R3 viewing-key leak anti-regression).
    pub fvk_bytes: Vec<u8>,
}

/// Regtest-style network with every upgrade, including NU6.3 / Ironwood,
/// active from the start - the builder then targets consensus branch Nu6_3
/// and defaults to TxVersion::V6.
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

/// Build + redact a real V6 orchard->ironwood migration PCZT. This is the
/// producer path `v6_ironwood.rs` used inline; the two tests now share it.
pub fn build_redacted_v6_migration() -> V6Fixture {
    let params = nu63_params();
    let target_height = BlockHeight::from_u32(100);

    // The device seed owns the orchard note being migrated. LocalNetwork
    // reports Regtest (coin type 1), and sign(mainnet=false) derives with
    // TestNetwork (also coin type 1), so keys line up.
    let mnemonic = bip39::Mnemonic::parse_in(bip39::Language::English, MNEMONIC).unwrap();
    let seed = mnemonic.to_seed("");
    let usk = UnifiedSpendingKey::from_seed(&TestNetwork, &seed, AccountId::ZERO).unwrap();
    let fvk = orchard::keys::FullViewingKey::from(usk.orchard());

    // A spendable orchard note (legacy pool, V2 note plaintext) anchored by a
    // dummy witness - the same fixture shape vizor's denomination split uses.
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

    // Migration destination: the wallet's own internal address in the Ironwood
    // pool (V3 note plaintexts), as the fork models it.
    let recipient = fvk.address_at(0u32, orchard::keys::Scope::Internal);
    let ironwood_recipient = recipient.to_raw_address_bytes();
    let internal_ovk = Some(fvk.to_ovk(orchard::keys::Scope::Internal));

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

    let pczt = Creator::build_from_parts(build_result.pczt_parts).expect("Creator");
    let pczt = IoFinalizer::new(pczt).finalize_io().expect("IoFinalizer");

    // Redact + ship over the airgap (exactly vizor's redact_pczt_for_signer):
    // strip the spend note plaintext AND the spend fvk from BOTH shielded
    // bundles so nothing linking the account's notes crosses the airgap.
    let redacted = Redactor::new(pczt)
        .redact_global_with(|mut r| r.redact_proprietary("zcash_client_backend:proposal_info"))
        .redact_orchard_with(|mut r| {
            r.redact_actions(|mut ar| {
                ar.clear_spend_witness();
                ar.clear_spend_rseed();
                ar.clear_spend_rho();
                ar.clear_spend_recipient();
                ar.clear_spend_value();
                ar.clear_spend_fvk();
                ar.redact_output_proprietary("zcash_client_backend:output_info");
            });
        })
        .redact_ironwood_with(|mut r| {
            r.redact_actions(|mut ar| {
                ar.clear_spend_witness();
                ar.clear_spend_rseed();
                ar.clear_spend_rho();
                ar.clear_spend_recipient();
                ar.clear_spend_value();
                ar.clear_spend_fvk();
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
    let redacted_pczt = redacted.serialize();

    // Sanity: the redacted bytes must still parse as a PCZT for the signer.
    Pczt::parse(&redacted_pczt).expect("redacted PCZT parses");

    V6Fixture {
        redacted_pczt,
        note_value,
        fee,
        migrated,
        ironwood_recipient,
        fvk_bytes: fvk.to_bytes().to_vec(),
    }
}
