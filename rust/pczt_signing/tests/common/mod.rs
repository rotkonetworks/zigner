//! Shared wallet-side (producer) half of the airgap contract for the interop
//! tests: build a PCZT, redact it exactly the way zafu's
//! `redact_pczt_for_signer` does, and hand the bytes to this crate as the cold
//! signer.
//!
//! Two fixtures live here:
//!   * [`redact_pczt_for_signer`] - the redaction itself, a line-for-line
//!     mirror of `zcash-wasm/src/lib.rs::redact_pczt_for_signer` in zcli. It
//!     used to be pulled in as a `zafu-wasm` dev-dependency; that crate is
//!     pinned to the pre-0.9 librustzcash rev and its `pczt::Pczt` type can no
//!     longer unify with ours, so the redaction is mirrored here instead. Keep
//!     the two in sync - it defines what does and does not cross the airgap.
//!   * [`build_redacted_v6_migration`] - a real V6 orchard -> ironwood
//!     turnstile PCZT, shared by the native signing test and the wasmi
//!     `module_host` round-trip test so both drive the exact same bytes.
//!
//! Since pczt 0.9.2 the Ironwood pool is UNGATED upstream: no
//! `zcash_unstable` cfg, no fork. This file compiles in the default build.

#![allow(dead_code)]

use pczt::{
    roles::{creator::Creator, io_finalizer::IoFinalizer, redactor::Redactor},
    Pczt,
};
use rand_core::OsRng;
use zcash_keys::keys::UnifiedSpendingKey;
use zcash_primitives::transaction::{
    builder::{BuildConfig, Builder, BundlePadding, PcztParts},
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

/// BIP-39 mnemonic of the wallet that owns the note being spent/migrated.
/// The device signs with this exact seed.
pub const MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

/// Mirror of zafu's `redact_pczt_for_signer`: what the wallet strips before the
/// PCZT crosses the airgap.
///
/// Note the deliberate asymmetry, which the device relies on:
///   * the SPEND side loses its note plaintext (recipient/value/rho/rseed) AND
///     the 96-byte orchard `fvk` (R3 viewing-key leak fix). The signer
///     reconstructs the fvk from the seed it already holds.
///   * the OUTPUT side KEEPS `recipient` and `value`, because in an ordinary
///     send the orchard output IS the recipient the user must confirm.
pub fn redact_pczt_for_signer(pczt: Pczt) -> Pczt {
    Redactor::new(pczt)
        .redact_global_with(|mut g| {
            g.clear_proprietary();
        })
        .redact_orchard_with(|mut o| {
            o.redact_actions(|mut a| {
                a.clear_spend_witness();
                a.clear_spend_zip32_derivation();
                a.clear_spend_dummy_sk();
                a.clear_spend_proprietary();
                a.clear_spend_rseed();
                a.clear_spend_rho();
                a.clear_spend_recipient();
                a.clear_spend_value();
                a.clear_spend_fvk();
                a.clear_output_zip32_derivation();
                a.clear_output_user_address();
                a.clear_output_proprietary();
            });
        })
        // The ironwood bundle (NU6.3 / V6) is orchard-shaped; identical
        // redaction. On a V5 PCZT the bundle is empty and this is a no-op.
        .redact_ironwood_with(|mut o| {
            o.redact_actions(|mut a| {
                a.clear_spend_witness();
                a.clear_spend_zip32_derivation();
                a.clear_spend_dummy_sk();
                a.clear_spend_proprietary();
                a.clear_spend_rseed();
                a.clear_spend_rho();
                a.clear_spend_recipient();
                a.clear_spend_value();
                a.clear_spend_fvk();
            });
        })
        .redact_transparent_with(|mut t| {
            t.redact_outputs(|mut o| {
                o.clear_user_address();
                o.clear_proprietary();
            });
        })
        .finish()
}

/// Everything the signer-side V6 tests need to assert against the redacted PCZT.
pub struct V6Fixture {
    /// The redacted-for-signer PCZT bytes - exactly what crosses the airgap.
    pub redacted_pczt: Vec<u8>,
    /// The full pre-redaction PCZT the wallet retains - the merge target for
    /// returned signature contributions (still carries the spend fvk).
    pub full_pczt: Vec<u8>,
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
/// and can produce a `TxVersion::V6` transaction.
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

/// The same regtest network with NU6.3 NOT activated, so the builder targets
/// consensus branch Nu6_2 and produces a `TxVersion::V5` transaction with an
/// `orchard_v2` bundle - the shipped V5 shape.
fn nu62_params() -> LocalNetwork {
    LocalNetwork {
        nu6_3: None,
        ..nu63_params()
    }
}

/// Build + redact a plain V5 orchard->orchard send, with the same seed as
/// [`build_redacted_v6_migration`]. Used as the V5 non-regression control: the
/// same module/rlib must still summarize it with `ironwood_actions == 0` and
/// sign every orchard action.
///
/// No Prover run: the Signer role recomputes the sighash from tx effects, so
/// spend-auth signing does not need the Halo2 proof.
pub fn build_redacted_v5_send() -> V6Fixture {
    let params = nu62_params();
    let target_height = BlockHeight::from_u32(100);

    let mnemonic = bip39::Mnemonic::parse_in(bip39::Language::English, MNEMONIC).unwrap();
    let seed = mnemonic.to_seed("");
    let usk = UnifiedSpendingKey::from_seed(&TestNetwork, &seed, AccountId::ZERO).unwrap();
    let fvk = orchard::keys::FullViewingKey::from(usk.orchard());

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

    // An external orchard recipient (not the wallet's own address).
    let recipient_sk = orchard::keys::SpendingKey::from_bytes([9u8; 32]).unwrap();
    let recipient = orchard::keys::FullViewingKey::from(&recipient_sk)
        .address_at(0u32, orchard::keys::Scope::External);

    let make_builder = |sent: u64| {
        let mut builder = Builder::new(
            params,
            target_height,
            BuildConfig::Standard {
                sapling_anchor: None,
                orchard_anchor: Some(orchard_anchor),
                // V5: no ironwood bundle.
                ironwood_anchor: None,
                orchard_padding: BundlePadding::DEFAULT,
                ironwood_padding: BundlePadding::DEFAULT,
            },
        );
        builder
            .propose_version::<zip317::FeeRule>(TxVersion::V5)
            .expect("propose V5");
        builder
            .add_orchard_spend::<zip317::FeeRule>(fvk.clone(), note, witness.clone())
            .expect("add orchard spend");
        builder
            .add_orchard_output::<zip317::FeeRule>(
                None,
                recipient,
                Zatoshis::const_from_u64(sent),
                MemoBytes::empty(),
            )
            .expect("add orchard output");
        builder
    };

    let fee = u64::from(
        make_builder(1)
            .get_fee(&zip317::FeeRule::standard())
            .expect("estimate fee"),
    );
    let sent = note_value - fee;

    let build_result = make_builder(sent)
        .build_for_pczt(OsRng, &zip317::FeeRule::standard())
        .expect("build_for_pczt");
    assert_eq!(build_result.pczt_parts.version, TxVersion::V5);

    let pczt = Creator::build_from_parts(build_result.pczt_parts).expect("Creator");
    let pczt = IoFinalizer::new(pczt).finalize_io().expect("IoFinalizer");

    let full_pczt = pczt.clone().serialize().expect("serialize full PCZT");
    let redacted = redact_pczt_for_signer(pczt);
    assert!(
        redacted.ironwood().actions().is_empty(),
        "V5 fixture must carry no ironwood actions"
    );
    let redacted_pczt = redacted.serialize().expect("serialize redacted PCZT");
    // V5 must still ship in the v1 PCZT encoding.
    assert_eq!(
        &redacted_pczt[4..8],
        &[1, 0, 0, 0],
        "V5 uses the v1 encoding"
    );

    V6Fixture {
        redacted_pczt,
        full_pczt,
        note_value,
        fee,
        migrated: sent,
        ironwood_recipient: recipient.to_raw_address_bytes(),
        fvk_bytes: fvk.to_bytes().to_vec(),
    }
}

/// Build + redact a real V6 orchard->ironwood migration PCZT.
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
    // dummy witness.
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
    // pool (V3 note plaintexts).
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
                orchard_padding: BundlePadding::DEFAULT,
                ironwood_padding: BundlePadding::DEFAULT,
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

    let full_pczt = pczt.clone().serialize().expect("serialize full PCZT");
    let redacted = redact_pczt_for_signer(pczt);
    assert_eq!(
        *redacted.global().tx_version(),
        zcash_protocol::constants::V6_TX_VERSION
    );
    let redacted_pczt = redacted.serialize().expect("serialize redacted PCZT");

    // Sanity: the redacted bytes must still parse as a PCZT for the signer.
    Pczt::parse(&redacted_pczt).expect("redacted PCZT parses");

    V6Fixture {
        redacted_pczt,
        full_pczt,
        note_value,
        fee,
        migrated,
        ironwood_recipient,
        fvk_bytes: fvk.to_bytes().to_vec(),
    }
}

/// Redact a PCZT for compact wallet transport: the wallet performs its
/// standard redaction (clearing spend note plaintext but keeping output values,
/// recipients, and rseed for display/recovery), then additionally clears cv_net
/// and cmx (recomputable by resolve_fields), and v6 anchors (not needed for v6
/// sighash). The signer's `resolve_fields()` recomputes these fields once, so
/// the same verification gates apply to compact and full PCZTs.
///
/// NOTE: This is NOT applied on top of the standard redaction - the wallet
/// does compact redaction directly, so it must NOT clear the spend/output values
/// needed for resolve_cv_net to work. This fixture simulates that by starting
/// with a fresh, unredacted PCZT.
pub fn redact_pczt_for_compact_signer(pczt: Pczt) -> Pczt {
    use pczt::roles::redactor::Redactor;

    Redactor::new(pczt)
        .redact_global_with(|mut g| {
            g.clear_proprietary();
        })
        .redact_orchard_with(|mut o| {
            // Compact-specific: clear cv_net and cmx (recomputable by resolve_fields)
            // and v6 anchor (not signed, effects_anchor = Omit).
            // Standard spend redaction: clear note plaintext but keep values/rseed.
            o.redact_actions(|mut a| {
                // Spend note plaintext: recipient, value, rho, rseed, fvk, witness
                a.clear_spend_witness();
                a.clear_spend_zip32_derivation();
                a.clear_spend_dummy_sk();
                a.clear_spend_proprietary();
                a.clear_spend_rseed();
                a.clear_spend_rho();
                a.clear_spend_recipient();
                // NOTE: DO NOT clear spend_value - needed for resolve_cv_net!
                a.clear_spend_fvk();
                // Compact redaction additions:
                a.clear_cv_net(); // Recomputable from spend/output value + rcv

                // Output: keep recipient and value for display, rseed for recovery
                a.clear_output_zip32_derivation();
                a.clear_output_user_address();
                a.clear_output_proprietary();
                // NOTE: DO NOT clear output value or recipient - needed for display and recovery!
                a.clear_cmx(); // Compact redaction: recomputable from note commitment
                               // Upstream's largest single request-leg win: the 580-byte
                               // enc_ciphertext collapses to the memo trimmed to its last
                               // nonzero byte - ONE byte for the empty memo a migration uses.
                               // The device re-encrypts it in resolve_fields() from
                               // recipient/value/rseed plus the spend nullifier (rho).
                               // (pczt::orchard::MEMO_SIZE is crate-private upstream = 512.)
                a.replace_enc_ciphertext_with_memo_plaintext([0u8; 512]);
            });
            o.clear_anchor(); // v6 anchor not signed and not needed
        })
        .redact_ironwood_with(|mut o| {
            o.redact_actions(|mut a| {
                // Same as orchard
                a.clear_spend_witness();
                a.clear_spend_zip32_derivation();
                a.clear_spend_dummy_sk();
                a.clear_spend_proprietary();
                a.clear_spend_rseed();
                a.clear_spend_rho();
                a.clear_spend_recipient();
                // NOTE: DO NOT clear spend_value!
                a.clear_spend_fvk();
                a.clear_cv_net(); // Compact redaction

                // NOTE: keep output recipient and value!
                a.clear_cmx(); // Compact redaction
                               // Upstream's largest single request-leg win: the 580-byte
                               // enc_ciphertext collapses to the memo trimmed to its last
                               // nonzero byte - ONE byte for the empty memo a migration uses.
                               // The device re-encrypts it in resolve_fields() from
                               // recipient/value/rseed plus the spend nullifier (rho).
                               // (pczt::orchard::MEMO_SIZE is crate-private upstream = 512.)
                a.replace_enc_ciphertext_with_memo_plaintext([0u8; 512]);
            });
            o.clear_anchor(); // v6 anchor not signed
        })
        .redact_transparent_with(|mut t| {
            t.redact_outputs(|mut o| {
                o.clear_user_address();
                o.clear_proprietary();
            });
        })
        .finish()
}

/// Everything the delegation-display tests need from
/// [`build_redacted_delegation`].
pub struct DelegationFixture {
    /// The redacted-for-signer PCZT bytes - exactly what crosses the airgap.
    pub redacted_pczt: Vec<u8>,
    /// Raw 43-byte receiver of the governance output (the voting hotkey).
    pub hotkey_recipient: [u8; 43],
}

/// Build + redact a Zcash voting-delegation authorization PCZT, matching the
/// shape zcli's `build_governance_pczt` produces (`zcli/crates/zcash-voting/
/// src/action.rs`): a single Ironwood action pairing a synthetic 1-zatoshi
/// "signed note" spend (from the voter's own external address, rho bound
/// off-PCZT to the real delegated notes + VAN + vote round id) with a
/// zero-value output to the voting hotkey address. No orchard bundle, no
/// transparent inputs - this "transaction" is never broadcast to the Zcash
/// network (it only carries a spend-auth signature the wallet extracts for
/// the cosmos voting chain), so it is built with the low-level
/// `orchard::builder::Builder` + `PcztParts` + `Creator` + `IoFinalizer`
/// path exactly as the real builder does, not the fee-rule-aware
/// `zcash_primitives::transaction::builder::Builder` used elsewhere in this
/// file (which would reject a "transaction" with no conventional fee).
pub fn build_redacted_delegation() -> DelegationFixture {
    use orchard::builder::{Builder as OrchardBuilder, BundleType};
    use orchard::bundle::BundleVersion;
    use orchard::keys::{FullViewingKey, Scope, SpendingKey};
    use orchard::note::{Note, RandomSeed, Rho};
    use orchard::tree::{MerkleHashOrchard, MerklePath};
    use orchard::value::NoteValue;
    use orchard::Anchor;
    use zcash_protocol::consensus::BranchId;

    let mnemonic = bip39::Mnemonic::parse_in(bip39::Language::English, MNEMONIC).unwrap();
    let seed = mnemonic.to_seed("");
    let usk = UnifiedSpendingKey::from_seed(&TestNetwork, &seed, AccountId::ZERO).unwrap();
    let fvk = FullViewingKey::from(usk.orchard());
    let bundle_version = BundleVersion::ironwood_v3();
    let note_version = bundle_version.note_version();

    // The "signed note": governance spend from the voter's own external
    // address, value 1 zatoshi. Never a real payment note - real production
    // code binds `rho` to the delegated notes / VAN / vote round id via
    // `governance::compute_rho_binding`; a fixed test rho is fine here since
    // this fixture only needs to exercise the PCZT *shape*, not the voting
    // circuit.
    let sender = fvk.address_at(0u32, Scope::External);
    let rho = Rho::from_bytes(&[7u8; 32]).unwrap();
    let rseed = (0u8..=255)
        .find_map(|b| RandomSeed::from_bytes([b; 32], &rho).into_option())
        .expect("test rseed");
    let signed_note: Note = Option::from(Note::from_parts(
        sender,
        NoteValue::from_raw(1),
        rho,
        rseed,
        note_version,
    ))
    .expect("signed note");

    let zero = Option::from(MerkleHashOrchard::from_bytes(&[0u8; 32])).expect("zero hash");
    let dummy_path = MerklePath::from_parts(0, [zero; 32]);
    let anchor = Anchor::from(dummy_path.root(signed_note.commitment().into()));

    // Voting hotkey: an external address distinct from the voter's own.
    let hotkey_sk = SpendingKey::from_bytes([42u8; 32]).unwrap();
    let hotkey_addr = FullViewingKey::from(&hotkey_sk).address_at(0u32, Scope::External);
    let hotkey_recipient = hotkey_addr.to_raw_address_bytes();

    let ovk = fvk.to_ovk(Scope::External);
    // Mirror zcli's `build_governance_pczt`: the padded orchard Builder
    // shuffles spends and outputs independently, so the real spend and the
    // real output are not guaranteed to land in the same action slot. zcli
    // retries until they do (`action.rs`'s `MAX_PCZT_LAYOUT_ATTEMPTS` loop);
    // do the same here so this fixture matches what real delegation PCZTs
    // from zafu actually look like, instead of occasionally exercising an
    // unpaired shape production never ships.
    let bundle = loop {
        let mut builder = OrchardBuilder::new(
            BundleType::DEFAULT,
            bundle_version,
            bundle_version.default_flags(),
            anchor,
        )
        .expect("orchard builder");
        builder
            .add_spend(fvk.clone(), signed_note.clone(), dummy_path.clone())
            .expect("add governance spend");
        builder
            .add_output(Some(ovk.clone()), hotkey_addr, NoteValue::ZERO, [0u8; 512])
            .expect("add governance output");
        let (bundle, meta) = builder.build_for_pczt(OsRng).expect("build_for_pczt");
        if meta.spend_action_index(0) == meta.output_action_index(0) {
            break bundle;
        }
    };

    let parts = PcztParts {
        params: TestNetwork,
        version: TxVersion::V6,
        consensus_branch_id: BranchId::Nu6_3,
        lock_time: 0,
        expiry_height: BlockHeight::from_u32(0),
        transparent: None,
        sapling: None,
        orchard: None,
        ironwood: Some(bundle),
    };
    let pczt = Creator::build_from_parts(parts).expect("Creator");
    let pczt = IoFinalizer::new(pczt).finalize_io().expect("IoFinalizer");

    let redacted = redact_pczt_for_signer(pczt);
    let redacted_pczt = redacted
        .serialize()
        .expect("serialize redacted delegation PCZT");
    Pczt::parse(&redacted_pczt).expect("redacted delegation PCZT parses");

    DelegationFixture {
        redacted_pczt,
        hotkey_recipient,
    }
}
