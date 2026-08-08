//! V6 / Ironwood interop: the wallet side builds a V6 PCZT in the orchard ->
//! ironwood migration shape (one orchard spend, outputs into the new Ironwood
//! pool), redacts it exactly the way zafu's `redact_pczt_for_signer` does, and
//! THIS crate signs it as the cold signer through
//! `pczt_signing::sign_redacted_pczt`.
//!
//! Mirrors tests/interop.rs, minus proving and tx extraction: the Signer role
//! recomputes the sighash from effects, so spend-auth signing is provable
//! without building the Halo2 keys.
//!
//! The producer/redaction half lives in tests/common/mod.rs so the wasmi
//! module_host round-trip test (tests/v6_ironwood_module.rs) drives the exact
//! same redacted PCZT bytes.
//!
//! Was previously the `pczt_signing_valar` spike, which needed a fork of
//! librustzcash and `RUSTFLAGS='--cfg zcash_unstable="nu6.3"'`. Released
//! `pczt` 0.9.2 ships Ironwood ungated, so this now runs in the default build.

mod common;

use common::{build_redacted_v5_send, build_redacted_v6_migration, MNEMONIC};
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
    let payload = pczt_signing::envelope::encode_request(
        &pczt_signing::envelope::SignRequest::Single(pczt_signing::envelope::RequestMessage {
            id: Vec::new(),
            pczt_bytes: over_the_qr.clone(),
        }),
    )
    .expect("encode single request");
    let summaries = pczt_signing::summarize_request(&payload).expect("summarize_request");
    assert_eq!(summaries.len(), 1);
    assert!(
        summaries[0].ironwood_actions >= 1,
        "head reports ironwood_actions"
    );
    assert_eq!(
        summaries[0].fee_zat,
        Some(fee),
        "head reports canonical fee"
    );

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

/// TAMPER DETECTION on the module crate's shipped entry points: a hostile
/// wallet inflates the plaintext `value` of an orchard output - the number the
/// confirmation screen displays - while the transaction still pays what the
/// note commitment says. `summarize` must refuse to display it and
/// `sign_redacted_pczt` must refuse to sign it.
#[test]
fn tampered_output_value_is_rejected() {
    let fx = common::build_redacted_v5_send();
    pczt_signing::summarize(&fx.redacted_pczt).expect("honest PCZT summarizes");

    // Option<u64> on the wire: 0x01 tag + LEB128. A same-length replacement
    // keeps every following offset intact.
    let mut needle = vec![0x01];
    needle.extend_from_slice(&varint(fx.migrated));
    let mut replacement = vec![0x01];
    replacement.extend_from_slice(&varint(fx.migrated + 1));
    assert_eq!(needle.len(), replacement.len());
    let (tampered, n) = patch_all(&fx.redacted_pczt, &needle, &replacement);
    assert!(n > 0, "output value field not found in the wire bytes");

    let parsed = Pczt::parse(&tampered).expect("tampered PCZT still parses");
    assert!(
        parsed
            .orchard()
            .actions()
            .iter()
            .any(|a| a.output().value() == &Some(fx.migrated + 1)),
        "the value the confirmation screen would display was not actually changed"
    );

    let err = pczt_signing::summarize(&tampered).expect_err(
        "a PCZT whose displayed amount contradicts its note commitment must be refused",
    );
    assert!(
        format!("{err}").contains("does not match what it claims to pay"),
        "unexpected rejection reason: {err}"
    );
    assert!(
        pczt_signing::sign_redacted_pczt(&tampered, MNEMONIC, 0, false).is_err(),
        "the device must refuse to sign a PCZT it refused to display"
    );
}

/// TAMPER DETECTION: the displayed recipient is swapped for one the user
/// trusts while the transaction pays somebody else.
#[test]
fn tampered_output_recipient_is_rejected() {
    let fx = common::build_redacted_v5_send();
    pczt_signing::summarize(&fx.redacted_pczt).expect("honest PCZT summarizes");

    let decoy_sk = orchard::keys::SpendingKey::from_bytes([11u8; 32]).unwrap();
    let decoy = orchard::keys::FullViewingKey::from(&decoy_sk)
        .address_at(0u32, orchard::keys::Scope::External)
        .to_raw_address_bytes();
    assert_ne!(decoy, fx.ironwood_recipient);

    let (tampered, n) = patch_all(&fx.redacted_pczt, &fx.ironwood_recipient, &decoy);
    assert!(n > 0, "output recipient not found in the wire bytes");

    let parsed = Pczt::parse(&tampered).expect("tampered PCZT still parses");
    assert!(
        parsed
            .orchard()
            .actions()
            .iter()
            .any(|a| a.output().recipient() == &Some(decoy)),
        "the recipient the confirmation screen would display was not actually changed"
    );

    let err = pczt_signing::summarize(&tampered).expect_err(
        "a PCZT whose displayed recipient contradicts its note commitment must be refused",
    );
    assert!(
        format!("{err}").contains("does not match what it claims to pay"),
        "unexpected rejection reason: {err}"
    );
    assert!(
        pczt_signing::sign_redacted_pczt(&tampered, MNEMONIC, 0, false).is_err(),
        "the device must refuse to sign a PCZT it refused to display"
    );
}

/// TAMPER DETECTION, the bypass variant: the two tests above only catch an
/// attacker who leaves the output `rseed` in place. `verify_note_commitment`
/// needs recipient + value + rseed, and the previous gate treated a MISSING
/// field as "not verifiable, don't block" — so a hostile wallet that simply
/// omits the output `rseed` disabled the gate entirely while `summarize` went
/// on displaying the attacker's chosen recipient and amount, and
/// `sign_redacted_pczt` went on signing (the signing path never reads the
/// output rseed: pczt's low-level signer sets `rseed: None` itself, and the
/// signature is over a sighash that binds the REAL `cmx`). The host then
/// reassembles the transaction with the true rseed and broadcasts.
///
/// The rule is now keyed on what is DISPLAYED, not on which field is absent:
/// an output that renders a recipient or a non-zero amount must verify.
#[test]
fn stripped_output_rseed_does_not_disable_the_display_gate() {
    let fx = common::build_redacted_v5_send();
    pczt_signing::summarize(&fx.redacted_pczt).expect("honest PCZT summarizes");

    // Attacker step 1: drop the output rseed, so `verify_note_commitment`
    // can no longer be computed at all.
    let stripped =
        pczt::roles::redactor::Redactor::new(Pczt::parse(&fx.redacted_pczt).expect("parse"))
            .redact_orchard_with(|mut o| {
                o.redact_actions(|mut a| {
                    a.clear_output_rseed();
                });
            })
            .finish()
            .serialize()
            .expect("serialize rseed-stripped PCZT");

    // Attacker step 2: now lie freely about both displayed fields.
    let mut needle = vec![0x01];
    needle.extend_from_slice(&varint(fx.migrated));
    let mut replacement = vec![0x01];
    replacement.extend_from_slice(&varint(fx.migrated + 1));
    let (tampered, n) = patch_all(&stripped, &needle, &replacement);
    assert!(n > 0, "output value field not found in the wire bytes");

    let decoy_sk = orchard::keys::SpendingKey::from_bytes([11u8; 32]).unwrap();
    let decoy = orchard::keys::FullViewingKey::from(&decoy_sk)
        .address_at(0u32, orchard::keys::Scope::External)
        .to_raw_address_bytes();
    let (tampered, n) = patch_all(&tampered, &fx.ironwood_recipient, &decoy);
    assert!(n > 0, "output recipient not found in the wire bytes");

    // The bytes really do carry the attacker's display values.
    let parsed = Pczt::parse(&tampered).expect("tampered PCZT still parses");
    assert!(
        parsed
            .orchard()
            .actions()
            .iter()
            .any(|a| a.output().recipient() == &Some(decoy)
                && a.output().value() == &Some(fx.migrated + 1)),
        "the values the confirmation screen would display were not actually changed"
    );

    let err = pczt_signing::summarize(&tampered).expect_err(
        "an output that displays a recipient/amount it cannot prove must be refused, \
         not silently skipped",
    );
    assert!(
        format!("{err}").contains("cannot be proven"),
        "unexpected rejection reason: {err}"
    );
    assert!(
        pczt_signing::sign_redacted_pczt(&tampered, MNEMONIC, 0, false).is_err(),
        "the device must refuse to sign a PCZT it refused to display"
    );
}

/// TAMPER DETECTION, the blank-output variant: the reason there is NO skip.
///
/// An intermediate version of the gate allowed an output to skip verification
/// when it rendered nothing (no recipient, no/zero value), on the grounds that
/// there was nothing to lie about. There was: a hostile producer strips
/// `recipient`, `value` AND `rseed` from every output, so each renders as
/// ("orchard:shielded", 0) while the transaction still pays a real amount
/// bound by `cmx`, alongside a plausible producer-supplied fee. The device
/// would display "shielded, 0" and sign a real payment.
#[test]
fn fully_blank_output_is_refused_rather_than_skipped() {
    let fx = common::build_redacted_v5_send();
    let honest = pczt_signing::summarize(&fx.redacted_pczt).expect("honest PCZT summarizes");
    assert!(
        honest.outputs.iter().any(|(_, v)| *v == fx.migrated),
        "the honest summary shows the real payment: {honest:?}"
    );

    // Strip every field the display reads AND the one the proof needs, so the
    // output renders blank and cannot be verified.
    let blanked =
        pczt::roles::redactor::Redactor::new(Pczt::parse(&fx.redacted_pczt).expect("parse"))
            .redact_orchard_with(|mut o| {
                o.redact_actions(|mut a| {
                    a.clear_output_rseed();
                    a.clear_output_recipient();
                    a.clear_output_value();
                });
            })
            .finish()
            .serialize()
            .expect("serialize blanked PCZT");

    let err = pczt_signing::summarize(&blanked)
        .expect_err("an output this device cannot prove must be refused, blank or not");
    assert!(
        format!("{err}").contains("cannot be proven"),
        "unexpected rejection reason: {err}"
    );
    assert!(
        pczt_signing::sign_redacted_pczt(&blanked, MNEMONIC, 0, false).is_err(),
        "the device must refuse to sign a payment it cannot display"
    );
}

/// FEE TAMPERING: the displayed fee is derived from each bundle's `value_sum`,
/// which is plaintext metadata the producer writes into the PCZT. Nothing in
/// the note-commitment check constrains it, so a hostile wallet could pay the
/// user's expected recipient the expected amount (both now provably displayed)
/// while declaring a `value_sum` that renders a trivial fee, and route the
/// rest of a large spent note to the miner.
///
/// `verify_value_balance` proves `value_sum` against `sum(cv_net)` and `bsk`,
/// none of which the producer can move without solving a discrete log.
#[test]
fn tampered_value_sum_is_rejected() {
    let fx = common::build_redacted_v5_send();
    let honest = pczt_signing::summarize(&fx.redacted_pczt).expect("honest PCZT summarizes");
    assert_eq!(honest.fee_zat, Some(fx.fee), "honest fee: {honest:?}");

    // For this shielded-only send the orchard value_sum IS the fee.
    let (tampered, n) = patch_all(&fx.redacted_pczt, &varint(fx.fee), &varint(fx.fee + 1));
    assert!(n > 0, "value_sum varint not found in the wire bytes");

    let err = pczt_signing::summarize(&tampered)
        .expect_err("a declared value balance that the commitments contradict must be refused");
    assert!(
        format!("{err}").contains("does not match the action value commitments"),
        "unexpected rejection reason: {err}"
    );
    assert!(
        pczt_signing::sign_redacted_pczt(&tampered, MNEMONIC, 0, false).is_err(),
        "the device must refuse to sign a fee it refused to display"
    );
}

/// The fee check must not be disableable by withholding `bsk`, the way the
/// output check was disableable by withholding `rseed`.
#[test]
fn stripped_bsk_does_not_disable_the_fee_check() {
    let fx = common::build_redacted_v5_send();
    pczt_signing::summarize(&fx.redacted_pczt).expect("honest PCZT summarizes");

    let no_bsk = pczt::roles::redactor::Redactor::new(Pczt::parse(&fx.redacted_pczt).unwrap())
        .redact_orchard_with(|mut o| {
            o.clear_bsk();
        })
        .finish()
        .serialize()
        .expect("serialize bsk-stripped PCZT");

    let err = pczt_signing::summarize(&no_bsk)
        .expect_err("without bsk the declared fee is unprovable and must be refused");
    assert!(
        format!("{err}").contains("binding key absent"),
        "unexpected rejection reason: {err}"
    );
    assert!(
        pczt_signing::sign_redacted_pczt(&no_bsk, MNEMONIC, 0, false).is_err(),
        "the device must refuse to sign a fee it refused to display"
    );
}

/// LEB128, the varint postcard uses for `u64`.
fn varint(mut v: u64) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let b = (v & 0x7f) as u8;
        v >>= 7;
        if v == 0 {
            out.push(b);
            return out;
        }
        out.push(b | 0x80);
    }
}

/// Replace every occurrence of `needle` with the same-length `replacement`.
/// Returns the patched bytes and the substitution count.
fn patch_all(bytes: &[u8], needle: &[u8], replacement: &[u8]) -> (Vec<u8>, usize) {
    assert_eq!(needle.len(), replacement.len());
    let mut out = bytes.to_vec();
    let mut n = 0;
    let mut i = 0;
    while i + needle.len() <= out.len() {
        if &out[i..i + needle.len()] == needle {
            out[i..i + needle.len()].copy_from_slice(replacement);
            n += 1;
            i += needle.len();
        } else {
            i += 1;
        }
    }
    (out, n)
}

/// COMPACT signatures-only response (the Ironwood QR shrink): a wallet that
/// asks for tx_type 0x05 gets back ONLY the spend-auth signatures (0x07), not
/// the full signed PCZT.
///
/// Correctness gate: the compact payload MUST be byte-identical to the
/// signatures extracted from the full signed-PCZT response - so the wallet
/// that merges the compact signatures reconstructs exactly what the full
/// response would have carried (which tests/interop.rs already proves
/// extracts to a broadcastable transaction).
#[test]
fn compact_v6_migration_returns_signatures_only() {
    let fx = build_redacted_v6_migration();
    let over_the_qr = fx.redacted_pczt.clone();

    // Wallet asks for COMPACT via tx_type 0x05 (single).
    let req = pczt_signing::envelope::encode_request_full(
        &pczt_signing::envelope::SignRequest::Single(pczt_signing::envelope::RequestMessage {
            id: Vec::new(),
            pczt_bytes: over_the_qr.clone(),
        }),
        true,
    )
    .expect("encode compact single request");
    assert_eq!(req[2], pczt_signing::envelope::TX_TYPE_PCZT_SINGLE_COMPACT);

    // Device summarizes exactly as for the legacy flow, then signs compact.
    let summaries = pczt_signing::summarize_request(&req).expect("summarize_request");
    assert_eq!(summaries.len(), 1);
    assert!(summaries[0].ironwood_actions >= 1);

    let resp = pczt_signing::sign_request(&req, MNEMONIC, 0, false).expect("compact sign");
    assert_eq!(
        resp[2],
        pczt_signing::envelope::TX_TYPE_PCZT_SINGLE_COMPACT_RESPONSE,
        "compact request must produce a signatures-only response (0x07), not a full PCZT (0x03)"
    );

    let compact = pczt_signing::parse_compact_response(&resp).expect("parse compact response");
    assert_eq!(compact.messages.len(), 1);
    assert!(compact.messages[0].id.is_empty());
    let returned = &compact.messages[0].signatures;

    // The size win is the point: compact is far smaller than the full
    // signed-PCZT response for this single shielded PCZT.
    let full_resp = pczt_signing::sign_request(
        &pczt_signing::envelope::encode_request(&pczt_signing::envelope::SignRequest::Single(
            pczt_signing::envelope::RequestMessage {
                id: Vec::new(),
                pczt_bytes: over_the_qr.clone(),
            },
        ))
        .expect("encode legacy single request"),
        MNEMONIC,
        0,
        false,
    )
    .expect("full sign");
    assert!(
        resp.len() * 4 < full_resp.len(),
        "compact response ({}) must be far smaller than the full signed-PCZT response ({})",
        resp.len(),
        full_resp.len()
    );

    // Correctness gate: the compact response must cover EXACTLY the same
    // (pool, action_index) spend-auth slots the full signed-PCZT response
    // carries - i.e. the wallet that merges the compact signatures lands them
    // on precisely the actions the full path signed. (Signature bytes are NOT
    // compared across the two runs: RedPallas spend-auth signing is
    // randomized, so a fresh sign run legitimately differs. The strong check
    // that the compact bytes are actually VALID for their actions is the
    // `apply_signature_contribution` / `apply_orchard_spend_auth_signature`
    // verify-before-store below.)
    let reference_slots: Vec<_> = {
        let signed = Pczt::parse(&full_resp[3 + 32 + 4..]).expect("parse signed pczt");
        use pczt::roles::signer::extract_orchard_spend_auth_signatures;
        extract_orchard_spend_auth_signatures(&signed)
            .into_iter()
            .map(|s| {
                (
                    match s.value_pool() {
                        orchard::ValuePool::Orchard => pczt_signing::envelope::POOL_ORCHARD,
                        orchard::ValuePool::Ironwood => pczt_signing::envelope::POOL_IRONWOOD,
                    },
                    s.action_index(),
                )
            })
            .collect()
    };
    let mut ours: Vec<_> = returned
        .iter()
        .map(|c| (c.pool, c.action_index as usize))
        .collect();
    ours.sort_unstable();
    let mut reference = reference_slots;
    reference.sort_unstable();
    assert_eq!(
        ours, reference,
        "compact response must cover exactly the signed (pool, action_index) slots of the full path"
    );
    assert!(
        returned
            .iter()
            .any(|c| c.pool == pczt_signing::envelope::POOL_IRONWOOD),
        "the migration's ironwood spend signature is returned"
    );

    // VALIDITY gate: each returned signature verifies against its action's
    // randomized verification key over the shielded sighash - the exact check
    // the wallet's merge (`apply_orchard_spend_auth_signature` /
    // `orchard::pczt::Action::apply_signature`) performs before storing, so a
    // compact response is provably as good as the full signed PCZT.
    let merged = Pczt::parse(&over_the_qr).expect("parse original");
    let shielded_sighash = pczt::roles::signer::Signer::new(merged.clone())
        .expect("signer")
        .shielded_sighash();
    let mut applied = 0;
    for c in returned {
        let action = match c.pool {
            pczt_signing::envelope::POOL_ORCHARD => {
                merged.orchard().actions().get(c.action_index as usize)
            }
            pczt_signing::envelope::POOL_IRONWOOD => {
                merged.ironwood().actions().get(c.action_index as usize)
            }
            _ => unreachable!(),
        };
        let action = action
            .unwrap_or_else(|| panic!("contribution references an action out of range: {c:?}"));
        let sig = orchard::primitives::redpallas::Signature::<
            orchard::primitives::redpallas::SpendAuth,
        >::from(c.signature);
        let rk: orchard::primitives::redpallas::VerificationKey<
            orchard::primitives::redpallas::SpendAuth,
        > = (*action.spend().rk())
            .try_into()
            .expect("action carries a valid rk");
        assert!(
            rk.verify(&shielded_sighash, &sig).is_ok(),
            "contribution {c:?} is NOT a valid spend-auth signature for its action"
        );
        applied += 1;
    }
    assert!(applied >= 1);
}

/// COMPACT BATCH: a single QR exchange for a multi-PCZT migration. The device
/// gives back one signatures list per PCZT in request order, echoing ids, and
/// the whole thing rides one much smaller response envelope.
#[test]
fn compact_batch_returns_per_pczt_signatures_with_ids() {
    let v6 = build_redacted_v6_migration();
    let v5 = build_redacted_v5_send();

    let req = pczt_signing::envelope::encode_request_full(
        &pczt_signing::envelope::SignRequest::Batch(vec![
            pczt_signing::envelope::RequestMessage {
                id: b"migrate-1".to_vec(),
                pczt_bytes: v6.redacted_pczt.clone(),
            },
            pczt_signing::envelope::RequestMessage {
                id: b"send-2".to_vec(),
                pczt_bytes: v5.redacted_pczt.clone(),
            },
        ]),
        true,
    )
    .expect("encode compact batch request");
    assert_eq!(req[2], pczt_signing::envelope::TX_TYPE_PCZT_BATCH_COMPACT);

    let summaries = pczt_signing::summarize_request(&req).expect("summarize compact batch");
    assert_eq!(summaries.len(), 2);

    let resp = pczt_signing::sign_request(&req, MNEMONIC, 0, false).expect("compact batch sign");
    assert_eq!(
        resp[2],
        pczt_signing::envelope::TX_TYPE_PCZT_BATCH_COMPACT_RESPONSE,
        "compact batch request must produce a batch signatures-only response (0x08)"
    );

    let compact = pczt_signing::parse_compact_response(&resp).expect("parse compact batch");
    assert_eq!(compact.messages.len(), 2);
    assert_eq!(compact.messages[0].id, b"migrate-1");
    assert_eq!(compact.messages[1].id, b"send-2");
    assert!(
        compact.messages[0]
            .signatures
            .iter()
            .any(|c| c.pool == pczt_signing::envelope::POOL_IRONWOOD),
        "migration message returns its ironwood signature"
    );
    assert!(
        compact.messages[0]
            .signatures
            .iter()
            .any(|c| c.pool == pczt_signing::envelope::POOL_ORCHARD),
        "migration message returns its orchard signatures too"
    );
    assert!(
        compact.messages[1]
            .signatures
            .iter()
            .all(|c| c.pool == pczt_signing::envelope::POOL_ORCHARD),
        "a V5 send carries no ironwood signatures"
    );
}
