//! Voting-delegation display: a delegation PCZT (zafu's
//! `build_delegation_pczt` / `build_governance_pczt`, `zcli/crates/
//! zcash-voting`) must render a truthful "voting delegation authorization"
//! screen, not a payment screen - and an ordinary send must NOT be
//! misclassified as a delegation. See `pczt_signing::detect_delegation` for
//! the detection rule and exactly what is/is not displayable.

mod common;

use common::{build_redacted_delegation, build_redacted_v5_send, build_redacted_v6_migration};

#[test]
fn delegation_pczt_is_recognized_and_shows_zero_value_hotkey_recipient() {
    let fx = build_redacted_delegation();

    let summary = pczt_signing::summarize(&fx.redacted_pczt).expect("summary");

    let delegation = summary
        .delegation
        .as_ref()
        .expect("delegation-shaped PCZT must be recognized as a delegation");

    let expected_hex: String = fx
        .hotkey_recipient
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    assert_eq!(
        delegation.hotkey_recipient, expected_hex,
        "displayed hotkey recipient must match the cmx-bound governance output recipient"
    );

    // The governance output must show zero value - the money-relevant fact
    // that makes it safe to distinguish this from a payment at all.
    assert!(
        summary
            .outputs
            .iter()
            .any(|(l, v)| l.starts_with("ironwood:") && *v == 0),
        "governance output must render as zero-value: {summary:?}"
    );

    // Structural signals a delegation PCZT is expected to satisfy. The
    // orchard default builder pads to a minimum of 2 actions, so this is
    // ironwood_actions == 2 (one real governance action + one dummy padding
    // action), not 1 - see `detect_delegation`'s doc comment.
    assert_eq!(summary.orchard_actions, 0);
    assert_eq!(summary.ironwood_actions, 2);
    assert_eq!(summary.transparent_inputs, 0);

    // Signing must still work - display truthfulness must not regress the
    // existing signing contract.
    let signed = pczt_signing::sign_redacted_pczt(&fx.redacted_pczt, common::MNEMONIC, 0, false)
        .expect("device signs the delegation PCZT");
    assert!(!signed.is_empty());
}

#[test]
fn delegation_head_line_reports_kind_delegation() {
    let fx = build_redacted_delegation();
    let payload = pczt_signing::envelope::encode_request(&pczt_signing::envelope::SignRequest::Single(
        pczt_signing::envelope::RequestMessage {
            id: Vec::new(),
            pczt_bytes: fx.redacted_pczt.clone(),
        },
    ))
    .expect("encode single request");
    let summaries = pczt_signing::summarize_request(&payload).expect("summarize_request");
    assert_eq!(summaries.len(), 1);
    assert!(
        summaries[0].delegation.is_some(),
        "request-level summary must also carry the delegation recognition"
    );
}

#[test]
fn ordinary_v5_send_is_not_misclassified_as_a_delegation() {
    let fx = build_redacted_v5_send();
    let summary = pczt_signing::summarize(&fx.redacted_pczt).expect("summary");
    assert!(
        summary.delegation.is_none(),
        "an ordinary non-zero-value orchard send must never render as a delegation: {summary:?}"
    );
}

#[test]
fn v6_migration_is_not_misclassified_as_a_delegation() {
    // A real orchard->ironwood migration has BOTH an orchard action (the
    // spend) and an ironwood action (the migrated output) - two actions
    // total, and the ironwood output carries the real migrated value, not
    // zero. Neither condition satisfies delegation detection.
    let fx = build_redacted_v6_migration();
    let summary = pczt_signing::summarize(&fx.redacted_pczt).expect("summary");
    assert!(
        summary.delegation.is_none(),
        "a value-carrying migration must never render as a delegation: {summary:?}"
    );
}

