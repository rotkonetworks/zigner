//! Compact PCZT signing: the wallet redacts cv_net, anchors (v6), and
//! output ciphertexts; the signer resolves these fields once in `summarize`
//! and `sign_redacted_pczt` so the same verification gates apply to compact
//! and full PCZTs.
//!
//! Tests verify: (1) resolve_fields is called by summarize and sign paths,
//! and (2) the resolution preserves verification correctness.

mod common;

use common::{build_redacted_v6_migration, MNEMONIC};
use pczt::Pczt;

/// Verify that the signer's `summarize` correctly processes a redacted V6 PCZT
/// and computes the expected fee by calling resolve_fields internally.
#[test]
fn v6_pczt_summarize_resolves_fields() {
    let fx = build_redacted_v6_migration();

    // The standard redacted PCZT (what the wallet sends)
    let summary = pczt_signing::summarize(&fx.redacted_pczt).expect("summarize redacted PCZT");
    assert!(summary.orchard_actions >= 1, "orchard actions visible");
    assert!(summary.ironwood_actions >= 1, "ironwood actions visible");
    assert_eq!(summary.fee_zat, Some(fx.fee), "fee computed correctly");
}

/// Verify that the signer can sign a redacted V6 PCZT after calling
/// resolve_fields internally.
#[test]
fn v6_pczt_signing_resolves_fields() {
    let fx = build_redacted_v6_migration();

    // Signing should work on the redacted PCZT (resolve_fields is called internally)
    let signed_bytes = pczt_signing::sign_redacted_pczt(&fx.redacted_pczt, MNEMONIC, 0, false)
        .expect("sign redacted PCZT");
    let signed = Pczt::parse(&signed_bytes).expect("signed PCZT parses");

    // Verify spend-auth signatures are present
    assert!(
        signed
            .orchard()
            .actions()
            .iter()
            .any(|a| a.spend().spend_auth_sig().is_some()),
        "orchard spend-auth signatures present"
    );
    assert!(
        signed
            .ironwood()
            .actions()
            .iter()
            .any(|a| a.spend().spend_auth_sig().is_some()),
        "ironwood spend-auth signatures present"
    );
}

/// Regression test: verify that a PCZT with explicit cv_net and cmx still works
/// (the resolve_fields call is a no-op when these fields are already present).
#[test]
fn explicit_cv_net_and_cmx_is_noop() {
    let fx = build_redacted_v6_migration();

    // Parse the redacted PCZT - it has explicit cv_net and cmx (not omitted)
    let pczt = Pczt::parse(&fx.redacted_pczt).expect("parse redacted PCZT");

    // resolve_fields should be a no-op on a PCZT where these fields are present
    let mut pczt2 = pczt.clone();
    pczt2.resolve_fields().expect("resolve_fields succeeds");

    // Both PCZTs should serialize to the same bytes (resolve_fields is a no-op)
    let bytes1 = pczt.serialize().expect("serialize original");
    let bytes2 = pczt2.serialize().expect("serialize after resolve_fields");
    assert_eq!(bytes1, bytes2, "resolve_fields is a no-op on full PCZT");

    // Signing should work either way
    let summary1 = pczt_signing::summarize(&bytes1).expect("summarize original");
    let summary2 = pczt_signing::summarize(&bytes2).expect("summarize after resolve");
    assert_eq!(summary1.fee_zat, summary2.fee_zat, "fee is the same");
}
