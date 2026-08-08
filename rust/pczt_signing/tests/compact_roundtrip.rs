//! The leg the whole compact optimization rests on: device signs a redacted
//! PCZT -> returns ONLY the signatures it produced -> the wallet merges them
//! into the full PCZT it retained. Regression cover for the review findings.
mod common;
use common::*;

const MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

fn compact_request(pczt: &[u8]) -> Vec<u8> {
    pczt_signing::envelope::encode_request_full(
        &pczt_signing::envelope::SignRequest::Single(pczt_signing::envelope::RequestMessage {
            id: b"rt".to_vec(),
            pczt_bytes: pczt.to_vec(),
        }),
        true,
    )
    .expect("encode compact request")
}

/// F1: the response carries ONLY signatures this device produced - never the
/// pre-authorized dummy signatures the wallet shipped in the request.
#[test]
fn response_excludes_signatures_the_wallet_supplied() {
    let fx = build_redacted_v6_migration();
    let before = pczt::Pczt::parse(&fx.redacted_pczt).expect("parse request");
    let preexisting = pczt::roles::signer::extract_orchard_spend_auth_signatures(&before).len();
    assert!(
        preexisting > 0,
        "fixture must carry builder-authorized dummies for this to be meaningful"
    );

    let resp = pczt_signing::sign_request(&compact_request(&fx.redacted_pczt), MNEMONIC, 0, false)
        .expect("device signs");
    let parsed = pczt_signing::parse_compact_response(&resp).expect("parse response");
    let returned: usize = parsed.messages.iter().map(|m| m.signatures.len()).sum();

    let after_all = pczt::roles::signer::extract_orchard_spend_auth_signatures(
        &pczt::Pczt::parse(
            &pczt_signing::sign_redacted_pczt(&fx.redacted_pczt, MNEMONIC, 0, false).unwrap(),
        )
        .unwrap(),
    )
    .len();
    assert_eq!(
        returned,
        after_all - preexisting,
        "compact response must be exactly the delta this device added"
    );
}

/// F1/F3: a request this device can authorize nothing in must FAIL, not come
/// back as a success carrying the wallet's own signatures.
#[test]
fn wrong_account_is_refused_not_silently_successful() {
    let fx = build_redacted_v6_migration();
    let err = pczt_signing::sign_request(&compact_request(&fx.redacted_pczt), MNEMONIC, 7, false)
        .expect_err("must refuse when it authorized nothing");
    let msg = format!("{err:?}");
    assert!(
        msg.contains("authorized no action"),
        "unexpected error: {msg}"
    );
}

/// F5: the full round trip, through the real merge API the wallet uses.
#[test]
fn device_signatures_merge_into_the_retained_pczt() {
    let fx = build_redacted_v6_migration();
    let resp = pczt_signing::sign_request(&compact_request(&fx.redacted_pczt), MNEMONIC, 0, false)
        .expect("device signs");
    let parsed = pczt_signing::parse_compact_response(&resp).expect("parse response");

    let mut merged = pczt::Pczt::parse(&fx.full_pczt).expect("wallet's retained pczt");
    let mut applied = 0usize;
    for m in &parsed.messages {
        for c in &m.signatures {
            merged = pczt_signing::apply_signature_contribution(merged, c)
                .unwrap_or_else(|e| panic!("wallet merge rejected {c:?}: {e:?}"));
            applied += 1;
        }
    }
    assert!(applied > 0, "nothing was merged");
}

/// A contribution that is not a valid spend-auth signature for its action must
/// be REFUSED by the merge, not absorbed.
#[test]
fn merge_refuses_a_forged_contribution() {
    let fx = build_redacted_v6_migration();
    let resp = pczt_signing::sign_request(&compact_request(&fx.redacted_pczt), MNEMONIC, 0, false)
        .expect("device signs");
    let parsed = pczt_signing::parse_compact_response(&resp).expect("parse");
    let mut forged = parsed.messages[0].signatures[0].clone();
    forged.signature[0] ^= 0xff;

    let pczt = pczt::Pczt::parse(&fx.full_pczt).expect("retained");
    assert!(
        pczt_signing::apply_signature_contribution(pczt, &forged).is_err(),
        "a tampered signature must not be accepted by the wallet merge"
    );
}
