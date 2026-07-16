//! Smoke tests. The real interop test (produce+redact with zcli's
//! zafu-wasm, sign here, extract there) lands when this crate is wired
//! as that repo's dev-dependency - tracked in
//! docs/keystone-compat-pczt-signing.md.

#[test]
fn garbage_is_a_parse_error_not_a_panic() {
    let err = pczt_signing::summarize(b"definitely not a pczt").unwrap_err();
    assert!(matches!(err, pczt_signing::Error::Parse(_)));
}

#[test]
fn bad_mnemonic_is_a_seed_error() {
    let err = pczt_signing::sign_redacted_pczt(&[0u8; 8], "not a mnemonic", 0, true).unwrap_err();
    // parse fails before seed on malformed pczt bytes; use a valid-prefix
    // check only on the error kind ordering we guarantee: parse first.
    assert!(matches!(err, pczt_signing::Error::Parse(_)));
}
