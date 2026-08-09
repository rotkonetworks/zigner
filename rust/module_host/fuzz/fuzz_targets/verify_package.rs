//! Whole-package verification against a fixed key set.
//!
//! The keys are fixed and the fuzzer does not know them, so this is not
//! trying to forge a signature - it is checking that everything reachable on
//! the way to the signature check survives hostile bytes.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let vk = [
        ed25519_dalek::SigningKey::from_bytes(&[1u8; 32]).verifying_key(),
        ed25519_dalek::SigningKey::from_bytes(&[2u8; 32]).verifying_key(),
        ed25519_dalek::SigningKey::from_bytes(&[3u8; 32]).verifying_key(),
    ];
    let base = b"a plausible base module";
    if let Ok(v) = module_host::manifest::verify_package_with_base(data, &vk, 1, 0, Some(base)) {
        // Reaching here means the fuzzer produced two valid signatures over a
        // key set it never saw, which would be the finding of the decade.
        // Assert the invariant anyway rather than trusting it.
        use sha2::Digest;
        let h: [u8; 32] = sha2::Sha256::digest(v.module_bytes.as_ref()).into();
        let (fields, _) = module_host::manifest::parse_signing_prefix(data).unwrap();
        assert_eq!(h, fields.module_hash, "accepted a module the manifest did not commit to");
    }
});
