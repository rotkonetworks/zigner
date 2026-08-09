use ed25519_dalek::SigningKey;
use module_host::manifest::*;

fn keys() -> ([SigningKey; 3], [ed25519_dalek::VerifyingKey; 3]) {
    let sk = [
        SigningKey::from_bytes(&[1u8; 32]),
        SigningKey::from_bytes(&[2u8; 32]),
        SigningKey::from_bytes(&[3u8; 32]),
    ];
    let vk = [
        sk[0].verifying_key(),
        sk[1].verifying_key(),
        sk[2].verifying_key(),
    ];
    (sk, vk)
}

#[test]
fn two_of_three_verifies() {
    let (sk, vk) = keys();
    let pkg = build_full_package(
        b"wasm",
        5,
        1,
        "test module",
        &[(0, sk[0].clone()), (2, sk[2].clone())],
    );
    let m = verify_package(&pkg, &vk, 1, 4).expect("verifies");
    assert_eq!(m.module_version, 5);
    assert_eq!(&m.module_bytes[..], b"wasm");
}

#[test]
fn one_signature_is_rejected() {
    let (sk, vk) = keys();
    let pkg = build_full_package(b"wasm", 5, 1, "m", &[(0, sk[0].clone())]);
    assert!(matches!(
        verify_package(&pkg, &vk, 1, 0),
        Err(ManifestError::NotEnoughSignatures(1))
    ));
}

#[test]
fn same_key_twice_is_rejected() {
    let (sk, vk) = keys();
    let pkg = build_full_package(
        b"wasm",
        5,
        1,
        "m",
        &[(1, sk[1].clone()), (1, sk[1].clone())],
    );
    assert!(matches!(
        verify_package(&pkg, &vk, 1, 0),
        Err(ManifestError::DuplicateKey(1))
    ));
}

#[test]
fn rollback_is_rejected() {
    let (sk, vk) = keys();
    let pkg = build_full_package(
        b"wasm",
        5,
        1,
        "m",
        &[(0, sk[0].clone()), (1, sk[1].clone())],
    );
    assert!(matches!(
        verify_package(&pkg, &vk, 1, 5),
        Err(ManifestError::Rollback { .. })
    ));
}

#[test]
fn tampered_module_is_rejected() {
    let (sk, vk) = keys();
    let mut pkg = build_full_package(
        b"wasm",
        5,
        1,
        "m",
        &[(0, sk[0].clone()), (1, sk[1].clone())],
    );
    let n = pkg.len();
    pkg[n - 1] ^= 1;
    assert!(matches!(
        verify_package(&pkg, &vk, 1, 0),
        Err(ManifestError::HashMismatch)
    ));
}

#[test]
fn tampered_manifest_field_is_rejected() {
    let (sk, vk) = keys();
    let mut pkg = build_full_package(
        b"wasm",
        5,
        3,
        "m",
        &[(0, sk[0].clone()), (1, sk[1].clone())],
    );
    pkg[9] = 1; // lower min_kernel_version post-signing
    assert!(matches!(
        verify_package(&pkg, &vk, 1, 0),
        Err(ManifestError::BadSignature(0))
    ));
}

// ── v2: payload kinds and the delta base ────────────────────────────────────

use sha2::{Digest, Sha256};

fn sha(b: &[u8]) -> [u8; 32] {
    Sha256::digest(b).into()
}

/// v1 packages must not verify. v1 never shipped - no package could ever have
/// been accepted, since the release keys are placeholders - so accepting it
/// would only widen the parser for no one's benefit.
#[test]
fn v1_manifests_are_refused() {
    let (sk, vk) = keys();
    let mut pkg = build_full_package(
        b"wasm",
        5,
        1,
        "m",
        &[(0, sk[0].clone()), (2, sk[2].clone())],
    );
    pkg[4] = 1; // manifest_version
    assert!(matches!(
        verify_package(&pkg, &vk, 1, 0),
        Err(ManifestError::UnsupportedVersion(1))
    ));
}

/// A full payload must carry an all-zero base_hash, so a package has exactly
/// one valid encoding and cannot be read two ways.
#[test]
fn full_payload_with_a_base_hash_is_refused() {
    let (sk, vk) = keys();
    let pkg = build_package(
        b"wasm",
        sha(b"wasm"),
        PAYLOAD_FULL,
        [7u8; 32],
        5,
        1,
        "m",
        &[(0, sk[0].clone()), (2, sk[2].clone())],
    );
    assert!(matches!(
        verify_package(&pkg, &vk, 1, 0),
        Err(ManifestError::BaseHashMismatch)
    ));
}

#[test]
fn a_patch_without_a_base_is_refused() {
    let (sk, vk) = keys();
    let pkg = build_package(
        b"delta",
        sha(b"the result"),
        PAYLOAD_ZSTD_PATCH,
        sha(b"the base"),
        5,
        1,
        "m",
        &[(0, sk[0].clone()), (2, sk[2].clone())],
    );
    assert!(matches!(
        verify_package(&pkg, &vk, 1, 0),
        Err(ManifestError::MissingBaseModule)
    ));
}

#[test]
fn a_patch_against_the_wrong_base_is_refused() {
    let (sk, vk) = keys();
    let pkg = build_package(
        b"delta",
        sha(b"the result"),
        PAYLOAD_ZSTD_PATCH,
        sha(b"the base"),
        5,
        1,
        "m",
        &[(0, sk[0].clone()), (2, sk[2].clone())],
    );
    assert!(matches!(
        verify_package_with_base(&pkg, &vk, 1, 0, Some(b"a different base")),
        Err(ManifestError::BaseHashMismatch)
    ));
}

/// Documents the open seam: the format accepts patches, the applier is not
/// compiled in yet. Flip this test when a patch crate lands.
#[test]
fn a_patch_with_the_right_base_reaches_the_applier() {
    let (sk, vk) = keys();
    let base = b"the base";
    let pkg = build_package(
        b"delta",
        sha(b"the result"),
        PAYLOAD_ZSTD_PATCH,
        sha(base),
        5,
        1,
        "m",
        &[(0, sk[0].clone()), (2, sk[2].clone())],
    );
    assert!(matches!(
        verify_package_with_base(&pkg, &vk, 1, 0, Some(base)),
        Err(ManifestError::PatchUnsupported)
    ));
}

/// The signatures cover the RESULT hash, so an unsigned change to the payload
/// cannot smuggle a different module through - this is what lets the patch
/// itself travel untrusted.
#[test]
fn tampering_with_the_payload_fails_the_result_hash() {
    let (sk, vk) = keys();
    let mut pkg = build_full_package(
        b"wasm",
        5,
        1,
        "m",
        &[(0, sk[0].clone()), (2, sk[2].clone())],
    );
    let n = pkg.len();
    pkg[n - 1] ^= 0xff;
    assert!(matches!(
        verify_package(&pkg, &vk, 1, 0),
        Err(ManifestError::HashMismatch)
    ));
}
