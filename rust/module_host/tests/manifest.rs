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
    let pkg = build_package(
        b"wasm",
        5,
        1,
        "test module",
        &[(0, sk[0].clone()), (2, sk[2].clone())],
    );
    let m = verify_package(&pkg, &vk, 1, 4).expect("verifies");
    assert_eq!(m.module_version, 5);
    assert_eq!(m.module_bytes, b"wasm");
}

#[test]
fn one_signature_is_rejected() {
    let (sk, vk) = keys();
    let pkg = build_package(b"wasm", 5, 1, "m", &[(0, sk[0].clone())]);
    assert!(matches!(
        verify_package(&pkg, &vk, 1, 0),
        Err(ManifestError::NotEnoughSignatures(1))
    ));
}

#[test]
fn same_key_twice_is_rejected() {
    let (sk, vk) = keys();
    let pkg = build_package(
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
    let pkg = build_package(
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
    let mut pkg = build_package(
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
    let mut pkg = build_package(
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
