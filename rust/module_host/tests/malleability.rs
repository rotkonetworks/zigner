#[test]
fn appended_bytes_to_a_signed_delta_package_are_refused() {
    use ed25519_dalek::SigningKey;
    use module_host::manifest::{ManifestError::PayloadLengthMismatch, *};
    use sha2::{Digest, Sha256};
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
    let base: Vec<u8> = (0..20_000u32).map(|i| (i % 251) as u8).collect();
    let mut new = base.clone();
    new[100] ^= 0xff;
    let mut raw = Vec::new();
    bsdiff::diff(&base, &new, &mut raw).unwrap();
    let patch = zstd::stream::encode_all(raw.as_slice(), 19).unwrap();
    let pkg = build_package(
        &patch,
        Sha256::digest(&new).into(),
        PAYLOAD_BSDIFF_ZSTD,
        Sha256::digest(&base).into(),
        5,
        1,
        "d",
        &[(0, sk[0].clone()), (2, sk[2].clone())],
    );
    assert!(
        verify_package_with_base(&pkg, &vk, 1, 0, Some(&base)).is_ok(),
        "baseline must verify"
    );
    let mut padded = pkg.clone();
    padded.extend_from_slice(&[0xAAu8; 4096]);
    let r = verify_package_with_base(&padded, &vk, 1, 0, Some(&base));
    assert!(
        matches!(r, Err(PayloadLengthMismatch)),
        "a signed package must have exactly one encoding - appended bytes \
         verified, which breaks any later use of the package hash for \
         caching, dedup or audit"
    );
}
