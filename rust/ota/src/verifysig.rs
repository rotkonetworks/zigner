//! Strict Ed25519 verification and signing (RFC 8032) over domain-tagged
//! canonical CBOR forms.

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};

use crate::types::{
    image_canonical, manifest_signed_canonical, result_signed_canonical, status_signed_canonical,
    ImageHeader, Manifest, OtaResult, Status, TAG_IMAGE, TAG_MANIFEST, TAG_RESULT, TAG_STATUS,
};
use crate::Error;

/// Reject the identity/small-order public key at pin time (RFC 8032 §3.1).
fn pin_pubkey(pubkey: &[u8; 32]) -> Result<VerifyingKey, Error> {
    let vk =
        VerifyingKey::from_bytes(pubkey).map_err(|e| Error(format!("invalid pubkey: {e:?}")))?;
    if vk.is_weak() {
        return Err(Error(
            "small-order / identity public key rejected at pin".into(),
        ));
    }
    Ok(vk)
}

fn parse_sig(sig: &[u8; 64]) -> Signature {
    Signature::from_bytes(sig)
}

/// Strictly verify the manifest signature: `ed25519(TAG_MANIFEST ||
/// canonical(1..7))` against `pubkey`.
pub fn verify_manifest(
    manifest: &Manifest,
    manifest_sig: &[u8; 64],
    pubkey: &[u8; 32],
) -> Result<(), Error> {
    let vk = pin_pubkey(pubkey)?;
    let mut msg = TAG_MANIFEST.to_vec();
    msg.extend_from_slice(&manifest_signed_canonical(manifest)?);
    vk.verify_strict(&msg, &parse_sig(manifest_sig))
        .map_err(|e| Error(format!("manifest signature invalid: {e:?}")))
}

/// Strictly verify the image signature: `ed25519(TAG_IMAGE ||
/// canonical{1..5})` against `pubkey`.
pub fn verify_image(
    header: &ImageHeader,
    image_sig: &[u8; 64],
    pubkey: &[u8; 32],
) -> Result<(), Error> {
    let vk = pin_pubkey(pubkey)?;
    let mut msg = TAG_IMAGE.to_vec();
    msg.extend_from_slice(&image_canonical(header)?);
    vk.verify_strict(&msg, &parse_sig(image_sig))
        .map_err(|e| Error(format!("image signature invalid: {e:?}")))
}

/// Strictly verify the result signature against the embedded `zid_pubkey`.
pub fn verify_result(result: &OtaResult) -> Result<(), Error> {
    let vk = pin_pubkey(&result.zid_pubkey)?;
    let mut msg = TAG_RESULT.to_vec();
    msg.extend_from_slice(&result_signed_canonical(result)?);
    vk.verify_strict(&msg, &parse_sig(&result.result_sig))
        .map_err(|e| Error(format!("result signature invalid: {e:?}")))
}

/// Strictly verify the status signature against the embedded `zid_pubkey`.
pub fn verify_status(status: &Status) -> Result<(), Error> {
    let vk = pin_pubkey(&status.zid_pubkey)?;
    let mut msg = TAG_STATUS.to_vec();
    msg.extend_from_slice(&status_signed_canonical(status)?);
    vk.verify_strict(&msg, &parse_sig(&status.status_sig))
        .map_err(|e| Error(format!("status signature invalid: {e:?}")))
}

/// Sign a pre-built signed set (tag || canonical) with the ZID secret key.
pub(crate) fn sign(tag: &[u8], canonical: &[u8], secret_key: &[u8; 32]) -> Result<[u8; 64], Error> {
    let sk = SigningKey::from_bytes(secret_key);
    let sig = sk.sign(&concat_tag(tag, canonical));
    Ok(sig.to_bytes())
}

fn concat_tag(tag: &[u8], canonical: &[u8]) -> Vec<u8> {
    let mut v = tag.to_vec();
    v.extend_from_slice(canonical);
    v
}
