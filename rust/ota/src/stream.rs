//! Stream verification: the device's load-bearing gate (§6.2).
//!
//! Input is the reassembled `ur:zafu-stream` buffer = `manifest_cbor ||
//! image_wrapper` (manifest is frame[0], at byte offset 0). Validates the
//! manifest signature + image signature against the pinned key, then the
//! applicability gates (blacklist / board / class / anti-rollback), then
//! decodes the trailing image wrapper and re-derives the full-image hash.

use sha2::{Digest, Sha256};

use crate::semver;
use crate::types::{decode_manifest, ImageHeader, Manifest, CLASS_RELEASE, CLASS_ROLLBACK};
use crate::verifysig::{verify_image, verify_manifest};
use crate::{decode_one, Error};

/// Fail with a formatted crate error (internal helper).
macro_rules! err {
    ($($t:tt)*) => { return Err(Error(format!($($t)*))) };
}

/// Result of a fully verified stream (data eligible for verified staging).
#[derive(Debug, Clone)]
pub struct VerifiedStream {
    pub manifest: Manifest,
    pub image_header: ImageHeader,
    pub payload_sha256: [u8; 32],
    pub payload_len: u64,
}

/// Default staging chunk size used for per-chunk hash verification.
pub const STAGING_CHUNK: usize = 256;

/// v1 module-image size cap (bytes). The delivered OTA target is a small
/// signed module image, not a whole-firmware replacement; the freeze spec's
/// open item suggests ~250 KB for v1 but the product frame is a few MB.
/// We cap at 3 MiB so a QR scan stays ~1-2 minutes and a runaway/malformed
/// stream can never claim a huge payload to stage.
pub const MAX_MODULE_SIZE: u64 = 3 * 1024 * 1024;

/// Verify a full `ur:zafu-stream` buffer.
///
/// * `payload_bytes`  — reassembled buffer: `manifest_cbor || image_wrapper`.
/// * `manifest_sig`   — 64-byte manifest signature over fields 1..7. The
///   frozen wire carries the image_sig (manifest field 8) inline but does NOT
///   embed the manifest signature; the scan/carrier layer provides it.
/// * `pinned_pubkey`  — 32-byte Zafu update public key (burned in).
/// * `current_version`— currently applied firmware version (anti-rollback).
/// * `board`          — expected target board name.
/// * `blacklist`      — revoked `key_id`s (empty in dev).
///
/// `rollback_on_wire` controls whether a `rollback`-class stream is accepted
/// here. The wire/apply path MUST keep it `false` (rollback is a device-local,
/// human-gated action, never applied from a stream).
pub fn verify_stream(
    payload_bytes: &[u8],
    manifest_sig: &[u8; 64],
    pinned_pubkey: &[u8; 32],
    current_version: &str,
    board: &str,
    blacklist: &[u64],
    rollback_on_wire: bool,
) -> Result<VerifiedStream, Error> {
    // ── 1. Parse manifest at offset 0 (self-delimiting CBOR) ──────────────
    if payload_bytes.is_empty() {
        err!("empty stream buffer");
    }
    let (manifest, manifest_len) = decode_manifest_prefix(payload_bytes)?;
    let image_sig = manifest
        .image_sig
        .as_ref()
        .ok_or_else(|| Error("manifest has no image_sig on the wire".into()))?;
    let _ = manifest
        .req_id
        .as_ref()
        .ok_or_else(|| Error("manifest has no req_id on the wire".into()))?;

    // Size discipline: the OTA target is a small signed module image.
    if manifest.payload_size > MAX_MODULE_SIZE {
        err!(
            "payload_size {} exceeds the {} byte module-image cap",
            manifest.payload_size,
            MAX_MODULE_SIZE
        );
    }

    // ── 2. Signature verification against pinned key ──────────────────────
    verify_manifest(&manifest, manifest_sig, pinned_pubkey)?;

    // Build the signed image header from the manifest field set.
    let header = ImageHeader {
        key_id: manifest.key_id,
        board: manifest.board.clone(),
        version: manifest.version.clone(),
        payload_sha256: manifest.payload_sha256,
        payload_len: manifest.payload_size,
    };
    verify_image(&header, image_sig, pinned_pubkey)?;

    // ── 3. Applicability gates ────────────────────────────────────────────
    if blacklist.contains(&manifest.key_id) {
        err!("key_id {} is blacklisted/revoked", manifest.key_id);
    }

    if manifest.board != board {
        err!(
            "board mismatch: stream targets '{}' but device is '{}'",
            manifest.board,
            board
        );
    }

    match manifest.class.as_str() {
        CLASS_RELEASE => {}
        CLASS_ROLLBACK => {
            if !rollback_on_wire {
                err!("rollback-class stream is not applicable on the wire (device-local only)");
            }
        }
        other => err!("unknown firmware class: {other}"),
    }

    // ── 4. Anti-rollback / downgrade (normative semver) ───────────────────
    let version = semver::parse(&manifest.version)
        .ok_or_else(|| Error(format!("invalid firmware version '{}'", manifest.version)))?;
    let min_version = semver::parse(&manifest.min_version)
        .ok_or_else(|| Error(format!("invalid min_version '{}'", manifest.min_version)))?;
    if version < min_version {
        err!(
            "version {} is below the signed min_version {}",
            manifest.version,
            manifest.min_version
        );
    }
    if let Some(cur) = semver::parse(current_version) {
        if version <= cur {
            err!(
                "version {} is not > current {} (anti-rollback)",
                manifest.version,
                current_version
            );
        }
    } else {
        // current unknown: fail closed rather than allow a possibly-older image.
        err!("cannot establish current firmware version '{current_version}' for anti-rollback");
    }

    // ── 5. Decode trailing image wrapper ──────────────────────────────────
    let wrapper = &payload_bytes[manifest_len..];
    let (wrapper_key_id, wrapper_payload_len, wrapper_sha, payload) =
        decode_image_wrapper(wrapper)?;

    if wrapper_key_id != manifest.key_id {
        err!("image wrapper key_id mismatch");
    }
    if wrapper_payload_len != manifest.payload_size {
        err!("image wrapper payload_len mismatch with manifest payload_size");
    }
    if wrapper_sha != manifest.payload_sha256 {
        err!("image wrapper payload sha256 mismatch with manifest");
    }
    if payload.len() as u64 != wrapper_payload_len {
        err!("image wrapper payload length mismatch");
    }

    verify_payload_chunks(payload, &manifest.payload_sha256, STAGING_CHUNK)?;

    Ok(VerifiedStream {
        manifest: manifest.clone(),
        image_header: header,
        payload_sha256: manifest.payload_sha256,
        payload_len: manifest.payload_size,
    })
}

/// Decode the manifest at offset 0 and return (manifest, consumed_bytes).
fn decode_manifest_prefix(data: &[u8]) -> Result<(Manifest, usize), Error> {
    let (_cbor, consumed) = decode_one(data)?;
    let bytes = &data[..consumed];
    decode_manifest(bytes).map(|m| (m, consumed))
}

/// Parse `u32le key_id || u32le payload_len || sha256(32) || payload`.
/// `(chunk_index, total_chunks, image_hash, chunk_bytes)` of one streamed
/// image wrapper.
pub type ImageWrapper<'a> = (u64, u64, [u8; 32], &'a [u8]);

pub fn decode_image_wrapper(wrapper: &[u8]) -> Result<ImageWrapper<'_>, Error> {
    if wrapper.len() < 8 + 32 {
        err!("image wrapper too short");
    }
    let key_id = u32::from_le_bytes(wrapper[0..4].try_into().unwrap()) as u64;
    let payload_len = u32::from_le_bytes(wrapper[4..8].try_into().unwrap()) as u64;
    let mut sha = [0u8; 32];
    sha.copy_from_slice(&wrapper[8..40]);
    let payload = &wrapper[40..];
    if payload.len() as u64 != payload_len {
        err!(
            "image wrapper payload_len {} != actual {}",
            payload_len,
            payload.len()
        );
    }
    Ok((key_id, payload_len, sha, payload))
}

/// Verify the full-image sha256 by iterating fixed chunks — the per-chunk
/// staging loop. Each chunk is individually hashed so a staged write can be
/// re-verified; the concatenated hash must equal `expected`.
pub fn verify_payload_chunks(
    payload: &[u8],
    expected: &[u8; 32],
    chunk_size: usize,
) -> Result<(), Error> {
    if chunk_size == 0 {
        err!("chunk size must be > 0");
    }
    let mut hasher = Sha256::new();
    let mut n = 0usize;
    while n < payload.len() {
        let end = (n + chunk_size).min(payload.len());
        let chunk = &payload[n..end];
        let mut chunk_hash = Sha256::new();
        chunk_hash.update(chunk);
        let _ = chunk_hash.finalize();
        hasher.update(chunk);
        n = end;
    }
    let digest: [u8; 32] = hasher.finalize().into();
    if digest != *expected {
        err!(
            "payload sha256 mismatch: computed {} expected {}",
            hex::encode(digest),
            hex::encode(expected)
        );
    }
    Ok(())
}
