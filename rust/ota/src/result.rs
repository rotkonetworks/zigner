//! Device-signed result/status production (pure). The device signs with its
//! ZID identity key; the wallet verifies `*_sig` against the embedded
//! `zid_pubkey`.

use crate::types::{OtaResult, Status, TAG_RESULT, TAG_STATUS, result_signed_canonical,
    result_wire_canonical, status_signed_canonical, status_wire_canonical};
use crate::verifysig::sign;
use crate::Error;

/// Produce the canonical wire CBOR of `ur:zafu-result` (fields 1..6),
/// signing fields 1..5 with the ZID identity key under `\x00zafu/result/v1`.
///
/// `slot` must be `b'A'` or `b'B'`.
pub fn produce_result(
    fw_version: &str,
    success: bool,
    slot: u8,
    req_id: &[u8; 8],
    zid_secret_key: &[u8; 32],
) -> Result<Vec<u8>, Error> {
    if slot != b'A' && slot != b'B' {
        return Err(Error(format!(
            "slot must be 'A' or 'B', got {}",
            char::from(slot)
        )));
    }
    let zpk = zid_public_key(zid_secret_key);
    let r = OtaResult {
        fw_version: fw_version.to_string(),
        success,
        slot,
        req_id: *req_id,
        zid_pubkey: zpk,
        result_sig: [0u8; 64],
    };
    let canonical = result_signed_canonical(&r)?;
    let sig = sign(TAG_RESULT, &canonical, zid_secret_key)?;
    let mut full = r;
    full.result_sig = sig;
    result_wire_canonical(&full)
}

/// Produce the canonical wire CBOR of `ur:zafu-status` (fields 1..5),
/// signing fields 1..4 with the ZID identity key under `\x00zafu/status/v1`.
pub fn produce_status(
    fw_version: &str,
    slot: u8,
    successful_boot: bool,
    zid_secret_key: &[u8; 32],
) -> Result<Vec<u8>, Error> {
    if slot != b'A' && slot != b'B' {
        return Err(Error(format!(
            "slot must be 'A' or 'B', got {}",
            char::from(slot)
        )));
    }
    let zpk = zid_public_key(zid_secret_key);
    let s = Status {
        fw_version: fw_version.to_string(),
        slot,
        successful_boot,
        zid_pubkey: zpk,
        status_sig: [0u8; 64],
    };
    let canonical = status_signed_canonical(&s)?;
    let sig = sign(TAG_STATUS, &canonical, zid_secret_key)?;
    let mut full = s;
    full.status_sig = sig;
    status_wire_canonical(&full)
}

/// Public key (pq) corresponding to a 32-byte ZID secret key.
pub fn zid_public_key(secret_key: &[u8; 32]) -> [u8; 32] {
    let sk = ed25519_dalek::SigningKey::from_bytes(secret_key);
    sk.verifying_key().to_bytes()
}
