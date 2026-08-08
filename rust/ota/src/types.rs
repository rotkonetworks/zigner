//! OTA domain types + canonical CBOR (de)serialization for each schema.
//!
//! Domain tags INCLUDE the leading 0x00 as part of the signed bytes
//! (freeze doc: "The 0x00 is part of the signed bytes").

use crate::{decode, encode, Cbor, Error};

/// Fail with a formatted crate error (internal helper).
macro_rules! err {
    ($($t:tt)*) => { return Err(Error(format!($($t)*))) };
}

/// Domain tag for signed manifests (includes leading 0x00).
pub const TAG_MANIFEST: &[u8] = b"\x00zafu/manifest/v1";
/// Domain tag for signed image headers.
pub const TAG_IMAGE: &[u8] = b"\x00zafu/image/v1";
/// Domain tag for signed results.
pub const TAG_RESULT: &[u8] = b"\x00zafu/result/v1";
/// Domain tag for signed status.
pub const TAG_STATUS: &[u8] = b"\x00zafu/status/v1";

/// Valid firmware classes.
pub const CLASS_RELEASE: &str = "release";
pub const CLASS_ROLLBACK: &str = "rollback";

/// Signed manifest (fields 1..7) plus optional frame[0] additions
/// (fields 8..9, un-signed).
#[derive(Debug, Clone, PartialEq)]
pub struct Manifest {
    pub version: String,
    pub board: String,
    pub payload_sha256: [u8; 32],
    pub payload_size: u64,
    pub min_version: String,
    pub key_id: u64,
    pub class: String,
    /// image_sig (field 8) — present on the wire frame[0], absent when
    /// parsing the signed 7-field set.
    pub image_sig: Option<[u8; 64]>,
    /// req_id (field 9) — present on the wire frame[0], absent when parsing
    /// the signed 7-field set.
    pub req_id: Option<[u8; 8]>,
}

/// Signed image header (fields 1..5).
#[derive(Debug, Clone, PartialEq)]
pub struct ImageHeader {
    pub key_id: u64,
    pub board: String,
    pub version: String,
    pub payload_sha256: [u8; 32],
    pub payload_len: u64,
}

/// Device→wallet result (fields 1..6). Signed set = 1..5.
#[derive(Debug, Clone, PartialEq)]
pub struct OtaResult {
    pub fw_version: String,
    pub success: bool,
    pub slot: u8, // b'A' | b'B'
    pub req_id: [u8; 8],
    pub zid_pubkey: [u8; 32],
    pub result_sig: [u8; 64],
}

/// Device→wallet status (fields 1..5). Signed set = 1..4.
#[derive(Debug, Clone, PartialEq)]
pub struct Status {
    pub fw_version: String,
    pub slot: u8,
    pub successful_boot: bool,
    pub zid_pubkey: [u8; 32],
    pub status_sig: [u8; 64],
}

fn arr32(b: &[u8]) -> Result<[u8; 32], Error> {
    let a: [u8; 32] = b
        .try_into()
        .map_err(|_| Error("expected 32-byte value".into()))?;
    Ok(a)
}
fn arr64(b: &[u8]) -> Result<[u8; 64], Error> {
    let a: [u8; 64] = b
        .try_into()
        .map_err(|_| Error("expected 64-byte value".into()))?;
    Ok(a)
}
fn arr8(b: &[u8]) -> Result<[u8; 8], Error> {
    let a: [u8; 8] = b
        .try_into()
        .map_err(|_| Error("expected 8-byte value".into()))?;
    Ok(a)
}

fn get<'a>(m: &'a [(u64, Cbor)], k: u64) -> Option<&'a Cbor> {
    m.iter().find(|(pk, _)| *pk == k).map(|(_, v)| v)
}

// ────────────────────────────────────────────────────────────────────────────
// Manifest
// ────────────────────────────────────────────────────────────────────────────

fn manifest_map_signed(m: &Manifest) -> Result<Cbor, Error> {
    Ok(Cbor::map()
        .insert(1, Cbor::Text(m.version.clone()))
        .insert(2, Cbor::Text(m.board.clone()))
        .insert(3, Cbor::Bytes(m.payload_sha256.to_vec()))
        .insert(4, Cbor::UInt(m.payload_size))
        .insert(5, Cbor::Text(m.min_version.clone()))
        .insert(6, Cbor::UInt(m.key_id))
        .insert(7, Cbor::Text(m.class.clone()))
        .build())
}

/// Canonical CBOR of the signed manifest field set (fields 1..7).
pub fn manifest_signed_canonical(m: &Manifest) -> Result<Vec<u8>, Error> {
    encode(&manifest_map_signed(m)?)
}

/// Canonical CBOR of the full wire frame[0] manifest (fields 1..9).
pub fn manifest_frame0_canonical(
    m: &Manifest,
    image_sig: &[u8; 64],
    req_id: &[u8; 8],
) -> Result<Vec<u8>, Error> {
    let c = Cbor::map()
        .insert(1, Cbor::Text(m.version.clone()))
        .insert(2, Cbor::Text(m.board.clone()))
        .insert(3, Cbor::Bytes(m.payload_sha256.to_vec()))
        .insert(4, Cbor::UInt(m.payload_size))
        .insert(5, Cbor::Text(m.min_version.clone()))
        .insert(6, Cbor::UInt(m.key_id))
        .insert(7, Cbor::Text(m.class.clone()))
        .insert(8, Cbor::Bytes(image_sig.to_vec()))
        .insert(9, Cbor::Bytes(req_id.to_vec()))
        .build();
    encode(&c)
}

/// Decode a manifest (accepts either the 7-field signed set or the 9-field
/// wire frame[0]). Strict canonical CBOR parsing.
pub fn decode_manifest(data: &[u8]) -> Result<Manifest, Error> {
    let c = decode(data)?;
    let m = match c {
        Cbor::Map(m) => m,
        _ => err!("manifest must be a CBOR map"),
    };
    let version = get(&m, 1)
        .and_then(|v| v.as_text())
        .ok_or(Error("manifest missing version".into()))?
        .to_string();
    let board = get(&m, 2)
        .and_then(|v| v.as_text())
        .ok_or(Error("manifest missing board".into()))?
        .to_string();
    let payload_sha256 = arr32(
        get(&m, 3)
            .and_then(|v| v.as_bytes())
            .ok_or(Error("manifest missing payload_sha256".into()))?,
    )?;
    let payload_size = get(&m, 4)
        .and_then(|v| v.as_uint())
        .ok_or(Error("manifest missing payload_size".into()))?;
    let min_version = get(&m, 5)
        .and_then(|v| v.as_text())
        .ok_or(Error("manifest missing min_version".into()))?
        .to_string();
    let key_id = get(&m, 6)
        .and_then(|v| v.as_uint())
        .ok_or(Error("manifest missing key_id".into()))?;
    let class = get(&m, 7)
        .and_then(|v| v.as_text())
        .ok_or(Error("manifest missing class".into()))?
        .to_string();
    let image_sig = match get(&m, 8) {
        Some(v) => Some(arr64(
            v.as_bytes()
                .ok_or(Error("manifest image_sig not bstr".into()))?,
        )?),
        None => None,
    };
    let req_id = match get(&m, 9) {
        Some(v) => Some(arr8(
            v.as_bytes()
                .ok_or(Error("manifest req_id not bstr".into()))?,
        )?),
        None => None,
    };
    Ok(Manifest {
        version,
        board,
        payload_sha256,
        payload_size,
        min_version,
        key_id,
        class,
        image_sig,
        req_id,
    })
}

// ────────────────────────────────────────────────────────────────────────────
// ImageHeader
// ────────────────────────────────────────────────────────────────────────────

fn image_map(h: &ImageHeader) -> Result<Cbor, Error> {
    Ok(Cbor::map()
        .insert(1, Cbor::UInt(h.key_id))
        .insert(2, Cbor::Text(h.board.clone()))
        .insert(3, Cbor::Text(h.version.clone()))
        .insert(4, Cbor::Bytes(h.payload_sha256.to_vec()))
        .insert(5, Cbor::UInt(h.payload_len))
        .build())
}

/// Canonical CBOR of the signed image header (fields 1..5).
pub fn image_canonical(h: &ImageHeader) -> Result<Vec<u8>, Error> {
    encode(&image_map(h)?)
}

/// Decode a signed image header from canonical CBOR.
pub fn decode_image_header(data: &[u8]) -> Result<ImageHeader, Error> {
    let c = decode(data)?;
    let m = match c {
        Cbor::Map(m) => m,
        _ => err!("image header must be a CBOR map"),
    };
    let key_id = get(&m, 1)
        .and_then(|v| v.as_uint())
        .ok_or(Error("image missing key_id".into()))?;
    let board = get(&m, 2)
        .and_then(|v| v.as_text())
        .ok_or(Error("image missing board".into()))?
        .to_string();
    let version = get(&m, 3)
        .and_then(|v| v.as_text())
        .ok_or(Error("image missing version".into()))?
        .to_string();
    let payload_sha256 = arr32(
        get(&m, 4)
            .and_then(|v| v.as_bytes())
            .ok_or(Error("image missing payload_sha256".into()))?,
    )?;
    let payload_len = get(&m, 5)
        .and_then(|v| v.as_uint())
        .ok_or(Error("image missing payload_len".into()))?;
    Ok(ImageHeader {
        key_id,
        board,
        version,
        payload_sha256,
        payload_len,
    })
}

// ────────────────────────────────────────────────────────────────────────────
// Result
// ────────────────────────────────────────────────────────────────────────────

fn result_map_signed(r: &OtaResult) -> Result<Cbor, Error> {
    Ok(Cbor::map()
        .insert(1, Cbor::Text(r.fw_version.clone()))
        .insert(2, Cbor::Bool(r.success))
        .insert(3, Cbor::Text(String::from(char::from(r.slot))))
        .insert(4, Cbor::Bytes(r.req_id.to_vec()))
        .insert(5, Cbor::Bytes(r.zid_pubkey.to_vec()))
        .build())
}

/// Canonical CBOR of the signed result field set (fields 1..5).
pub fn result_signed_canonical(r: &OtaResult) -> Result<Vec<u8>, Error> {
    encode(&result_map_signed(r)?)
}

/// Canonical CBOR of the full wire result map (fields 1..6).
pub fn result_wire_canonical(r: &OtaResult) -> Result<Vec<u8>, Error> {
    let c = Cbor::map()
        .insert(1, Cbor::Text(r.fw_version.clone()))
        .insert(2, Cbor::Bool(r.success))
        .insert(3, Cbor::Text(String::from(char::from(r.slot))))
        .insert(4, Cbor::Bytes(r.req_id.to_vec()))
        .insert(5, Cbor::Bytes(r.zid_pubkey.to_vec()))
        .insert(6, Cbor::Bytes(r.result_sig.to_vec()))
        .build();
    encode(&c)
}

/// Decode a wire result (fields 1..6).
pub fn decode_result(data: &[u8]) -> Result<OtaResult, Error> {
    let c = decode(data)?;
    let m = match c {
        Cbor::Map(m) => m,
        _ => err!("result must be a CBOR map"),
    };
    let fw_version = get(&m, 1)
        .and_then(|v| v.as_text())
        .ok_or(Error("result missing fw_version".into()))?
        .to_string();
    let success = get(&m, 2)
        .and_then(|v| v.as_bool())
        .ok_or(Error("result missing success".into()))?;
    let slots = get(&m, 3)
        .and_then(|v| v.as_text())
        .ok_or(Error("result missing slot".into()))?;
    if slots.len() != 1 {
        err!("result slot must be a single character");
    }
    let slot = slots.as_bytes()[0];
    if slot != b'A' && slot != b'B' {
        err!("result slot must be 'A' or 'B'");
    }
    let req_id = arr8(
        get(&m, 4)
            .and_then(|v| v.as_bytes())
            .ok_or(Error("result missing req_id".into()))?,
    )?;
    let zid_pubkey = arr32(
        get(&m, 5)
            .and_then(|v| v.as_bytes())
            .ok_or(Error("result missing zid_pubkey".into()))?,
    )?;
    let result_sig = arr64(
        get(&m, 6)
            .and_then(|v| v.as_bytes())
            .ok_or(Error("result missing result_sig".into()))?,
    )?;
    Ok(OtaResult {
        fw_version,
        success,
        slot,
        req_id,
        zid_pubkey,
        result_sig,
    })
}

// ────────────────────────────────────────────────────────────────────────────
// Status
// ────────────────────────────────────────────────────────────────────────────

fn status_map_signed(s: &Status) -> Result<Cbor, Error> {
    Ok(Cbor::map()
        .insert(1, Cbor::Text(s.fw_version.clone()))
        .insert(2, Cbor::Text(String::from(char::from(s.slot))))
        .insert(3, Cbor::Bool(s.successful_boot))
        .insert(4, Cbor::Bytes(s.zid_pubkey.to_vec()))
        .build())
}

/// Canonical CBOR of the signed status field set (fields 1..4).
pub fn status_signed_canonical(s: &Status) -> Result<Vec<u8>, Error> {
    encode(&status_map_signed(s)?)
}

/// Canonical CBOR of the full wire status map (fields 1..5).
pub fn status_wire_canonical(s: &Status) -> Result<Vec<u8>, Error> {
    let c = Cbor::map()
        .insert(1, Cbor::Text(s.fw_version.clone()))
        .insert(2, Cbor::Text(String::from(char::from(s.slot))))
        .insert(3, Cbor::Bool(s.successful_boot))
        .insert(4, Cbor::Bytes(s.zid_pubkey.to_vec()))
        .insert(5, Cbor::Bytes(s.status_sig.to_vec()))
        .build();
    encode(&c)
}

/// Decode a wire status (fields 1..5).
pub fn decode_status(data: &[u8]) -> Result<Status, Error> {
    let c = decode(data)?;
    let m = match c {
        Cbor::Map(m) => m,
        _ => err!("status must be a CBOR map"),
    };
    let fw_version = get(&m, 1)
        .and_then(|v| v.as_text())
        .ok_or(Error("status missing fw_version".into()))?
        .to_string();
    let slots = get(&m, 2)
        .and_then(|v| v.as_text())
        .ok_or(Error("status missing slot".into()))?;
    if slots.len() != 1 {
        err!("status slot must be a single character");
    }
    let slot = slots.as_bytes()[0];
    if slot != b'A' && slot != b'B' {
        err!("status slot must be 'A' or 'B'");
    }
    let successful_boot = get(&m, 3)
        .and_then(|v| v.as_bool())
        .ok_or(Error("status missing successful_boot".into()))?;
    let zid_pubkey = arr32(
        get(&m, 4)
            .and_then(|v| v.as_bytes())
            .ok_or(Error("status missing zid_pubkey".into()))?,
    )?;
    let status_sig = arr64(
        get(&m, 5)
            .and_then(|v| v.as_bytes())
            .ok_or(Error("status missing status_sig".into()))?,
    )?;
    Ok(Status {
        fw_version,
        slot,
        successful_boot,
        zid_pubkey,
        status_sig,
    })
}
