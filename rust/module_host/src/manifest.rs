//! Signed module packages: the trust layer of the update architecture.
//!
//! package = manifest || module_bytes
//! manifest (fixed order, little-endian):
//!   magic "ZIGM" | manifest_version:u8=1 | module_version:u32 |
//!   min_kernel_version:u32 | module_hash:[32] | payload_kind:u8 |
//!   base_hash:[32] | desc_len:u16 | desc |
//!   sig_count:u8 | sig_count * ( key_index:u8 | sig:[64] )
//!
//! `module_hash` is always the sha256 of the RESULTING module. For
//! payload_kind FULL the payload is that module verbatim. For a patch the
//! payload is a delta and `base_hash` names the module it applies to - full
//! modules are ~2.7 MB and take ~36 minutes over QR at the default playback
//! speed, where a measured delta is tens of KB and takes seconds.
//!
//! Signatures cover every manifest byte before sig_count over the
//! domain-separated message "zigner-module-v1" || fields. 2-of-3 of the
//! kernel-baked release keys must verify, each from a DISTINCT key.
//! module_hash must equal sha256(module_bytes). The kernel additionally
//! enforces module_version > last_installed (anti-rollback) - persisted
//! counter, outside this parser.

use ed25519_dalek::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};

pub const MAGIC: &[u8; 4] = b"ZIGM";
pub const DOMAIN: &[u8] = b"zigner-module-v1";
pub const REQUIRED_SIGS: usize = 2;

/// Wire format version. v1 never shipped - no package could ever verify,
/// because the release keys are still placeholders - so v2 replaces it
/// outright rather than being accepted alongside it.
pub const MANIFEST_VERSION: u8 = 2;

/// Payload is the complete module.
pub const PAYLOAD_FULL: u8 = 0;
/// Payload is a bsdiff delta against `base_hash`, zstd-compressed.
///
/// bsdiff+zstd rather than `zstd --patch-from`: measured on a real module
/// pair it is smaller (33,723 vs 42,839 bytes) AND applies with pure-Rust
/// crates, where zstd's prefix-dictionary path needs the C library.
pub const PAYLOAD_BSDIFF_ZSTD: u8 = 1;

#[derive(Debug)]
pub enum ManifestError {
    Truncated,
    BadMagic,
    UnsupportedVersion(u8),
    HashMismatch,
    DuplicateKey(u8),
    UnknownKey(u8),
    BadSignature(u8),
    NotEnoughSignatures(usize),
    Rollback {
        offered: u32,
        installed: u32,
    },
    KernelTooOld {
        required: u32,
        running: u32,
    },
    UnknownPayloadKind(u8),
    /// A patch package was offered but no base module was supplied.
    MissingBaseModule,
    /// The supplied base is not the one this patch was built against.
    BaseHashMismatch,
    /// The delta did not apply, decompress, or stayed within its size bound.
    PatchFailed,
}

pub struct VerifiedModule<'a> {
    pub module_version: u32,
    pub min_kernel_version: u32,
    pub description: String,
    /// Borrowed for a full payload, owned when produced by applying a patch.
    pub module_bytes: std::borrow::Cow<'a, [u8]>,
}

/// The fields of a manifest's signed region.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestFields {
    pub module_version: u32,
    pub min_kernel_version: u32,
    /// sha256 of the resulting module, whether shipped whole or patched.
    pub module_hash: [u8; 32],
    pub payload_kind: u8,
    /// The module a patch applies to; all-zero for a full payload.
    pub base_hash: [u8; 32],
    pub description: String,
}

/// Parse the signed region of a manifest, returning its fields and its exact
/// length in bytes - the region the release signatures cover.
///
/// Shared by the verifier and by the offline signing flow, deliberately: a
/// signer that parsed this format separately from the verifier would be one
/// refactor away from displaying different fields than the ones it signs.
pub fn parse_signing_prefix(data: &[u8]) -> Result<(ManifestFields, usize), ManifestError> {
    let take = |b: &[u8], n: usize| -> Result<(usize, usize), ManifestError> {
        if b.len() < n {
            Err(ManifestError::Truncated)
        } else {
            Ok((n, b.len() - n))
        }
    };
    let mut at = 0usize;
    let mut need = |n: usize| -> Result<std::ops::Range<usize>, ManifestError> {
        let _ = take(&data[at.min(data.len())..], n)?;
        let r = at..at + n;
        at += n;
        Ok(r)
    };

    if data[need(4)?] != *MAGIC {
        return Err(ManifestError::BadMagic);
    }
    let v = data[need(1)?][0];
    if v != MANIFEST_VERSION {
        return Err(ManifestError::UnsupportedVersion(v));
    }
    let module_version = u32::from_le_bytes(data[need(4)?].try_into().unwrap());
    let min_kernel_version = u32::from_le_bytes(data[need(4)?].try_into().unwrap());
    let module_hash: [u8; 32] = data[need(32)?].try_into().unwrap();
    let payload_kind = data[need(1)?][0];
    if !matches!(payload_kind, PAYLOAD_FULL | PAYLOAD_BSDIFF_ZSTD) {
        return Err(ManifestError::UnknownPayloadKind(payload_kind));
    }
    let base_hash: [u8; 32] = data[need(32)?].try_into().unwrap();
    let desc_len = u16::from_le_bytes(data[need(2)?].try_into().unwrap()) as usize;
    let desc = data[need(desc_len)?].to_vec();

    Ok((
        ManifestFields {
            module_version,
            min_kernel_version,
            module_hash,
            payload_kind,
            base_hash,
            description: String::from_utf8_lossy(&desc).into_owned(),
        },
        at,
    ))
}

/// Verify a full-payload package. Patch packages need [`verify_package_with_base`].
pub fn verify_package<'a>(
    package: &'a [u8],
    release_keys: &[VerifyingKey; 3],
    kernel_version: u32,
    last_installed_version: u32,
) -> Result<VerifiedModule<'a>, ManifestError> {
    verify_package_with_base(
        package,
        release_keys,
        kernel_version,
        last_installed_version,
        None,
    )
}

/// Parse + fully verify a module package against the kernel's trust
/// anchors and state. Returns the module only if EVERY check passes.
///
/// `base` is the currently-installed module, required only when the package
/// carries a patch. The patch itself needs no trust: the signatures cover the
/// RESULT hash, so a hostile or corrupt delta fails the final hash check.
pub fn verify_package_with_base<'a>(
    package: &'a [u8],
    release_keys: &[VerifyingKey; 3],
    kernel_version: u32,
    last_installed_version: u32,
    base: Option<&[u8]>,
) -> Result<VerifiedModule<'a>, ManifestError> {
    let take = |b: &'a [u8], n: usize| -> Result<(&'a [u8], &'a [u8]), ManifestError> {
        if b.len() < n {
            Err(ManifestError::Truncated)
        } else {
            Ok(b.split_at(n))
        }
    };

    let (fields, signed_len) = parse_signing_prefix(package)?;
    let module_version = fields.module_version;
    let min_kernel_version = fields.min_kernel_version;
    let hash = fields.module_hash;
    let rest = &package[signed_len..];

    let mut msg = Vec::with_capacity(DOMAIN.len() + signed_len);
    msg.extend_from_slice(DOMAIN);
    msg.extend_from_slice(&package[..signed_len]);

    let (sc, mut rest) = take(rest, 1)?;
    let mut seen = [false; 3];
    let mut valid = 0usize;
    for _ in 0..sc[0] {
        let (ki, r) = take(rest, 1)?;
        let (sig, r) = take(r, 64)?;
        rest = r;
        let idx = ki[0] as usize;
        if idx >= 3 {
            return Err(ManifestError::UnknownKey(ki[0]));
        }
        if seen[idx] {
            return Err(ManifestError::DuplicateKey(ki[0]));
        }
        seen[idx] = true;
        let signature = Signature::from_bytes(sig.try_into().unwrap());
        // verify_strict, not verify: the permissive form accepts small-order
        // public keys and non-canonical R, both of which admit forgeries. This
        // is a trust anchor, so take the strict equation.
        release_keys[idx]
            .verify_strict(&msg, &signature)
            .map_err(|_| ManifestError::BadSignature(ki[0]))?;
        valid += 1;
    }
    if valid < REQUIRED_SIGS {
        return Err(ManifestError::NotEnoughSignatures(valid));
    }

    // Resolve the payload into the actual module before any hash check.
    let module_bytes: std::borrow::Cow<'a, [u8]> = match fields.payload_kind {
        PAYLOAD_FULL => {
            // An unused base_hash must be zero, so there is exactly one
            // encoding of a full package and no room for a second reading.
            if fields.base_hash != [0u8; 32] {
                return Err(ManifestError::BaseHashMismatch);
            }
            std::borrow::Cow::Borrowed(rest)
        }
        PAYLOAD_BSDIFF_ZSTD => {
            let base = base.ok_or(ManifestError::MissingBaseModule)?;
            if <[u8; 32]>::from(Sha256::digest(base)) != fields.base_hash {
                return Err(ManifestError::BaseHashMismatch);
            }
            std::borrow::Cow::Owned(apply_patch(base, rest)?)
        }
        other => return Err(ManifestError::UnknownPayloadKind(other)),
    };
    if <[u8; 32]>::from(Sha256::digest(module_bytes.as_ref())) != hash {
        return Err(ManifestError::HashMismatch);
    }
    if module_version <= last_installed_version {
        return Err(ManifestError::Rollback {
            offered: module_version,
            installed: last_installed_version,
        });
    }
    if min_kernel_version > kernel_version {
        return Err(ManifestError::KernelTooOld {
            required: min_kernel_version,
            running: kernel_version,
        });
    }

    Ok(VerifiedModule {
        module_version,
        min_kernel_version,
        description: fields.description,
        module_bytes,
    })
}

/// Largest module we will reconstruct from a delta.
///
/// This bound is load-bearing, not hygiene. The signatures cover the manifest
/// - and therefore the RESULT hash - but NOT the payload bytes. So a valid
/// signed manifest can be paired with a swapped payload, and the mismatch is
/// only caught by the hash check at the end. Without a cap, a decompression
/// bomb would be expanded in full before we ever got there.
pub const MAX_MODULE_BYTES: usize = 16 * 1024 * 1024;

/// Reconstruct a module from `base` plus a zstd-compressed bsdiff delta.
///
/// Measured on a real module pair: 33,723 bytes against 2.0 MB for the whole
/// module - seconds of QR scanning instead of half an hour.
///
/// The `take` is the bomb defence: decompression stops at the cap rather than
/// running to completion, so a swapped payload costs bounded work and then
/// fails, instead of expanding without limit before the hash check catches it.
fn apply_patch(base: &[u8], patch: &[u8]) -> Result<Vec<u8>, ManifestError> {
    use std::io::Read;
    let decoder = ruzstd::StreamingDecoder::new(patch).map_err(|_| ManifestError::PatchFailed)?;
    let mut raw = Vec::new();
    decoder
        .take(MAX_MODULE_BYTES as u64)
        .read_to_end(&mut raw)
        .map_err(|_| ManifestError::PatchFailed)?;
    let mut out = Vec::new();
    bsdiff::patch(base, &mut raw.as_slice(), &mut out).map_err(|_| ManifestError::PatchFailed)?;
    // Belt to the take's braces: bsdiff output should be bounded by the patch
    // it was read from, but that is a property of the format rather than
    // something enforced above, so check it rather than assume it.
    if out.len() > MAX_MODULE_BYTES {
        return Err(ManifestError::PatchFailed);
    }
    Ok(out)
}

/// Packaging helper (release tooling + tests): sign with the provided keys.
pub fn build_package(
    payload: &[u8],
    module_hash: [u8; 32],
    payload_kind: u8,
    base_hash: [u8; 32],
    module_version: u32,
    min_kernel_version: u32,
    description: &str,
    signers: &[(u8, ed25519_dalek::SigningKey)],
) -> Vec<u8> {
    use ed25519_dalek::Signer as _;
    let mut out = Vec::new();
    out.extend_from_slice(MAGIC);
    out.push(MANIFEST_VERSION);
    out.extend_from_slice(&module_version.to_le_bytes());
    out.extend_from_slice(&min_kernel_version.to_le_bytes());
    out.extend_from_slice(&module_hash);
    out.push(payload_kind);
    out.extend_from_slice(&base_hash);
    // u16 length: the description carries the human-readable changelog the
    // device shows on the confirm screen, and it is INSIDE the signed bytes -
    // so what the user reads is what the release keys attested to. A u8 would
    // cap that at 255 bytes (one sentence) and, worse, `as u8` silently wrapped
    // for anything longer, producing a package that misparses.
    assert!(
        description.len() <= u16::MAX as usize,
        "module description too long: {} bytes (max {})",
        description.len(),
        u16::MAX
    );
    out.extend_from_slice(&(description.len() as u16).to_le_bytes());
    out.extend_from_slice(description.as_bytes());
    let mut msg = Vec::from(DOMAIN);
    msg.extend_from_slice(&out);
    out.push(signers.len() as u8);
    for (idx, key) in signers {
        out.push(*idx);
        out.extend_from_slice(&key.sign(&msg).to_bytes());
    }
    out.extend_from_slice(payload);
    out
}

/// Convenience for the common case: a complete module, no patch.
pub fn build_full_package(
    module_bytes: &[u8],
    module_version: u32,
    min_kernel_version: u32,
    description: &str,
    signers: &[(u8, ed25519_dalek::SigningKey)],
) -> Vec<u8> {
    build_package(
        module_bytes,
        Sha256::digest(module_bytes).into(),
        PAYLOAD_FULL,
        [0u8; 32],
        module_version,
        min_kernel_version,
        description,
        signers,
    )
}
