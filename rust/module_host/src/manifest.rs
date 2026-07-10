//! Signed module packages: the trust layer of the update architecture.
//!
//! package = manifest || module_bytes
//! manifest (fixed order, little-endian):
//!   magic "ZIGM" | manifest_version:u8=1 | module_version:u32 |
//!   min_kernel_version:u32 | module_hash:[32] | desc_len:u8 | desc |
//!   sig_count:u8 | sig_count * ( key_index:u8 | sig:[64] )
//!
//! Signatures cover every manifest byte before sig_count over the
//! domain-separated message "zigner-module-v1" || fields. 2-of-3 of the
//! kernel-baked release keys must verify, each from a DISTINCT key.
//! module_hash must equal sha256(module_bytes). The kernel additionally
//! enforces module_version > last_installed (anti-rollback) - persisted
//! counter, outside this parser.

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};

pub const MAGIC: &[u8; 4] = b"ZIGM";
pub const DOMAIN: &[u8] = b"zigner-module-v1";
pub const REQUIRED_SIGS: usize = 2;

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
    Rollback { offered: u32, installed: u32 },
    KernelTooOld { required: u32, running: u32 },
}

pub struct VerifiedModule<'a> {
    pub module_version: u32,
    pub min_kernel_version: u32,
    pub description: String,
    pub module_bytes: &'a [u8],
}

/// Parse + fully verify a module package against the kernel's trust
/// anchors and state. Returns the module only if EVERY check passes.
pub fn verify_package<'a>(
    package: &'a [u8],
    release_keys: &[VerifyingKey; 3],
    kernel_version: u32,
    last_installed_version: u32,
) -> Result<VerifiedModule<'a>, ManifestError> {
    let take = |b: &'a [u8], n: usize| -> Result<(&'a [u8], &'a [u8]), ManifestError> {
        if b.len() < n {
            Err(ManifestError::Truncated)
        } else {
            Ok(b.split_at(n))
        }
    };

    let (magic, rest) = take(package, 4)?;
    if magic != MAGIC {
        return Err(ManifestError::BadMagic);
    }
    let (ver, rest) = take(rest, 1)?;
    if ver[0] != 1 {
        return Err(ManifestError::UnsupportedVersion(ver[0]));
    }
    let (mv, rest) = take(rest, 4)?;
    let module_version = u32::from_le_bytes(mv.try_into().unwrap());
    let (kv, rest) = take(rest, 4)?;
    let min_kernel_version = u32::from_le_bytes(kv.try_into().unwrap());
    let (hash, rest) = take(rest, 32)?;
    let (dl, rest) = take(rest, 1)?;
    let (desc, rest) = take(rest, dl[0] as usize)?;

    // signed region = everything up to here
    let signed_len = package.len() - rest.len();
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
        release_keys[idx]
            .verify(&msg, &signature)
            .map_err(|_| ManifestError::BadSignature(ki[0]))?;
        valid += 1;
    }
    if valid < REQUIRED_SIGS {
        return Err(ManifestError::NotEnoughSignatures(valid));
    }

    let module_bytes = rest;
    if <[u8; 32]>::from(Sha256::digest(module_bytes)) != *<&[u8; 32]>::try_from(hash).unwrap() {
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
        description: String::from_utf8_lossy(desc).into_owned(),
        module_bytes,
    })
}

/// Packaging helper (release tooling + tests): sign with the provided keys.
pub fn build_package(
    module_bytes: &[u8],
    module_version: u32,
    min_kernel_version: u32,
    description: &str,
    signers: &[(u8, ed25519_dalek::SigningKey)],
) -> Vec<u8> {
    use ed25519_dalek::Signer as _;
    let mut out = Vec::new();
    out.extend_from_slice(MAGIC);
    out.push(1);
    out.extend_from_slice(&module_version.to_le_bytes());
    out.extend_from_slice(&min_kernel_version.to_le_bytes());
    out.extend_from_slice(&Sha256::digest(module_bytes));
    out.push(description.len() as u8);
    out.extend_from_slice(description.as_bytes());
    let mut msg = Vec::from(DOMAIN);
    msg.extend_from_slice(&out);
    out.push(signers.len() as u8);
    for (idx, key) in signers {
        out.push(*idx);
        out.extend_from_slice(&key.sign(&msg).to_bytes());
    }
    out.extend_from_slice(module_bytes);
    out
}
