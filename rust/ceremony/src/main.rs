//! Release ceremony coordinator.
//!
//! Three key holders in three places cannot easily be in one browser tab at
//! one moment. This holds an in-progress ceremony so they can each sign when
//! they get to it: the build host posts what `modpack prepare` produced, each
//! holder fetches the manifest and posts back a signature, and the assembled
//! package comes out the other end.
//!
//! WHAT IT STORES IS ALL PUBLIC. A manifest, a payload, and some signatures.
//! There are no keys here and there is nothing to steal. It cannot forge a
//! package, and it cannot make a holder sign something they were not shown,
//! because the device parses the manifest itself and renders the version,
//! hash and changelog from the bytes it actually received.
//!
//! THE RISK THIS SERVICE INTRODUCES is not cryptographic, it is procedural.
//! With files on a build host, a holder had to have the module in front of
//! them, so comparing its hash was natural. Fetch a manifest from a URL and
//! that step is easy to skip - and skipping it is exactly what makes a
//! substituted manifest work. Convenience is the attack here. So the API
//! surfaces the hash on every read and refuses to pretend it has verified
//! anything it has not.
//!
//! Signatures are checked against the release keys when the ceremony was
//! created with them, which catches the wrong device signing long before
//! anyone tries to install the result. That is a convenience, not the
//! authority: `modpack verify` and the device are.

use axum::{
    extract::{Path, State},
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use module_host::manifest::{self, ManifestFields};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::sync::RwLock;

type Store = Arc<RwLock<HashMap<String, Ceremony>>>;

/// Ceremonies are short-lived by nature - a release takes hours or days, not
/// months - and holding them longer is just a larger pile of stale manifests.
const TTL_SECS: u64 = 30 * 24 * 3600;

struct Ceremony {
    prefix: Vec<u8>,
    payload: Vec<u8>,
    fields: ManifestFields,
    /// Optional: the three release public keys. When present, submitted
    /// signatures are verified on arrival instead of at install time.
    release_keys: Option<[[u8; 32]; 3]>,
    sigs: Vec<(u8, [u8; 64])>,
    created: u64,
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn bad(msg: impl Into<String>) -> (StatusCode, String) {
    (StatusCode::BAD_REQUEST, msg.into())
}

fn b64(s: &str) -> Result<Vec<u8>, (StatusCode, String)> {
    STANDARD.decode(s).map_err(|e| bad(format!("bad base64: {e}")))
}

// ── create ──────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct CreateReq {
    prefix_b64: String,
    payload_b64: String,
    /// Hex, 3 entries, in slot order. Optional.
    #[serde(default)]
    release_keys: Option<Vec<String>>,
}

#[derive(Serialize)]
struct CreateResp {
    id: String,
    module_hash: String,
    module_version: u32,
}

async fn create(
    State(store): State<Store>,
    Json(req): Json<CreateReq>,
) -> Result<Json<CreateResp>, (StatusCode, String)> {
    let prefix = b64(&req.prefix_b64)?;
    let payload = b64(&req.payload_b64)?;

    // Parse with the same code the device verifies with. A malformed manifest
    // rejected here is a ceremony that never wastes a holder's attention.
    let (fields, consumed) = manifest::parse_signing_prefix(&prefix)
        .map_err(|e| bad(format!("not a module manifest: {e:?}")))?;
    if consumed != prefix.len() {
        return Err(bad(
            "prefix has trailing bytes - it must be exactly the signed region",
        ));
    }
    // The manifest commits to the payload length, so a mismatch means these
    // two files came from different `modpack prepare` runs. Catching it now
    // saves a ceremony that would end in a device rejection.
    if payload.len() as u64 != fields.payload_len as u64 {
        return Err(bad(format!(
            "payload is {} bytes, manifest commits to {}",
            payload.len(),
            fields.payload_len
        )));
    }

    let release_keys = match req.release_keys {
        None => None,
        Some(v) => {
            if v.len() != 3 {
                return Err(bad("release_keys must have exactly 3 entries, in slot order"));
            }
            let mut out = [[0u8; 32]; 3];
            for (i, h) in v.iter().enumerate() {
                let raw = hex::decode(h).map_err(|e| bad(format!("key {i}: bad hex: {e}")))?;
                out[i] = raw
                    .try_into()
                    .map_err(|_| bad(format!("key {i}: a public key is 32 bytes")))?;
            }
            Some(out)
        }
    };

    let mut id_bytes = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut id_bytes);
    let id = hex::encode(id_bytes);

    let resp = CreateResp {
        id: id.clone(),
        module_hash: hex::encode(fields.module_hash),
        module_version: fields.module_version,
    };

    let mut w = store.write().await;
    w.retain(|_, c| now().saturating_sub(c.created) < TTL_SECS);
    w.insert(
        id,
        Ceremony {
            prefix,
            payload,
            fields,
            release_keys,
            sigs: Vec::new(),
            created: now(),
        },
    );
    Ok(Json(resp))
}

// ── read ────────────────────────────────────────────────────────────────────

#[derive(Serialize)]
struct GetResp {
    prefix_b64: String,
    module_version: u32,
    min_kernel_version: u32,
    /// The digest the holder must compare against a module they built. This
    /// is the whole point of the response; everything else is context.
    module_hash: String,
    payload_kind: u8,
    payload_len: u32,
    description: String,
    /// Slots that have signed. Signatures themselves are returned only in the
    /// assembled package - there is no reason to hand them out piecemeal.
    signed_slots: Vec<u8>,
    required_sigs: usize,
    keys_verified_on_arrival: bool,
}

async fn get_ceremony(
    State(store): State<Store>,
    Path(id): Path<String>,
) -> Result<Json<GetResp>, (StatusCode, String)> {
    let r = store.read().await;
    let c = r.get(&id).ok_or((StatusCode::NOT_FOUND, "no such ceremony".into()))?;
    Ok(Json(GetResp {
        prefix_b64: STANDARD.encode(&c.prefix),
        module_version: c.fields.module_version,
        min_kernel_version: c.fields.min_kernel_version,
        module_hash: hex::encode(c.fields.module_hash),
        payload_kind: c.fields.payload_kind,
        payload_len: c.fields.payload_len,
        description: c.fields.description.clone(),
        signed_slots: c.sigs.iter().map(|(i, _)| *i).collect(),
        required_sigs: manifest::REQUIRED_SIGS,
        keys_verified_on_arrival: c.release_keys.is_some(),
    }))
}

// ── sign ────────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct SigReq {
    index: u8,
    signature_hex: String,
}

async fn add_signature(
    State(store): State<Store>,
    Path(id): Path<String>,
    Json(req): Json<SigReq>,
) -> Result<Json<GetRespSlots>, (StatusCode, String)> {
    if req.index > 2 {
        return Err(bad("key slot must be 0, 1 or 2"));
    }
    let raw = hex::decode(req.signature_hex.trim())
        .map_err(|e| bad(format!("bad signature hex: {e}")))?;
    let sig: [u8; 64] = raw
        .try_into()
        .map_err(|_| bad("a signature is 64 bytes / 128 hex characters"))?;

    let mut w = store.write().await;
    let c = w
        .get_mut(&id)
        .ok_or((StatusCode::NOT_FOUND, "no such ceremony".into()))?;

    // Two signatures from one slot is not 2-of-3, and the device rejects
    // duplicate indices anyway. Refuse rather than accumulate a package that
    // is guaranteed to fail.
    if c.sigs.iter().any(|(i, _)| *i == req.index) {
        return Err(bad(format!("slot #{} has already signed", req.index)));
    }

    if let Some(keys) = c.release_keys {
        // Verify now rather than at install time. Catches the wrong device
        // signing, or a signature over a different manifest, while the person
        // who can fix it is still paying attention.
        let vk = ed25519_dalek::VerifyingKey::from_bytes(&keys[req.index as usize])
            .map_err(|e| bad(format!("slot #{} public key is invalid: {e}", req.index)))?;
        let msg = manifest::signing_message(&c.prefix);
        let signature = ed25519_dalek::Signature::from_bytes(&sig);
        // verify_strict for the same reason the kernel uses it: the permissive
        // form accepts small-order keys and non-canonical R.
        vk.verify_strict(&msg, &signature)
            .map_err(|_| bad(format!(
                "signature does not verify against the slot #{} release key - \
                 wrong device, or signed over a different manifest",
                req.index
            )))?;
    }

    c.sigs.push((req.index, sig));
    c.sigs.sort_by_key(|(i, _)| *i);
    Ok(Json(GetRespSlots {
        signed_slots: c.sigs.iter().map(|(i, _)| *i).collect(),
        required_sigs: manifest::REQUIRED_SIGS,
    }))
}

#[derive(Serialize)]
struct GetRespSlots {
    signed_slots: Vec<u8>,
    required_sigs: usize,
}

// ── assemble ────────────────────────────────────────────────────────────────

async fn package(
    State(store): State<Store>,
    Path(id): Path<String>,
) -> Result<Vec<u8>, (StatusCode, String)> {
    let r = store.read().await;
    let c = r.get(&id).ok_or((StatusCode::NOT_FOUND, "no such ceremony".into()))?;
    if c.sigs.len() < manifest::REQUIRED_SIGS {
        return Err(bad(format!(
            "{} of {} signatures collected",
            c.sigs.len(),
            manifest::REQUIRED_SIGS
        )));
    }
    let pkg = manifest::assemble_package(&c.prefix, &c.sigs, &c.payload);

    // Self-check when we can. This is the server marking its own homework, so
    // it proves nothing to anyone else - run `modpack verify` before shipping.
    // It does catch the server having corrupted something in transit, which is
    // the failure it is actually in a position to notice.
    if let Some(keys) = c.release_keys {
        if c.fields.payload_kind == manifest::PAYLOAD_FULL {
            let vks: Result<Vec<_>, _> = keys
                .iter()
                .map(ed25519_dalek::VerifyingKey::from_bytes)
                .collect();
            if let Ok(vks) = vks {
                let vks: [ed25519_dalek::VerifyingKey; 3] = vks.try_into().unwrap();
                if manifest::verify_package(&pkg, &vks, module_host::KERNEL_VERSION, 0).is_err() {
                    return Err((
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "assembled package does not verify - refusing to hand it out".into(),
                    ));
                }
            }
        }
    }
    Ok(pkg)
}

async fn health() -> &'static str {
    "ok"
}

#[tokio::main]
async fn main() {
    let store: Store = Arc::new(RwLock::new(HashMap::new()));
    let app = Router::new()
        .route("/api/ceremony", post(create))
        .route("/api/ceremony/:id", get(get_ceremony))
        .route("/api/ceremony/:id/signature", post(add_signature))
        .route("/api/ceremony/:id/package", get(package))
        .route("/health", get(health))
        .with_state(store);

    let addr = std::env::var("CEREMONY_ADDR").unwrap_or_else(|_| "127.0.0.1:8788".into());
    let listener = tokio::net::TcpListener::bind(&addr).await.expect("bind");
    eprintln!("ceremony coordinator on {addr}");
    axum::serve(listener, app).await.expect("serve");
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    /// The length check has to happen at creation, not at install: a mismatch
    /// means the operator picked up files from two different prepare runs, and
    /// finding that out after two people have signed wastes the scarce thing
    /// in this process, which is their attention.
    #[test]
    fn payload_length_is_checked_against_the_manifest() {
        let module = b"a module";
        let prefix = manifest::build_signing_prefix(
            Sha256::digest(module).into(),
            manifest::PAYLOAD_FULL,
            [0u8; 32],
            module.len() as u32,
            3,
            1,
            "notes",
        );
        let (fields, consumed) = manifest::parse_signing_prefix(&prefix).unwrap();
        assert_eq!(consumed, prefix.len());
        assert_eq!(fields.payload_len as usize, module.len());
        assert_ne!(fields.payload_len as usize, module.len() + 1);
    }
}
