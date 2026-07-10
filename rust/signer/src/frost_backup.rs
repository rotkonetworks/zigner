//! FROST multisig wallet backup — encrypted JSON envelope, format-compatible
//! with zafu's `@repo/encryption` Box/KeyPrint primitives.
//!
//! Crypto:
//!   - Key derivation: PBKDF2-HMAC-SHA512, 210,000 iterations, 16-byte salt
//!     → 32-byte key (AES-GCM-256). Matches zafu's `keyStretchingHash`.
//!   - KeyPrint hash: SHA-256(derived_key). Constant-time compared on import
//!     to fail fast on wrong passphrase before AES-GCM auth tag.
//!   - Envelope encryption: AES-GCM-256, 12-byte random nonce, ciphertext
//!     includes the auth tag.
//!
//! Wire format (JSON, identical on zafu and zigner):
//!
//!   { "version": 1,
//!     "type": "frost-share-backup",
//!     "label": "treasury",
//!     "publicKeyPackage": "<hex>",
//!     "exportedAt": <ms unix>,
//!     "keyPrint": { "hash": "<base64>", "salt": "<base64>" },
//!     "box": { "nonce": "<base64>", "cipherText": "<base64>" } }
//!
//! Plaintext payload (inside the box):
//!
//!   { "version": 1,
//!     "type": "frost-share",
//!     "label", "publicKeyPackage", "keyPackage", "ephemeralSeed",
//!     "threshold", "maxSigners", "mainnet",
//!     "orchardFvk"?, "address"?, "relayUrl"?,
//!     "createdAt" }

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::Engine as _;
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const PBKDF2_ITERATIONS: u32 = 210_000;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;
const KEY_LEN: usize = 32;

#[derive(Serialize, Deserialize)]
struct KeyPrintJson {
    hash: String,
    salt: String,
}

#[derive(Serialize, Deserialize)]
struct BoxJson {
    nonce: String,
    #[serde(rename = "cipherText")]
    cipher_text: String,
}

#[derive(Serialize, Deserialize)]
struct Envelope {
    version: u32,
    #[serde(rename = "type")]
    kind: String,
    label: String,
    #[serde(rename = "publicKeyPackage", skip_serializing_if = "Option::is_none")]
    public_key_package: Option<String>,
    #[serde(rename = "exportedAt")]
    exported_at: u64,
    #[serde(rename = "keyPrint")]
    key_print: KeyPrintJson,
    #[serde(rename = "box")]
    bx: BoxJson,
}

#[derive(Serialize, Deserialize)]
pub struct PlaintextPayload {
    pub version: u32,
    #[serde(rename = "type")]
    pub kind: String,
    pub label: String,
    #[serde(rename = "publicKeyPackage")]
    pub public_key_package: String,
    #[serde(rename = "keyPackage")]
    pub key_package: String,
    #[serde(rename = "ephemeralSeed")]
    pub ephemeral_seed: String,
    pub threshold: u16,
    #[serde(rename = "maxSigners")]
    pub max_signers: u16,
    pub mainnet: bool,
    #[serde(
        rename = "orchardFvk",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub orchard_fvk: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    #[serde(rename = "relayUrl", default, skip_serializing_if = "Option::is_none")]
    pub relay_url: Option<String>,
    #[serde(rename = "createdAt")]
    pub created_at: u64,
}

fn b64() -> base64::engine::GeneralPurpose {
    base64::engine::general_purpose::STANDARD
}

fn derive_key(passphrase: &str, salt: &[u8]) -> [u8; KEY_LEN] {
    let mut key = [0u8; KEY_LEN];
    pbkdf2::pbkdf2_hmac::<sha2::Sha512>(passphrase.as_bytes(), salt, PBKDF2_ITERATIONS, &mut key);
    key
}

/// Generic seal: encrypt arbitrary plaintext bytes under a passphrase and
/// wrap them in the standard envelope. `kind` distinguishes single vs batch
/// (e.g. "frost-share-backup" vs "frost-share-batch-backup").
pub fn seal_envelope_bytes(
    plaintext: &[u8],
    passphrase: &str,
    kind: &str,
    label: &str,
    public_key_package: Option<&str>,
) -> Result<String, String> {
    let mut salt = [0u8; SALT_LEN];
    let mut nonce_bytes = [0u8; NONCE_LEN];
    // OsRng pulls directly from /dev/urandom (or platform equivalent) — best
    // practice for cold signing key material. thread_rng is a CSPRNG too in
    // current rand, but OsRng removes any concern about state reuse across
    // the thread's lifetime.
    OsRng.fill_bytes(&mut salt);
    OsRng.fill_bytes(&mut nonce_bytes);

    let key = derive_key(passphrase, &salt);
    let cipher = Aes256Gcm::new(&key.into());
    let cipher_text = cipher
        .encrypt(Nonce::from_slice(&nonce_bytes), plaintext)
        .map_err(|e| format!("aes-gcm seal: {e}"))?;

    let key_hash = Sha256::digest(key);

    let envelope = Envelope {
        version: 1,
        kind: kind.to_string(),
        label: label.to_string(),
        public_key_package: public_key_package.map(|s| s.to_string()),
        exported_at: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0),
        key_print: KeyPrintJson {
            hash: b64().encode(key_hash),
            salt: b64().encode(salt),
        },
        bx: BoxJson {
            nonce: b64().encode(nonce_bytes),
            cipher_text: b64().encode(&cipher_text),
        },
    };

    serde_json::to_string(&envelope).map_err(|e| format!("serialize envelope: {e}"))
}

/// Generic open: decrypt the envelope and return (kind, plaintext_bytes).
/// Caller parses plaintext as the matching shape.
pub fn open_envelope_bytes(
    envelope_json: &str,
    passphrase: &str,
) -> Result<(String, Vec<u8>), String> {
    let envelope: Envelope =
        serde_json::from_str(envelope_json).map_err(|e| format!("parse envelope: {e}"))?;

    if envelope.version != 1 {
        return Err(format!("unsupported envelope version {}", envelope.version));
    }

    let salt = b64()
        .decode(&envelope.key_print.salt)
        .map_err(|e| format!("decode salt: {e}"))?;
    let expected_hash = b64()
        .decode(&envelope.key_print.hash)
        .map_err(|e| format!("decode keyprint hash: {e}"))?;
    let nonce_bytes = b64()
        .decode(&envelope.bx.nonce)
        .map_err(|e| format!("decode nonce: {e}"))?;
    let cipher_text = b64()
        .decode(&envelope.bx.cipher_text)
        .map_err(|e| format!("decode ciphertext: {e}"))?;

    let key = derive_key(passphrase, &salt);
    let key_hash = Sha256::digest(key);
    if !constant_time_eq(&key_hash, &expected_hash) {
        return Err("wrong passphrase".to_string());
    }

    let cipher = Aes256Gcm::new(&key.into());
    let plaintext = cipher
        .decrypt(
            Nonce::from_slice(nonce_bytes.as_slice()),
            cipher_text.as_slice(),
        )
        .map_err(|_| "wrong passphrase or corrupted backup".to_string())?;

    Ok((envelope.kind, plaintext))
}

/// Seal a single FROST share. Thin wrapper over `seal_envelope_bytes`.
pub fn seal_envelope(payload: &PlaintextPayload, passphrase: &str) -> Result<String, String> {
    let bytes = serde_json::to_vec(payload).map_err(|e| format!("serialize payload: {e}"))?;
    seal_envelope_bytes(
        &bytes,
        passphrase,
        "frost-share-backup",
        &payload.label,
        Some(&payload.public_key_package),
    )
}

/// Open a single-share envelope. Errors if the envelope is a batch backup.
pub fn open_envelope(envelope_json: &str, passphrase: &str) -> Result<PlaintextPayload, String> {
    let (kind, bytes) = open_envelope_bytes(envelope_json, passphrase)?;
    if kind != "frost-share-backup" {
        return Err(format!("expected frost-share-backup, got '{kind}'"));
    }
    let payload: PlaintextPayload =
        serde_json::from_slice(&bytes).map_err(|e| format!("parse payload: {e}"))?;
    if payload.version != 1 || payload.kind != "frost-share" {
        return Err("unsupported plaintext payload format".to_string());
    }
    Ok(payload)
}

/// Plaintext for a batch backup. `shares` reuses the single-share fields
/// minus `version`/`type` (those live on the parent payload).
#[derive(Serialize, Deserialize)]
pub struct PlaintextBatch {
    pub version: u32,
    #[serde(rename = "type")]
    pub kind: String,
    pub shares: Vec<ShareEntry>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ShareEntry {
    pub label: String,
    #[serde(rename = "publicKeyPackage")]
    pub public_key_package: String,
    #[serde(rename = "keyPackage")]
    pub key_package: String,
    #[serde(rename = "ephemeralSeed")]
    pub ephemeral_seed: String,
    pub threshold: u16,
    #[serde(rename = "maxSigners")]
    pub max_signers: u16,
    pub mainnet: bool,
    #[serde(
        rename = "orchardFvk",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub orchard_fvk: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    #[serde(rename = "relayUrl", default, skip_serializing_if = "Option::is_none")]
    pub relay_url: Option<String>,
    #[serde(rename = "createdAt")]
    pub created_at: u64,
}

/// Seal a batch of FROST shares into one envelope.
pub fn seal_batch_envelope(shares: &[ShareEntry], passphrase: &str) -> Result<String, String> {
    let payload = PlaintextBatch {
        version: 1,
        kind: "frost-share-batch".into(),
        shares: shares.to_vec(),
    };
    let bytes = serde_json::to_vec(&payload).map_err(|e| format!("serialize batch: {e}"))?;
    let label = format!(
        "{} multisig wallet{}",
        shares.len(),
        if shares.len() == 1 { "" } else { "s" }
    );
    seal_envelope_bytes(&bytes, passphrase, "frost-share-batch-backup", &label, None)
}

/// Open a batch envelope, returning the share list. Errors if the envelope
/// is a single-share backup.
pub fn open_batch_envelope(
    envelope_json: &str,
    passphrase: &str,
) -> Result<Vec<ShareEntry>, String> {
    let (kind, bytes) = open_envelope_bytes(envelope_json, passphrase)?;
    if kind != "frost-share-batch-backup" {
        return Err(format!("expected frost-share-batch-backup, got '{kind}'"));
    }
    let payload: PlaintextBatch =
        serde_json::from_slice(&bytes).map_err(|e| format!("parse batch payload: {e}"))?;
    if payload.version != 1 || payload.kind != "frost-share-batch" {
        return Err("unsupported plaintext batch format".to_string());
    }
    Ok(payload.shares)
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_payload() -> PlaintextPayload {
        PlaintextPayload {
            version: 1,
            kind: "frost-share".into(),
            label: "treasury".into(),
            public_key_package: "ccdd".into(),
            key_package: "aabb".into(),
            ephemeral_seed: "eeff".into(),
            threshold: 2,
            max_signers: 3,
            mainnet: true,
            orchard_fvk: None,
            address: None,
            relay_url: None,
            created_at: 1700000000,
        }
    }

    #[test]
    fn round_trip() {
        let env = seal_envelope(&fixture_payload(), "correct horse battery staple").unwrap();
        let opened = open_envelope(&env, "correct horse battery staple").unwrap();
        assert_eq!(opened.label, "treasury");
        assert_eq!(opened.threshold, 2);
        assert_eq!(opened.key_package, "aabb");
    }

    #[test]
    fn wrong_passphrase_rejected() {
        let env = seal_envelope(&fixture_payload(), "right pass").unwrap();
        let result = open_envelope(&env, "wrong pass");
        assert!(result.is_err());
    }

    #[test]
    fn tampered_ciphertext_rejected() {
        let env = seal_envelope(&fixture_payload(), "p").unwrap();
        // flip one base64 char inside cipherText to corrupt the ciphertext
        let tampered = env.replacen("cipherText\":\"", "cipherText\":\"A", 1);
        let result = open_envelope(&tampered, "p");
        assert!(result.is_err());
    }

    fn fixture_share(suffix: &str) -> ShareEntry {
        ShareEntry {
            label: format!("wallet-{suffix}"),
            public_key_package: format!("ccdd{suffix}"),
            key_package: format!("aabb{suffix}"),
            ephemeral_seed: format!("eeff{suffix}"),
            threshold: 2,
            max_signers: 3,
            mainnet: true,
            orchard_fvk: Some(format!("uview1{suffix}")),
            address: Some(format!("u1{suffix}")),
            relay_url: Some("ws://localhost:50053".into()),
            created_at: 1700000000,
        }
    }

    #[test]
    fn batch_round_trip() {
        let shares = vec![fixture_share("a"), fixture_share("b"), fixture_share("c")];
        let env = seal_batch_envelope(&shares, "passphrase123").unwrap();
        let opened = open_batch_envelope(&env, "passphrase123").unwrap();
        assert_eq!(opened.len(), 3);
        assert_eq!(opened[0].label, "wallet-a");
        assert_eq!(opened[2].address, Some("u1c".into()));
    }

    #[test]
    fn batch_wrong_passphrase_rejected() {
        let shares = vec![fixture_share("a")];
        let env = seal_batch_envelope(&shares, "right").unwrap();
        assert!(open_batch_envelope(&env, "wrong").is_err());
    }

    #[test]
    fn cross_format_rejected() {
        let single = seal_envelope(&fixture_payload(), "p").unwrap();
        // single envelope must not parse as batch
        assert!(open_batch_envelope(&single, "p").is_err());

        let batch = seal_batch_envelope(&[fixture_share("x")], "p").unwrap();
        // batch envelope must not parse as single
        assert!(open_envelope(&batch, "p").is_err());
    }
}
