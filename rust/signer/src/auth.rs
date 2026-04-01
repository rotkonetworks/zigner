// auth.rs — ed25519 identity derivation and QR-based authentication
//
// Compatible with zafu's identity.ts derivation:
//   HMAC-SHA512("zafu-identity", mnemonic || '\0' || index) → ed25519 seed
//
// This produces the same keypairs as zafu for the same mnemonic + index.
// Identity is wallet-level, not per-domain. Domain binding happens in
// the challenge message, not the key derivation.
//
// For per-service keys, use domain-separated derivation:
//   HMAC-SHA512("zafu-identity:" || domain, mnemonic || '\0' || index) → ed25519 seed
// These are distinct from the base identity (different HMAC key).

use sp_core::{ed25519, Pair};
use std::convert::TryInto;

const IDENTITY_DOMAIN: &[u8] = b"zafu-identity";

/// Derive the base identity keypair (compatible with zafu).
/// Returns hex-encoded 32-byte ed25519 public key.
pub fn derive_identity(seed_phrase: &str, index: u32) -> Result<String, String> {
    let pair = derive_base_keypair(seed_phrase, index)?;
    Ok(hex::encode(pair.public().0))
}

/// Derive a domain-scoped identity keypair.
/// Different domain = different key (no cross-site correlation).
/// Returns hex-encoded 32-byte ed25519 public key.
pub fn derive_domain_identity(
    seed_phrase: &str,
    domain: &str,
    index: u32,
) -> Result<String, String> {
    let pair = derive_domain_keypair(seed_phrase, domain, index)?;
    Ok(hex::encode(pair.public().0))
}

/// Sign a challenge with the base identity (zafu-compatible).
///
/// The challenge is an opaque byte string — the caller (mobile UI) constructs
/// it from the scanned QR payload. For zigner QR auth, the canonical format is:
///   "zigner-auth-v1\n{domain}\n{nonce}\n{timestamp}"
///
/// Returns (pubkey_hex, signature_hex).
pub fn sign_challenge(
    seed_phrase: &str,
    index: u32,
    challenge: &[u8],
) -> Result<(String, String), String> {
    let pair = derive_base_keypair(seed_phrase, index)?;
    let signature = pair.sign(challenge);
    Ok((hex::encode(pair.public().0), hex::encode(signature.0)))
}

/// Sign a challenge with a domain-scoped identity.
pub fn sign_domain_challenge(
    seed_phrase: &str,
    domain: &str,
    index: u32,
    challenge: &[u8],
) -> Result<(String, String), String> {
    let pair = derive_domain_keypair(seed_phrase, domain, index)?;
    let signature = pair.sign(challenge);
    Ok((hex::encode(pair.public().0), hex::encode(signature.0)))
}

/// Verify an ed25519 signature.
pub fn verify_signature(pubkey_hex: &str, sig_hex: &str, challenge: &[u8]) -> Result<bool, String> {
    let pubkey_bytes: [u8; 32] = hex::decode(pubkey_hex)
        .map_err(|e| format!("bad pubkey hex: {e}"))?
        .try_into()
        .map_err(|_| "pubkey must be 32 bytes".to_string())?;
    let sig_bytes: [u8; 64] = hex::decode(sig_hex)
        .map_err(|e| format!("bad sig hex: {e}"))?
        .try_into()
        .map_err(|_| "signature must be 64 bytes".to_string())?;

    let pubkey = ed25519::Public::from_raw(pubkey_bytes);
    let signature = ed25519::Signature::from_raw(sig_bytes);
    Ok(ed25519::Pair::verify(&signature, challenge, &pubkey))
}

/// Build the canonical challenge message for QR-based auth.
/// Format: "zigner-auth-v1\n{domain}\n{nonce}\n{timestamp}"
pub fn build_auth_challenge(domain: &str, nonce: &str, timestamp: u64) -> Vec<u8> {
    format!("zigner-auth-v1\n{domain}\n{nonce}\n{timestamp}").into_bytes()
}

// ── internal derivation ──

/// Base identity derivation — matches zafu's identity.ts exactly:
///   HMAC-SHA512(key="zafu-identity", data=mnemonic + '\0' + index_str)
fn derive_base_keypair(seed_phrase: &str, index: u32) -> Result<ed25519::Pair, String> {
    use hmac::{Hmac, Mac};
    use sha2::Sha512;
    type HmacSha512 = Hmac<Sha512>;

    // Match zafu: TextEncoder.encode(mnemonic + '\0' + index)
    let data = format!("{seed_phrase}\0{index}");

    let mut mac =
        HmacSha512::new_from_slice(IDENTITY_DOMAIN).map_err(|e| format!("hmac init: {e}"))?;
    mac.update(data.as_bytes());
    let result = mac.finalize().into_bytes();

    let seed: [u8; 32] = result[..32]
        .try_into()
        .map_err(|_| "hmac output too short".to_string())?;
    Ok(ed25519::Pair::from_seed(&seed))
}

/// Domain-scoped derivation — extends zafu's scheme with domain separation:
///   HMAC-SHA512(key="zafu-identity:" + domain, data=mnemonic + '\0' + index_str)
///
/// When domain is empty, falls back to base derivation.
fn derive_domain_keypair(
    seed_phrase: &str,
    domain: &str,
    index: u32,
) -> Result<ed25519::Pair, String> {
    if domain.is_empty() {
        return derive_base_keypair(seed_phrase, index);
    }

    use hmac::{Hmac, Mac};
    use sha2::Sha512;
    type HmacSha512 = Hmac<Sha512>;

    let hmac_key = format!("zafu-identity:{domain}");
    let data = format!("{seed_phrase}\0{index}");

    let mut mac =
        HmacSha512::new_from_slice(hmac_key.as_bytes()).map_err(|e| format!("hmac init: {e}"))?;
    mac.update(data.as_bytes());
    let result = mac.finalize().into_bytes();

    let seed: [u8; 32] = result[..32]
        .try_into()
        .map_err(|_| "hmac output too short".to_string())?;
    Ok(ed25519::Pair::from_seed(&seed))
}

// ── hot wallet derivation ──

/// Derive a 12-word BIP39 hot wallet mnemonic from the master seed phrase.
///
/// Matches zafu's identity.ts derivation exactly:
///   root     = HMAC-SHA512(key="zid-v1", data=mnemonic)
///   identity = HMAC-SHA512(key=root, data="identity:default")
///   seed     = HMAC-SHA512(key=identity, data="hot-wallet-v1")
///   entropy  = seed[0..16]  (128 bits = 12 words)
///
/// The resulting mnemonic is deterministic and recoverable from the master seed.
pub fn derive_hot_wallet_mnemonic(seed_phrase: &str) -> Result<String, String> {
    derive_hot_wallet_mnemonic_for_identity(seed_phrase, "default")
}

/// Derive hot wallet mnemonic for a specific identity name.
pub fn derive_hot_wallet_mnemonic_for_identity(
    seed_phrase: &str,
    identity_name: &str,
) -> Result<String, String> {
    use hmac::{Hmac, Mac};
    use sha2::Sha512;
    type HmacSha512 = Hmac<Sha512>;

    // step 1: root = HMAC-SHA512(key="zid-v1", data=mnemonic)
    let mut mac = HmacSha512::new_from_slice(b"zid-v1")
        .map_err(|e| format!("hmac init: {e}"))?;
    mac.update(seed_phrase.as_bytes());
    let root = mac.finalize().into_bytes();

    // step 2: identity = HMAC-SHA512(key=root, data="identity:{name}")
    let mut mac = HmacSha512::new_from_slice(&root)
        .map_err(|e| format!("hmac init: {e}"))?;
    mac.update(format!("identity:{identity_name}").as_bytes());
    let identity = mac.finalize().into_bytes();

    // step 3: seed = HMAC-SHA512(key=identity, data="hot-wallet-v1")
    let mut mac = HmacSha512::new_from_slice(&identity)
        .map_err(|e| format!("hmac init: {e}"))?;
    mac.update(b"hot-wallet-v1");
    let seed = mac.finalize().into_bytes();

    // step 4: entropy = first 16 bytes (128 bits = 12-word mnemonic)
    let entropy: [u8; 16] = seed[..16].try_into()
        .map_err(|_| "entropy slice failed".to_string())?;

    // convert to BIP39 mnemonic
    use bip39::{Language, Mnemonic};
    let mnemonic = Mnemonic::from_entropy(&entropy, Language::English)
        .map_err(|e| format!("bip39: {e}"))?;

    Ok(mnemonic.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_PHRASE: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    #[test]
    fn test_base_identity_deterministic() {
        let id1 = derive_identity(TEST_PHRASE, 0).unwrap();
        let id2 = derive_identity(TEST_PHRASE, 0).unwrap();
        assert_eq!(id1, id2);
        assert_eq!(id1.len(), 64); // 32 bytes hex
    }

    #[test]
    fn test_rotation_changes_key() {
        let id0 = derive_identity(TEST_PHRASE, 0).unwrap();
        let id1 = derive_identity(TEST_PHRASE, 1).unwrap();
        assert_ne!(id0, id1);
    }

    #[test]
    fn test_domain_identity_differs_from_base() {
        let base = derive_identity(TEST_PHRASE, 0).unwrap();
        let domain = derive_domain_identity(TEST_PHRASE, "example.com", 0).unwrap();
        assert_ne!(base, domain);
    }

    #[test]
    fn test_different_domains_different_keys() {
        let a = derive_domain_identity(TEST_PHRASE, "example.com", 0).unwrap();
        let b = derive_domain_identity(TEST_PHRASE, "other.org", 0).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn test_sign_and_verify_base() {
        let challenge = build_auth_challenge("example.com", "nonce123", 1710000000);
        let (pubkey, sig) = sign_challenge(TEST_PHRASE, 0, &challenge).unwrap();
        let valid = verify_signature(&pubkey, &sig, &challenge).unwrap();
        assert!(valid);
    }

    #[test]
    fn test_sign_and_verify_domain() {
        let challenge = build_auth_challenge("example.com", "nonce123", 1710000000);
        let (pubkey, sig) =
            sign_domain_challenge(TEST_PHRASE, "example.com", 0, &challenge).unwrap();
        let valid = verify_signature(&pubkey, &sig, &challenge).unwrap();
        assert!(valid);
    }

    #[test]
    fn test_wrong_challenge_fails() {
        let challenge = build_auth_challenge("example.com", "nonce1", 1710000000);
        let (pubkey, sig) = sign_challenge(TEST_PHRASE, 0, &challenge).unwrap();

        let wrong = build_auth_challenge("evil.com", "nonce1", 1710000000);
        let valid = verify_signature(&pubkey, &sig, &wrong).unwrap();
        assert!(!valid);
    }

    #[test]
    fn test_empty_domain_falls_back_to_base() {
        let base = derive_identity(TEST_PHRASE, 0).unwrap();
        let empty_domain = derive_domain_identity(TEST_PHRASE, "", 0).unwrap();
        assert_eq!(base, empty_domain);
    }

    #[test]
    fn test_hot_wallet_deterministic() {
        let m1 = derive_hot_wallet_mnemonic(TEST_PHRASE).unwrap();
        let m2 = derive_hot_wallet_mnemonic(TEST_PHRASE).unwrap();
        assert_eq!(m1, m2);
        // 12 words
        assert_eq!(m1.split_whitespace().count(), 12);
        // different from master seed
        assert_ne!(m1, TEST_PHRASE);
    }

    #[test]
    fn test_hot_wallet_different_identities() {
        let default = derive_hot_wallet_mnemonic(TEST_PHRASE).unwrap();
        let poker = derive_hot_wallet_mnemonic_for_identity(TEST_PHRASE, "poker").unwrap();
        assert_ne!(default, poker);
    }
}
