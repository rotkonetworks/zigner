// auth.rs — QR-based ed25519 authentication with rotatable identities
//
// Derives per-domain ed25519 keypairs from the user's seed phrase.
// Signs challenges from services. No chain-specific logic.
//
// Derivation path: "//auth/{domain}/{index}"
// - domain: the service domain (e.g. "example.com")
// - index: rotation counter (0, 1, 2, ...)
//
// The signed payload is: domain || nonce || timestamp (canonical encoding)
// This prevents replay (nonce), cross-site (domain), and time-based attacks (timestamp).

use std::convert::TryInto;
use sp_core::{ed25519, Pair};

/// Derive an auth identity (ed25519 public key) for a given domain + index.
/// Returns hex-encoded 32-byte public key.
pub fn derive_auth_identity(
    seed_phrase: &str,
    domain: &str,
    index: u32,
) -> Result<String, String> {
    let pair = derive_keypair(seed_phrase, domain, index)?;
    Ok(hex::encode(pair.public().0))
}

/// Sign an authentication challenge.
///
/// The challenge message is constructed canonically:
///   "zigner-auth-v1" || domain || nonce || timestamp_bytes
///
/// This binding prevents:
/// - Cross-site replay (domain is in the signed message)
/// - Replay attacks (nonce is unique per challenge)
/// - Stale challenges (timestamp included, service can enforce expiry)
///
/// Returns hex-encoded 64-byte ed25519 signature.
pub fn sign_auth_challenge(
    seed_phrase: &str,
    domain: &str,
    index: u32,
    nonce: &str,
    timestamp: u64,
) -> Result<(String, String), String> {
    let pair = derive_keypair(seed_phrase, domain, index)?;
    let message = build_challenge_message(domain, nonce, timestamp);
    let signature = pair.sign(&message);
    let pubkey_hex = hex::encode(pair.public().0);
    let sig_hex = hex::encode(signature.0);
    Ok((pubkey_hex, sig_hex))
}

/// Verify an auth signature (for testing / self-verification).
pub fn verify_auth_signature(
    pubkey_hex: &str,
    sig_hex: &str,
    domain: &str,
    nonce: &str,
    timestamp: u64,
) -> Result<bool, String> {
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
    let message = build_challenge_message(domain, nonce, timestamp);

    Ok(ed25519::Pair::verify(&signature, &message, &pubkey))
}

// ── internal ──

fn derive_keypair(
    seed_phrase: &str,
    domain: &str,
    index: u32,
) -> Result<ed25519::Pair, String> {
    if domain.is_empty() {
        return Err("domain must not be empty".to_string());
    }

    // Use a two-level hard derivation: //auth//<domain_hash>//<index>
    // Domain is hashed to avoid special characters in Substrate paths.
    // The hash is truncated to 8 hex chars (4 bytes) — collision-resistant
    // enough for derivation (we're not storing secrets, just deriving keys).
    use sp_core::hashing::twox_64;
    let domain_hash = hex::encode(&twox_64(domain.as_bytes())[..4]);

    let path = format!("//auth//{domain_hash}//{index}");
    let (pair, _) = ed25519::Pair::from_string_with_seed(
        &format!("{seed_phrase}{path}"),
        None,
    )
    .map_err(|e| format!("derivation failed: {e:?}"))?;
    Ok(pair)
}

/// Build the canonical challenge message that both signer and verifier construct.
/// Format: "zigner-auth-v1\n{domain}\n{nonce}\n{timestamp}"
///
/// Using a versioned prefix ensures forward compatibility if we change the format.
fn build_challenge_message(domain: &str, nonce: &str, timestamp: u64) -> Vec<u8> {
    format!("zigner-auth-v1\n{domain}\n{nonce}\n{timestamp}").into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_PHRASE: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";

    #[test]
    fn test_derive_identity_deterministic() {
        let id1 = derive_auth_identity(TEST_PHRASE, "example.com", 0).unwrap();
        let id2 = derive_auth_identity(TEST_PHRASE, "example.com", 0).unwrap();
        assert_eq!(id1, id2);
        assert_eq!(id1.len(), 64); // 32 bytes hex
    }

    #[test]
    fn test_different_domains_different_keys() {
        let id1 = derive_auth_identity(TEST_PHRASE, "example.com", 0).unwrap();
        let id2 = derive_auth_identity(TEST_PHRASE, "other.org", 0).unwrap();
        assert_ne!(id1, id2);
    }

    #[test]
    fn test_rotation_changes_key() {
        let id0 = derive_auth_identity(TEST_PHRASE, "example.com", 0).unwrap();
        let id1 = derive_auth_identity(TEST_PHRASE, "example.com", 1).unwrap();
        assert_ne!(id0, id1);
    }

    #[test]
    fn test_sign_and_verify() {
        let (pubkey, sig) = sign_auth_challenge(
            TEST_PHRASE,
            "example.com",
            0,
            "random-nonce-123",
            1710000000,
        )
        .unwrap();

        let valid = verify_auth_signature(
            &pubkey,
            &sig,
            "example.com",
            "random-nonce-123",
            1710000000,
        )
        .unwrap();
        assert!(valid);
    }

    #[test]
    fn test_wrong_domain_fails() {
        let (pubkey, sig) = sign_auth_challenge(
            TEST_PHRASE,
            "example.com",
            0,
            "nonce",
            1710000000,
        )
        .unwrap();

        let valid = verify_auth_signature(
            &pubkey,
            &sig,
            "evil.com", // wrong domain
            "nonce",
            1710000000,
        )
        .unwrap();
        assert!(!valid);
    }

    #[test]
    fn test_wrong_nonce_fails() {
        let (pubkey, sig) = sign_auth_challenge(
            TEST_PHRASE,
            "example.com",
            0,
            "nonce-1",
            1710000000,
        )
        .unwrap();

        let valid = verify_auth_signature(
            &pubkey,
            &sig,
            "example.com",
            "nonce-2", // wrong nonce
            1710000000,
        )
        .unwrap();
        assert!(!valid);
    }

    #[test]
    fn test_empty_domain_rejected() {
        let result = derive_auth_identity(TEST_PHRASE, "", 0);
        assert!(result.is_err());
    }

    #[test]
    fn test_domain_with_special_chars_works() {
        // Domain is hashed, so special chars are fine — no path injection possible
        let result = derive_auth_identity(TEST_PHRASE, "evil/../../secret", 0);
        assert!(result.is_ok());
        // But different from a normal domain
        let normal = derive_auth_identity(TEST_PHRASE, "example.com", 0).unwrap();
        assert_ne!(result.unwrap(), normal);
    }
}
