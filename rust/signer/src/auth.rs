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

// ── ZID root derivation (two-stage KDF) ──

/// Derive the ZID root seed from the mnemonic words via HKDF.
///
/// Matches zafu's identity.ts v2 derivation:
///   mnemonic_hash = SHA-256(mnemonic_string)
///   zid_seed = HKDF-SHA256(mnemonic_hash, "zafu-zid-v2", "identity-root", 64)
///
/// NOTE: we derive from SHA-256(mnemonic), NOT from BIP39Seed(mnemonic).
/// BIP39Seed = PBKDF2(mnemonic, "mnemonic" + passphrase) is what spending
/// keys use. By hashing the mnemonic string directly, ZID shares zero
/// intermediate material with spending keys.
///
/// Same mnemonic, completely separate derivation path.
fn derive_zid_root(seed_phrase: &str) -> Result<[u8; 64], String> {
    use hkdf::Hkdf;
    use sha2::{Sha256, Digest};

    let mnemonic_hash = Sha256::digest(seed_phrase.as_bytes());

    let hk = Hkdf::<Sha256>::new(Some(b"zafu-zid-v2"), &mnemonic_hash);
    let mut zid_root = [0u8; 64];
    hk.expand(b"identity-root", &mut zid_root)
        .map_err(|e| format!("hkdf expand: {e}"))?;

    Ok(zid_root)
}

// ── ZID pubkey derivation ──

/// Derive the ZID cross-site public key from the mnemonic.
///
/// Matches zafu's deriveZidCrossSite(mnemonic, "default"):
///   zid_root  = derive_zid_root(mnemonic)
///   identity  = HMAC-SHA512(zid_root, "identity:default")
///   seed      = HMAC-SHA512(identity, "cross-site")
///   pubkey    = ed25519.getPublicKey(seed[0:32])
///
/// Returns hex-encoded 32-byte ed25519 public key.
pub fn derive_zid_pubkey(seed_phrase: &str) -> Result<String, String> {
    derive_zid_pubkey_for_identity(seed_phrase, "default")
}

/// Derive ZID pubkey for a specific identity name.
pub fn derive_zid_pubkey_for_identity(
    seed_phrase: &str,
    identity_name: &str,
) -> Result<String, String> {
    use hmac::{Hmac, Mac};
    use sha2::Sha512;
    type HmacSha512 = Hmac<Sha512>;

    let zid_root = derive_zid_root(seed_phrase)?;

    // identity = HMAC-SHA512(zid_root, "identity:{name}")
    let mut mac = HmacSha512::new_from_slice(&zid_root)
        .map_err(|e| format!("hmac init: {e}"))?;
    mac.update(format!("identity:{identity_name}").as_bytes());
    let identity = mac.finalize().into_bytes();

    // seed = HMAC-SHA512(identity, "cross-site")
    let mut mac = HmacSha512::new_from_slice(&identity)
        .map_err(|e| format!("hmac init: {e}"))?;
    mac.update(b"cross-site");
    let seed = mac.finalize().into_bytes();

    let key_seed: [u8; 32] = seed[..32]
        .try_into()
        .map_err(|_| "seed slice failed".to_string())?;
    let pair = ed25519::Pair::from_seed(&key_seed);

    Ok(hex::encode(pair.public().0))
}

/// Sign a ZID challenge. Supports both site-specific and cross-site modes.
///
/// Matches zafu's signZid():
///   - mode "site": tag = "site:{origin}" or "site:{origin}:{rotation}"
///   - mode "cross-site": tag = "cross-site"
///
/// Returns (signature_hex, pubkey_hex).
pub fn sign_zid_challenge(
    seed_phrase: &str,
    identity_name: &str,
    mode: &str,
    origin: &str,
    rotation: u32,
    challenge: &[u8],
) -> Result<(String, String), String> {
    use hmac::{Hmac, Mac};
    use sha2::Sha512;
    type HmacSha512 = Hmac<Sha512>;

    let zid_root = derive_zid_root(seed_phrase)?;

    // identity = HMAC-SHA512(zid_root, "identity:{name}")
    let mut mac = HmacSha512::new_from_slice(&zid_root)
        .map_err(|e| format!("hmac init: {e}"))?;
    mac.update(format!("identity:{identity_name}").as_bytes());
    let identity = mac.finalize().into_bytes();

    // derive seed based on mode
    let tag = if mode == "cross-site" {
        "cross-site".to_string()
    } else if rotation == 0 {
        format!("site:{origin}")
    } else {
        format!("site:{origin}:{rotation}")
    };

    let mut mac = HmacSha512::new_from_slice(&identity)
        .map_err(|e| format!("hmac init: {e}"))?;
    mac.update(tag.as_bytes());
    let seed = mac.finalize().into_bytes();

    let key_seed: [u8; 32] = seed[..32]
        .try_into()
        .map_err(|_| "seed slice failed".to_string())?;
    let pair = ed25519::Pair::from_seed(&key_seed);
    let signature = pair.sign(challenge);

    Ok((hex::encode(signature.0), hex::encode(pair.public().0)))
}

// ── hot wallet derivation ──

/// Derive a 12-word BIP39 hot wallet mnemonic from the master seed phrase.
///
/// Uses two-stage KDF (v2):
///   zid_root  = derive_zid_root(mnemonic)  // HKDF from BIP39 seed
///   identity  = HMAC-SHA512(zid_root, "identity:default")
///   seed      = HMAC-SHA512(identity, "hot-wallet-v1")
///   entropy   = seed[0..16]  (128 bits = 12 words)
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

    // stage 1+2: two-stage KDF to get ZID root
    let zid_root = derive_zid_root(seed_phrase)?;

    // step 3: identity = HMAC-SHA512(zid_root, "identity:{name}")
    let mut mac = HmacSha512::new_from_slice(&zid_root)
        .map_err(|e| format!("hmac init: {e}"))?;
    mac.update(format!("identity:{identity_name}").as_bytes());
    let identity = mac.finalize().into_bytes();

    // step 4: seed = HMAC-SHA512(identity, "hot-wallet-v1")
    let mut mac = HmacSha512::new_from_slice(&identity)
        .map_err(|e| format!("hmac init: {e}"))?;
    mac.update(b"hot-wallet-v1");
    let seed = mac.finalize().into_bytes();

    // step 5: entropy = first 16 bytes (128 bits = 12-word mnemonic)
    let entropy: [u8; 16] = seed[..16].try_into()
        .map_err(|_| "entropy slice failed".to_string())?;

    use bip39::{Language, Mnemonic};
    let mnemonic = Mnemonic::from_entropy(&entropy, Language::English)
        .map_err(|e| format!("bip39: {e}"))?;

    Ok(mnemonic.to_string())
}

// ========================================================================
// POST-QUANTUM RECOVERY: reserved derivation paths
// ========================================================================
//
// The derivation tree (HKDF-SHA256 root + HMAC-SHA512 branches) is quantum-safe.
// Only the final ed25519 keypair is vulnerable to Shor's algorithm.
//
// When PQ signatures are needed, derive from the SAME mnemonic using reserved tags.
// No protocol-breaking changes required - mnemonic recovery always works.
//
// Reserved tags (DO NOT USE until PQ migration):
//   "zid-falcon-v1"       - FALCON-512 site-scoped identity
//   "zid-falcon-cross-v1" - FALCON-512 cross-site identity
//   "ring-vrf-pq-v1"      - post-quantum ring VRF
//
// Migration: same derive_zid_root() + identity, then
//   HMAC-SHA512(identity, "zid-falcon-v1") -> 48 bytes -> FALCON-512 keypair
//   Hybrid signing via falconed crate (ed25519 + FALCON-512)
//
// FALCON-512: 897B pubkey, 666B sig (QR-friendly for zigner)
// Dilithium2: 1312B pubkey, 2420B sig (too large for single QR)
// ========================================================================

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
    fn test_zid_pubkey_deterministic() {
        let pk1 = derive_zid_pubkey(TEST_PHRASE).unwrap();
        let pk2 = derive_zid_pubkey(TEST_PHRASE).unwrap();
        assert_eq!(pk1, pk2);
        assert_eq!(pk1.len(), 64); // 32 bytes hex
    }

    #[test]
    fn test_zid_pubkey_matches_zafu() {
        // cross-repo compat: this value is produced by zafu's identity.ts
        // deriveZidCrossSite("abandon...about", "default")
        let pk = derive_zid_pubkey(TEST_PHRASE).unwrap();
        assert_eq!(pk, "c19e35c5735667f974a39729fddb3b19fb90f325fd9fdbed7b3bf32116e97835");
    }

    #[test]
    fn test_zid_pubkey_different_identities() {
        let default = derive_zid_pubkey(TEST_PHRASE).unwrap();
        let poker = derive_zid_pubkey_for_identity(TEST_PHRASE, "poker").unwrap();
        assert_ne!(default, poker);
    }

    #[test]
    fn test_zid_pubkey_differs_from_base_identity() {
        // ZID v2 (HKDF-based) must differ from old zafu-identity (direct HMAC)
        let zid = derive_zid_pubkey(TEST_PHRASE).unwrap();
        let base = derive_identity(TEST_PHRASE, 0).unwrap();
        assert_ne!(zid, base);
    }

    #[test]
    fn test_sign_zid_challenge_cross_site() {
        let challenge = b"test-challenge-data";
        let (sig1, pk1) = sign_zid_challenge(TEST_PHRASE, "default", "cross-site", "", 0, challenge).unwrap();
        let (sig2, pk2) = sign_zid_challenge(TEST_PHRASE, "default", "cross-site", "", 0, challenge).unwrap();
        // deterministic
        assert_eq!(sig1, sig2);
        assert_eq!(pk1, pk2);
        // pubkey matches derive_zid_pubkey (both are cross-site "default")
        let expected_pk = derive_zid_pubkey(TEST_PHRASE).unwrap();
        assert_eq!(pk1, expected_pk);
        // signature verifies
        assert!(verify_signature(&pk1, &sig1, challenge).unwrap());
    }

    #[test]
    fn test_sign_zid_challenge_site_specific() {
        let challenge = b"site-challenge";
        let (sig_a, pk_a) = sign_zid_challenge(TEST_PHRASE, "default", "site", "https://example.com", 0, challenge).unwrap();
        let (sig_b, pk_b) = sign_zid_challenge(TEST_PHRASE, "default", "site", "https://other.org", 0, challenge).unwrap();
        // different sites produce different keys
        assert_ne!(pk_a, pk_b);
        // both verify
        assert!(verify_signature(&pk_a, &sig_a, challenge).unwrap());
        assert!(verify_signature(&pk_b, &sig_b, challenge).unwrap());
        // site-specific differs from cross-site
        let cross_pk = derive_zid_pubkey(TEST_PHRASE).unwrap();
        assert_ne!(pk_a, cross_pk);
    }

    #[test]
    fn test_sign_zid_challenge_rotation() {
        let challenge = b"rotate";
        let (_, pk0) = sign_zid_challenge(TEST_PHRASE, "default", "site", "https://example.com", 0, challenge).unwrap();
        let (_, pk1) = sign_zid_challenge(TEST_PHRASE, "default", "site", "https://example.com", 1, challenge).unwrap();
        assert_ne!(pk0, pk1);
    }

    #[test]
    fn test_sign_zid_site_specific_matches_zafu() {
        // cross-repo compat: site-specific pubkeys must match zafu's deriveZidForSite()
        let challenge = b"x";
        let (_, pk) = sign_zid_challenge(TEST_PHRASE, "default", "site", "https://example.com", 0, challenge).unwrap();
        assert_eq!(pk, "3f96957e3a6ded64243bc0a3926faf79c25ddfb93b33c4d15d787fb13322ec5f");
        let (_, pk1) = sign_zid_challenge(TEST_PHRASE, "default", "site", "https://example.com", 1, challenge).unwrap();
        assert_eq!(pk1, "9eb0ab0f2c8c252e04b7dd4af0615ffe209171162523347e1a402bbdcffb42a5");
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
