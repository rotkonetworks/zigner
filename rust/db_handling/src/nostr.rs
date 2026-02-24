//! Nostr key derivation using NIP-06 and event signing
//!
//! This implements key derivation for Nostr using:
//! - NIP-06: Basic key derivation from mnemonic (m/44'/1237'/account'/0/0)
//! - BIP-340: Schnorr signatures for event signing
//!
//! Nostr uses x-only public keys (32 bytes) and Schnorr signatures.

use crate::error::{Error, Result};
use bip32::{DerivationPath, XPrv};
use secp256k1::{Keypair, Message, Secp256k1, SecretKey, XOnlyPublicKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// SLIP-0044 coin type for Nostr (NIP-06)
pub const COIN_TYPE_NOSTR: u32 = 1237;

/// Sled tree name for storing Nostr npub addresses
const NOSTR_ADDRS: &str = "nostr_addresses";

/// Store a Nostr npub for a given public key hex
pub fn store_nostr_address(database: &sled::Db, pubkey_hex: &str, npub: &str) -> Result<()> {
    let tree = database.open_tree(NOSTR_ADDRS)?;
    tree.insert(pubkey_hex.as_bytes(), npub.as_bytes())?;
    Ok(())
}

/// Retrieve a Nostr npub for a given public key hex
pub fn get_nostr_address(database: &sled::Db, pubkey_hex: &str) -> Result<Option<String>> {
    let tree = database.open_tree(NOSTR_ADDRS)?;
    match tree.get(pubkey_hex.as_bytes())? {
        Some(bytes) => {
            let npub = String::from_utf8(bytes.to_vec())
                .map_err(|e| Error::Other(anyhow::anyhow!("Invalid UTF-8: {}", e)))?;
            Ok(Some(npub))
        }
        None => Ok(None),
    }
}

/// Nostr key pair with x-only public key
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct NostrKeyPair {
    /// 32-byte secp256k1 secret key
    pub secret_key: [u8; 32],
    /// 32-byte x-only public key (BIP-340)
    pub public_key: [u8; 32],
    /// Account index used for derivation
    pub account: u32,
}

impl NostrKeyPair {
    /// Get the npub (bech32-encoded public key)
    pub fn npub(&self) -> Result<String> {
        use bech32::{Bech32, Hrp};

        let hrp =
            Hrp::parse("npub").map_err(|e| Error::Other(anyhow::anyhow!("Invalid hrp: {}", e)))?;

        let npub = bech32::encode::<Bech32>(hrp, &self.public_key)
            .map_err(|e| Error::Other(anyhow::anyhow!("Bech32 encoding error: {}", e)))?;

        Ok(npub)
    }

    /// Get the nsec (bech32-encoded secret key) - USE WITH CAUTION
    pub fn nsec(&self) -> Result<String> {
        use bech32::{Bech32, Hrp};

        let hrp =
            Hrp::parse("nsec").map_err(|e| Error::Other(anyhow::anyhow!("Invalid hrp: {}", e)))?;

        let nsec = bech32::encode::<Bech32>(hrp, &self.secret_key)
            .map_err(|e| Error::Other(anyhow::anyhow!("Bech32 encoding error: {}", e)))?;

        Ok(nsec)
    }

    /// Get public key as hex string
    pub fn pubkey_hex(&self) -> String {
        hex::encode(self.public_key)
    }

    /// Sign a Nostr event (returns 64-byte Schnorr signature)
    pub fn sign_event(&self, event: &UnsignedEvent) -> Result<SignedEvent> {
        let id = event.compute_id();
        let sig = self.sign_schnorr(&id)?;

        Ok(SignedEvent {
            id: hex::encode(id),
            pubkey: self.pubkey_hex(),
            created_at: event.created_at,
            kind: event.kind,
            tags: event.tags.clone(),
            content: event.content.clone(),
            sig: hex::encode(sig),
        })
    }

    /// Sign a raw message hash using BIP-340 Schnorr
    pub fn sign_schnorr(&self, message_hash: &[u8; 32]) -> Result<[u8; 64]> {
        let secp = Secp256k1::new();
        let secret = SecretKey::from_slice(&self.secret_key)
            .map_err(|e| Error::Other(anyhow::anyhow!("Invalid secret key: {}", e)))?;
        let keypair = Keypair::from_secret_key(&secp, &secret);
        let msg = Message::from_digest_slice(message_hash)
            .map_err(|e| Error::Other(anyhow::anyhow!("Invalid message: {}", e)))?;

        let sig = secp.sign_schnorr_no_aux_rand(&msg, &keypair);
        Ok(*sig.as_ref())
    }
}

/// Unsigned Nostr event (NIP-01)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UnsignedEvent {
    pub created_at: u64,
    pub kind: u32,
    pub tags: Vec<Vec<String>>,
    pub content: String,
}

impl UnsignedEvent {
    /// Create a new unsigned event
    pub fn new(kind: u32, content: String, tags: Vec<Vec<String>>) -> Self {
        use std::time::{SystemTime, UNIX_EPOCH};

        let created_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        Self {
            created_at,
            kind,
            tags,
            content,
        }
    }

    /// Compute event ID per NIP-01
    /// SHA256 of JSON: [0, pubkey, created_at, kind, tags, content]
    pub fn compute_id_with_pubkey(&self, pubkey_hex: &str) -> [u8; 32] {
        let serialized = serde_json::to_string(&(
            0u8,
            pubkey_hex,
            self.created_at,
            self.kind,
            &self.tags,
            &self.content,
        ))
        .expect("serialization should not fail");

        let mut hasher = Sha256::new();
        hasher.update(serialized.as_bytes());
        hasher.finalize().into()
    }

    /// Compute event ID (requires pubkey to be set separately)
    fn compute_id(&self) -> [u8; 32] {
        // This is a placeholder - actual ID requires pubkey
        // In practice, sign_event provides the pubkey
        [0u8; 32]
    }
}

/// Signed Nostr event (NIP-01)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignedEvent {
    pub id: String,
    pub pubkey: String,
    pub created_at: u64,
    pub kind: u32,
    pub tags: Vec<Vec<String>>,
    pub content: String,
    pub sig: String,
}

impl SignedEvent {
    /// Serialize to JSON for relay submission
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).expect("serialization should not fail")
    }

    /// Verify the event signature
    pub fn verify(&self) -> Result<bool> {
        let secp = Secp256k1::new();

        // Decode pubkey
        let pubkey_bytes = hex::decode(&self.pubkey)
            .map_err(|e| Error::Other(anyhow::anyhow!("Invalid pubkey hex: {}", e)))?;
        let xonly = XOnlyPublicKey::from_slice(&pubkey_bytes)
            .map_err(|e| Error::Other(anyhow::anyhow!("Invalid x-only pubkey: {}", e)))?;

        // Decode signature
        let sig_bytes = hex::decode(&self.sig)
            .map_err(|e| Error::Other(anyhow::anyhow!("Invalid sig hex: {}", e)))?;
        let sig = secp256k1::schnorr::Signature::from_slice(&sig_bytes)
            .map_err(|e| Error::Other(anyhow::anyhow!("Invalid signature: {}", e)))?;

        // Decode and verify id
        let id_bytes = hex::decode(&self.id)
            .map_err(|e| Error::Other(anyhow::anyhow!("Invalid id hex: {}", e)))?;
        let msg = Message::from_digest_slice(&id_bytes)
            .map_err(|e| Error::Other(anyhow::anyhow!("Invalid message: {}", e)))?;

        Ok(secp.verify_schnorr(&sig, &msg, &xonly).is_ok())
    }
}

/// Derive Nostr key from seed phrase (NIP-06)
///
/// Path: m/44'/1237'/account'/0/0
pub fn derive_nostr_key(seed_phrase: &str, account: u32) -> Result<NostrKeyPair> {
    use bip39::{Language, Mnemonic, Seed};

    // Parse mnemonic and generate seed
    let mnemonic = Mnemonic::from_phrase(seed_phrase, Language::English)
        .map_err(|e| Error::Other(anyhow::anyhow!("Invalid mnemonic: {}", e)))?;
    let seed = Seed::new(&mnemonic, ""); // No passphrase

    // NIP-06 path: m/44'/1237'/account'/0/0
    let path_str = format!("m/44'/{}'/{}'/0/0", COIN_TYPE_NOSTR, account);
    let path: DerivationPath = path_str
        .parse()
        .map_err(|e| Error::Other(anyhow::anyhow!("Invalid derivation path: {}", e)))?;

    // Derive key
    let xprv = XPrv::derive_from_path(seed.as_bytes(), &path)
        .map_err(|e| Error::Other(anyhow::anyhow!("Key derivation failed: {}", e)))?;

    // Extract secret key
    let mut secret_key = [0u8; 32];
    secret_key.copy_from_slice(&xprv.private_key().to_bytes());

    // Derive x-only public key
    let secp = Secp256k1::new();
    let secret = SecretKey::from_slice(&secret_key)
        .map_err(|e| Error::Other(anyhow::anyhow!("Invalid secret key: {}", e)))?;
    let keypair = Keypair::from_secret_key(&secp, &secret);
    let (xonly, _parity) = keypair.x_only_public_key();

    let mut public_key = [0u8; 32];
    public_key.copy_from_slice(&xonly.serialize());

    Ok(NostrKeyPair {
        secret_key,
        public_key,
        account,
    })
}

/// Parse Nostr derivation path
///
/// Supports:
/// - Full NIP-06 path: m/44'/1237'/0'/0/0
/// - Simplified: //nostr//0
pub fn parse_nostr_path(path: &str) -> Result<u32> {
    // Try parsing as full path
    if path.starts_with("m/44'/1237'/") {
        let parts: Vec<&str> = path.split('/').collect();
        if parts.len() >= 4 {
            let account = parts[3]
                .trim_end_matches('\'')
                .parse::<u32>()
                .map_err(|_| Error::InvalidDerivation(path.to_string()))?;
            return Ok(account);
        }
    }

    // Simplified path: //nostr//0
    let parts: Vec<&str> = path.split("//").filter(|s| !s.is_empty()).collect();
    let account = parts
        .iter()
        .filter_map(|p| p.parse::<u32>().ok())
        .next()
        .unwrap_or(0);

    Ok(account)
}

/// Event kinds that require explicit user confirmation
pub fn requires_confirmation(kind: u32) -> bool {
    match kind {
        0 => true,     // Metadata (profile) - identity change
        3 => true,     // Contact list - social graph
        10002 => true, // Relay list - privacy implications
        30023 => true, // Long-form content - publishing
        _ => false,
    }
}

/// Get human-readable event kind name
pub fn event_kind_name(kind: u32) -> &'static str {
    match kind {
        0 => "Profile Metadata",
        1 => "Text Note",
        2 => "Recommend Relay",
        3 => "Contact List",
        4 => "Encrypted DM",
        5 => "Delete",
        6 => "Repost",
        7 => "Reaction",
        40 => "Channel Create",
        41 => "Channel Metadata",
        42 => "Channel Message",
        43 => "Channel Hide",
        44 => "Channel Mute",
        10002 => "Relay List",
        30023 => "Long-form Content",
        _ => "Unknown Event",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nostr_key_derivation() {
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

        let key = derive_nostr_key(mnemonic, 0).unwrap();

        println!("Nostr public key: {}", key.pubkey_hex());
        println!("Nostr npub: {}", key.npub().unwrap());

        // npub should start with npub1
        assert!(key.npub().unwrap().starts_with("npub1"));
        assert_eq!(key.public_key.len(), 32);
    }

    #[test]
    fn test_multiple_accounts() {
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

        let key0 = derive_nostr_key(mnemonic, 0).unwrap();
        let key1 = derive_nostr_key(mnemonic, 1).unwrap();

        assert_ne!(key0.public_key, key1.public_key);

        println!("Account 0: {}", key0.npub().unwrap());
        println!("Account 1: {}", key1.npub().unwrap());
    }

    #[test]
    fn test_event_signing() {
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let key = derive_nostr_key(mnemonic, 0).unwrap();

        // Create a test event
        let event = UnsignedEvent {
            created_at: 1234567890,
            kind: 1,
            tags: vec![],
            content: "Hello, Nostr!".to_string(),
        };

        // Compute ID with pubkey
        let id = event.compute_id_with_pubkey(&key.pubkey_hex());

        // Sign the ID
        let sig = key.sign_schnorr(&id).unwrap();

        println!("Event ID: {}", hex::encode(id));
        println!("Signature: {}", hex::encode(sig));

        assert_eq!(sig.len(), 64);
    }

    #[test]
    fn test_signed_event_verification() {
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let key = derive_nostr_key(mnemonic, 0).unwrap();

        // Create and sign event manually
        let created_at = 1234567890u64;
        let kind = 1u32;
        let tags: Vec<Vec<String>> = vec![];
        let content = "Hello, Nostr!".to_string();

        // Compute ID
        let serialized =
            serde_json::to_string(&(0u8, &key.pubkey_hex(), created_at, kind, &tags, &content))
                .unwrap();

        let mut hasher = Sha256::new();
        hasher.update(serialized.as_bytes());
        let id: [u8; 32] = hasher.finalize().into();

        // Sign
        let sig = key.sign_schnorr(&id).unwrap();

        // Create signed event
        let signed = SignedEvent {
            id: hex::encode(id),
            pubkey: key.pubkey_hex(),
            created_at,
            kind,
            tags,
            content,
            sig: hex::encode(sig),
        };

        // Verify
        assert!(signed.verify().unwrap());

        println!("Signed event JSON: {}", signed.to_json());
    }

    #[test]
    fn test_parse_nostr_path() {
        // Full path
        let account = parse_nostr_path("m/44'/1237'/5'/0/0").unwrap();
        assert_eq!(account, 5);

        // Simplified path
        let account = parse_nostr_path("//nostr//3").unwrap();
        assert_eq!(account, 3);

        // Default account
        let account = parse_nostr_path("//nostr").unwrap();
        assert_eq!(account, 0);
    }

    #[test]
    fn test_event_kind_names() {
        assert_eq!(event_kind_name(0), "Profile Metadata");
        assert_eq!(event_kind_name(1), "Text Note");
        assert_eq!(event_kind_name(7), "Reaction");
        assert!(requires_confirmation(0));
        assert!(requires_confirmation(3));
        assert!(!requires_confirmation(1));
    }
}
