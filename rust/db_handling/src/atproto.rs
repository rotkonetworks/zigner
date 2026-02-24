//! AT Protocol (Bluesky) key derivation and signing
//!
//! This implements key derivation and signing for AT Protocol using:
//! - BIP-44: Key derivation from mnemonic (m/44'/29'/account'/0/0)
//! - secp256k1: ECDSA signatures for repo commits
//! - did:plc: Placeholder DID method for identity
//!
//! AT Protocol uses secp256k1 for signing and identifies users via did:plc
//! identifiers which are derived from a hash of the genesis operation.

use crate::error::{Error, Result};
use bip32::{DerivationPath, XPrv};
use secp256k1::{Message, PublicKey, Secp256k1, SecretKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// SLIP-0044 coin type for AT Protocol (unofficial, commonly used)
pub const COIN_TYPE_ATPROTO: u32 = 29;

/// Sled tree name for storing AT Protocol DIDs
const ATPROTO_DIDS: &str = "atproto_dids";

/// Store an AT Protocol DID for a given public key hex
pub fn store_atproto_did(database: &sled::Db, pubkey_hex: &str, did: &str) -> Result<()> {
    let tree = database.open_tree(ATPROTO_DIDS)?;
    tree.insert(pubkey_hex.as_bytes(), did.as_bytes())?;
    Ok(())
}

/// Retrieve an AT Protocol DID for a given public key hex
pub fn get_atproto_did(database: &sled::Db, pubkey_hex: &str) -> Result<Option<String>> {
    let tree = database.open_tree(ATPROTO_DIDS)?;
    match tree.get(pubkey_hex.as_bytes())? {
        Some(bytes) => {
            let did = String::from_utf8(bytes.to_vec())
                .map_err(|e| Error::Other(anyhow::anyhow!("Invalid UTF-8: {}", e)))?;
            Ok(Some(did))
        }
        None => Ok(None),
    }
}

/// AT Protocol key pair with secp256k1 keys
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct AtProtoKeyPair {
    /// 32-byte secp256k1 secret key
    pub secret_key: [u8; 32],
    /// 33-byte compressed secp256k1 public key
    pub public_key: [u8; 33],
    /// Account index used for derivation
    pub account: u32,
}

impl AtProtoKeyPair {
    /// Get public key as hex string
    pub fn pubkey_hex(&self) -> String {
        hex::encode(self.public_key)
    }

    /// Get the did:key representation (multicodec + multibase encoded public key)
    /// Format: did:key:zQ3sh... (secp256k1-pub multicodec prefix 0xe7)
    pub fn did_key(&self) -> String {
        // Multicodec prefix for secp256k1-pub is 0xe7 (varint encoded as 0xe701)
        let mut bytes = vec![0xe7, 0x01];
        bytes.extend_from_slice(&self.public_key);

        // Multibase encode with base58btc (prefix 'z')
        let encoded = base58_encode(&bytes);
        format!("did:key:z{}", encoded)
    }

    /// Generate a did:plc from this key
    ///
    /// did:plc is derived from SHA-256 hash of the genesis operation,
    /// truncated to 120 bits, base32 encoded (lowercase, no padding)
    pub fn generate_did_plc(
        &self,
        handle: Option<&str>,
        pds_endpoint: &str,
    ) -> Result<(String, PlcOperation)> {
        let genesis_op = PlcOperation::genesis(&self.did_key(), handle, pds_endpoint);

        let did = genesis_op.compute_did()?;
        Ok((did, genesis_op))
    }

    /// Sign a message hash using ECDSA
    pub fn sign_ecdsa(&self, message_hash: &[u8; 32]) -> Result<[u8; 64]> {
        let secp = Secp256k1::new();
        let secret = SecretKey::from_slice(&self.secret_key)
            .map_err(|e| Error::Other(anyhow::anyhow!("Invalid secret key: {}", e)))?;
        let msg = Message::from_digest_slice(message_hash)
            .map_err(|e| Error::Other(anyhow::anyhow!("Invalid message: {}", e)))?;

        let sig = secp.sign_ecdsa(&msg, &secret);
        Ok(sig.serialize_compact())
    }

    /// Sign a repo commit (CAR file root CID)
    pub fn sign_commit(&self, commit: &UnsignedCommit) -> Result<SignedCommit> {
        let commit_bytes = commit.to_cbor()?;
        let mut hasher = Sha256::new();
        hasher.update(&commit_bytes);
        let hash: [u8; 32] = hasher.finalize().into();

        let sig = self.sign_ecdsa(&hash)?;

        Ok(SignedCommit {
            did: commit.did.clone(),
            version: commit.version,
            data: commit.data.clone(),
            rev: commit.rev.clone(),
            prev: commit.prev.clone(),
            sig: hex::encode(sig),
        })
    }
}

/// PLC Operation for did:plc creation/updates
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PlcOperation {
    #[serde(rename = "type")]
    pub op_type: String,
    #[serde(rename = "rotationKeys")]
    pub rotation_keys: Vec<String>,
    #[serde(rename = "verificationMethods")]
    pub verification_methods: VerificationMethods,
    #[serde(rename = "alsoKnownAs")]
    pub also_known_as: Vec<String>,
    pub services: Services,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prev: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VerificationMethods {
    pub atproto: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Services {
    #[serde(rename = "atproto_pds")]
    pub atproto_pds: ServiceEndpoint,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ServiceEndpoint {
    #[serde(rename = "type")]
    pub service_type: String,
    pub endpoint: String,
}

impl PlcOperation {
    /// Create a genesis operation (first operation for a new DID)
    pub fn genesis(signing_key: &str, handle: Option<&str>, pds_endpoint: &str) -> Self {
        let also_known_as = handle
            .map(|h| vec![format!("at://{}", h)])
            .unwrap_or_default();

        Self {
            op_type: "plc_operation".to_string(),
            rotation_keys: vec![signing_key.to_string()],
            verification_methods: VerificationMethods {
                atproto: signing_key.to_string(),
            },
            also_known_as,
            services: Services {
                atproto_pds: ServiceEndpoint {
                    service_type: "AtprotoPersonalDataServer".to_string(),
                    endpoint: pds_endpoint.to_string(),
                },
            },
            prev: None,
        }
    }

    /// Compute the did:plc identifier from this operation
    /// SHA-256 hash, truncated to 120 bits, base32 encoded (lowercase, no padding)
    pub fn compute_did(&self) -> Result<String> {
        let json = serde_json::to_string(self)
            .map_err(|e| Error::Other(anyhow::anyhow!("JSON serialization error: {}", e)))?;

        let mut hasher = Sha256::new();
        hasher.update(json.as_bytes());
        let hash = hasher.finalize();

        // Truncate to 120 bits (15 bytes)
        let truncated = &hash[..15];

        // Base32 encode (lowercase, no padding)
        let encoded = base32_encode_lowercase(truncated);

        Ok(format!("did:plc:{}", encoded))
    }

    /// Serialize to JSON string
    pub fn to_json(&self) -> Result<String> {
        serde_json::to_string(self).map_err(|e| Error::Other(anyhow::anyhow!("JSON error: {}", e)))
    }
}

/// Unsigned repo commit
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UnsignedCommit {
    pub did: String,
    pub version: u32,
    pub data: String,         // CID of MST root
    pub rev: String,          // TID (timestamp ID)
    pub prev: Option<String>, // Previous commit CID
}

impl UnsignedCommit {
    /// Create a new unsigned commit
    pub fn new(did: String, data_cid: String, rev: String, prev: Option<String>) -> Self {
        Self {
            did,
            version: 3,
            data: data_cid,
            rev,
            prev,
        }
    }

    /// Serialize to CBOR bytes (simplified - in real impl would use dag-cbor)
    pub fn to_cbor(&self) -> Result<Vec<u8>> {
        // For cold wallet, we receive pre-serialized commit data
        // This is a simplified representation
        let json = serde_json::to_vec(self)
            .map_err(|e| Error::Other(anyhow::anyhow!("Serialization error: {}", e)))?;
        Ok(json)
    }
}

/// Signed repo commit
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignedCommit {
    pub did: String,
    pub version: u32,
    pub data: String,
    pub rev: String,
    pub prev: Option<String>,
    pub sig: String, // Hex-encoded ECDSA signature
}

impl SignedCommit {
    /// Serialize to JSON
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).expect("serialization should not fail")
    }
}

/// Derive AT Protocol key from seed phrase
///
/// Path: m/44'/29'/account'/0/0
pub fn derive_atproto_key(seed_phrase: &str, account: u32) -> Result<AtProtoKeyPair> {
    use bip39::{Language, Mnemonic, Seed};

    // Parse mnemonic and generate seed
    let mnemonic = Mnemonic::from_phrase(seed_phrase, Language::English)
        .map_err(|e| Error::Other(anyhow::anyhow!("Invalid mnemonic: {}", e)))?;
    let seed = Seed::new(&mnemonic, ""); // No passphrase

    // BIP-44 path: m/44'/29'/account'/0/0
    let path_str = format!("m/44'/{}'/{}'/0/0", COIN_TYPE_ATPROTO, account);
    let path: DerivationPath = path_str
        .parse()
        .map_err(|e| Error::Other(anyhow::anyhow!("Invalid derivation path: {}", e)))?;

    // Derive key
    let xprv = XPrv::derive_from_path(seed.as_bytes(), &path)
        .map_err(|e| Error::Other(anyhow::anyhow!("Key derivation failed: {}", e)))?;

    // Extract secret key
    let mut secret_key = [0u8; 32];
    secret_key.copy_from_slice(&xprv.private_key().to_bytes());

    // Derive compressed public key
    let secp = Secp256k1::new();
    let secret = SecretKey::from_slice(&secret_key)
        .map_err(|e| Error::Other(anyhow::anyhow!("Invalid secret key: {}", e)))?;
    let pubkey = PublicKey::from_secret_key(&secp, &secret);

    let mut public_key = [0u8; 33];
    public_key.copy_from_slice(&pubkey.serialize());

    Ok(AtProtoKeyPair {
        secret_key,
        public_key,
        account,
    })
}

/// Parse AT Protocol derivation path
///
/// Supports:
/// - Full BIP-44 path: m/44'/29'/0'/0/0
/// - Simplified: //atproto//0
pub fn parse_atproto_path(path: &str) -> Result<u32> {
    // Try parsing as full path
    if path.starts_with("m/44'/29'/") {
        let parts: Vec<&str> = path.split('/').collect();
        if parts.len() >= 4 {
            let account = parts[3]
                .trim_end_matches('\'')
                .parse::<u32>()
                .map_err(|_| Error::InvalidDerivation(path.to_string()))?;
            return Ok(account);
        }
    }

    // Simplified path: //atproto//0
    let parts: Vec<&str> = path.split("//").filter(|s| !s.is_empty()).collect();
    let account = parts
        .iter()
        .filter_map(|p| p.parse::<u32>().ok())
        .next()
        .unwrap_or(0);

    Ok(account)
}

/// Base58 encode (Bitcoin alphabet)
fn base58_encode(data: &[u8]) -> String {
    const ALPHABET: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

    // Count leading zeros
    let leading_zeros = data.iter().take_while(|&&b| b == 0).count();

    // Convert to big integer and repeatedly divide by 58
    let mut digits: Vec<u8> = Vec::new();
    for &byte in data {
        let mut carry = byte as u32;
        for digit in digits.iter_mut() {
            carry += (*digit as u32) << 8;
            *digit = (carry % 58) as u8;
            carry /= 58;
        }
        while carry > 0 {
            digits.push((carry % 58) as u8);
            carry /= 58;
        }
    }

    // Add leading '1's for leading zeros
    let mut result = String::with_capacity(leading_zeros + digits.len());
    for _ in 0..leading_zeros {
        result.push('1');
    }

    // Convert digits to characters (reverse order)
    for &digit in digits.iter().rev() {
        result.push(ALPHABET[digit as usize] as char);
    }

    result
}

/// Base32 encode with lowercase alphabet (RFC 4648 without padding)
fn base32_encode_lowercase(data: &[u8]) -> String {
    const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz234567";

    let mut result = String::new();
    let mut buffer: u64 = 0;
    let mut bits_in_buffer = 0;

    for &byte in data {
        buffer = (buffer << 8) | byte as u64;
        bits_in_buffer += 8;

        while bits_in_buffer >= 5 {
            bits_in_buffer -= 5;
            let index = ((buffer >> bits_in_buffer) & 0x1F) as usize;
            result.push(ALPHABET[index] as char);
        }
    }

    // Handle remaining bits
    if bits_in_buffer > 0 {
        let index = ((buffer << (5 - bits_in_buffer)) & 0x1F) as usize;
        result.push(ALPHABET[index] as char);
    }

    result
}

/// Generate a TID (Timestamp ID) for repo commits
/// Format: Base32-sortable encoding of microseconds since Unix epoch
pub fn generate_tid() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};

    let micros = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_micros() as u64;

    // TID is 13 characters of base32-sortable
    // First 53 bits: timestamp in microseconds
    // Last 10 bits: clock sequence (random)
    let clock_seq: u16 = rand_clock_seq();
    let tid_value = (micros << 10) | (clock_seq as u64 & 0x3FF);

    // Base32-sortable encoding (different alphabet than standard base32)
    const TID_ALPHABET: &[u8] = b"234567abcdefghijklmnopqrstuvwxyz";
    let mut result = String::with_capacity(13);
    let mut value = tid_value;

    for _ in 0..13 {
        let index = (value & 0x1F) as usize;
        result.insert(0, TID_ALPHABET[index] as char);
        value >>= 5;
    }

    result
}

/// Simple clock sequence generator (in production, use proper random)
fn rand_clock_seq() -> u16 {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .subsec_nanos();
    (nanos & 0x3FF) as u16
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_atproto_key_derivation() {
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

        let key = derive_atproto_key(mnemonic, 0).unwrap();

        println!("AT Proto public key: {}", key.pubkey_hex());
        println!("AT Proto did:key: {}", key.did_key());

        // did:key should start with did:key:z
        assert!(key.did_key().starts_with("did:key:z"));
        assert_eq!(key.public_key.len(), 33);
    }

    #[test]
    fn test_multiple_accounts() {
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

        let key0 = derive_atproto_key(mnemonic, 0).unwrap();
        let key1 = derive_atproto_key(mnemonic, 1).unwrap();

        assert_ne!(key0.public_key, key1.public_key);

        println!("Account 0 did:key: {}", key0.did_key());
        println!("Account 1 did:key: {}", key1.did_key());
    }

    #[test]
    fn test_did_plc_generation() {
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let key = derive_atproto_key(mnemonic, 0).unwrap();

        let (did, op) = key
            .generate_did_plc(Some("test.bsky.social"), "https://bsky.social")
            .unwrap();

        println!("Generated did:plc: {}", did);
        println!("Genesis operation: {}", op.to_json().unwrap());

        assert!(did.starts_with("did:plc:"));
        assert_eq!(op.op_type, "plc_operation");
    }

    #[test]
    fn test_ecdsa_signing() {
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let key = derive_atproto_key(mnemonic, 0).unwrap();

        // Sign a test message hash
        let message_hash = [0u8; 32];
        let signature = key.sign_ecdsa(&message_hash).unwrap();

        assert_eq!(signature.len(), 64);
        println!("ECDSA signature: {}", hex::encode(signature));
    }

    #[test]
    fn test_commit_signing() {
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let key = derive_atproto_key(mnemonic, 0).unwrap();

        let (did, _) = key.generate_did_plc(None, "https://bsky.social").unwrap();

        let commit = UnsignedCommit::new(
            did.clone(),
            "bafyreiabc123".to_string(),
            generate_tid(),
            None,
        );

        let signed = key.sign_commit(&commit).unwrap();

        println!("Signed commit: {}", signed.to_json());
        assert_eq!(signed.did, did);
        assert!(!signed.sig.is_empty());
    }

    #[test]
    fn test_tid_generation() {
        let tid1 = generate_tid();
        let tid2 = generate_tid();

        println!("TID 1: {}", tid1);
        println!("TID 2: {}", tid2);

        assert_eq!(tid1.len(), 13);
        assert_eq!(tid2.len(), 13);
        // TIDs should be sortable (later > earlier)
        assert!(tid2 >= tid1);
    }

    #[test]
    fn test_parse_atproto_path() {
        // Full path
        let account = parse_atproto_path("m/44'/29'/5'/0/0").unwrap();
        assert_eq!(account, 5);

        // Simplified path
        let account = parse_atproto_path("//atproto//3").unwrap();
        assert_eq!(account, 3);

        // Default account
        let account = parse_atproto_path("//atproto").unwrap();
        assert_eq!(account, 0);
    }

    #[test]
    fn test_base32_encode() {
        // Test vector
        let data = [0x12, 0x34, 0x56, 0x78, 0x9a];
        let encoded = base32_encode_lowercase(&data);
        println!("Base32 encoded: {}", encoded);
        assert!(!encoded.is_empty());
        // Should only contain lowercase letters and digits 2-7
        assert!(encoded
            .chars()
            .all(|c| c.is_ascii_lowercase() || ('2'..='7').contains(&c)));
    }
}
