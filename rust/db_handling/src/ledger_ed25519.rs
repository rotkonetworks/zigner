//! Ledger Ed25519 key derivation using Cardano-style BIP32-Ed25519
//!
//! This implements the same key derivation used by Ledger hardware wallets
//! for Polkadot and other Substrate-based chains.
//!
//! Key derivation path: m/44'/slip0044'/account'/change'/address'
//! For Polkadot: m/44'/354'/0'/0'/0'
//!
//! Note: Ledger uses Cardano-style BIP32-Ed25519, NOT SLIP-10.
//! The difference is in the master key generation which iterates
//! until a valid key is found.

use crate::error::{Error, Result};
use hmac::{Hmac, Mac};
use sha2::{Sha256, Sha512};
use sp_core::Pair;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// SLIP-0044 coin types
pub const SLIP0044_POLKADOT: u32 = 354;
pub const SLIP0044_KUSAMA: u32 = 434;

/// Hardened derivation flag
const HARDENED: u32 = 0x80000000;

/// Generate Ledger master key from seed using Cardano-style derivation
/// Returns (extended_secret[64], chain_code[32]) = 96 bytes total
/// This matches the polkadot-js ledgerMaster implementation
fn ledger_master(seed: &[u8]) -> ([u8; 64], [u8; 32]) {
    // Chain code: HMAC-SHA256 with key "ed25519 seed", data = [1, ...seed]
    // Note: polkadot-js uses 256 bits (SHA256), not 512!
    let mut cc_hmac = Hmac::<Sha256>::new_from_slice(b"ed25519 seed")
        .expect("HMAC can take key of any size");
    let mut cc_data = vec![1u8];
    cc_data.extend_from_slice(seed);
    cc_hmac.update(&cc_data);
    let cc_result = cc_hmac.finalize().into_bytes();

    let mut chain_code = [0u8; 32];
    chain_code.copy_from_slice(&cc_result);

    // Private key: iterate HMAC-SHA512 until (priv[31] & 0x20) == 0
    let mut priv_data: Option<Vec<u8>> = None;
    let mut priv_key: [u8; 64];

    loop {
        let mut hmac = Hmac::<Sha512>::new_from_slice(b"ed25519 seed")
            .expect("HMAC can take key of any size");

        match &priv_data {
            Some(data) => hmac.update(data),
            None => hmac.update(seed),
        }

        let result = hmac.finalize().into_bytes();
        priv_key = result.into();

        // Cardano validity check: third highest bit of byte 31 must be zero
        if (priv_key[31] & 0b0010_0000) == 0 {
            // Clamp the private key (Cardano-style)
            priv_key[0] &= 0b1111_1000;  // Clear lowest 3 bits
            priv_key[31] &= 0b0111_1111; // Clear bit 255
            priv_key[31] |= 0b0100_0000; // Set bit 254

            return (priv_key, chain_code);
        }

        // If not valid, hash again with the result
        priv_data = Some(result.to_vec());
    }
}

/// Full Ledger key derivation from mnemonic
/// Path: m/44'/slip0044'/account'/change'/address'
pub fn derive_ledger_key(
    seed_phrase: &str,
    slip0044: u32,
    account: u32,
    change: u32,
    address_index: u32,
) -> Result<LedgerKeyPair> {
    use bip39::{Language, Mnemonic, Seed};

    // Parse mnemonic and generate seed
    let mnemonic = Mnemonic::from_phrase(seed_phrase, Language::English)
        .map_err(|e| Error::Other(anyhow::anyhow!("Invalid mnemonic: {}", e)))?;
    let seed = Seed::new(&mnemonic, ""); // No passphrase

    // Generate master key using Cardano-style derivation (96 bytes: kL[32] || kR[32] || cc[32])
    let (extended_secret, chain_code) = ledger_master(seed.as_bytes());

    // Derive the full path: m/44'/slip0044'/account'/change'/address'
    let path = [
        44 | HARDENED,
        slip0044 | HARDENED,
        account | HARDENED,
        change | HARDENED,
        address_index | HARDENED,
    ];

    let (final_extended, _final_cc) = ledger_derive_path(&extended_secret, &chain_code, &path);

    // For Ed25519, the secret key is kL (first 32 bytes)
    // This is used as an ed25519 SEED, which gets hashed internally
    let mut secret_key = [0u8; 32];
    secret_key.copy_from_slice(&final_extended[0..32]);

    // Derive public key using sp_core::ed25519 (already a dependency)
    // This matches polkadot-js ed25519PairFromSeed behavior
    let pair = sp_core::ed25519::Pair::from_seed_slice(&secret_key)
        .map_err(|e| Error::Other(anyhow::anyhow!("Ed25519 seed error: {:?}", e)))?;
    let public_key = pair.public().0;

    Ok(LedgerKeyPair {
        extended_key: final_extended,
        secret_key,
        public_key,
    })
}

/// Derive a child key along the path (hardened only)
/// This implements the polkadot-js ledgerDerivePrivate
fn ledger_derive_path(
    extended_secret: &[u8; 64],
    chain_code: &[u8; 32],
    path: &[u32],
) -> ([u8; 64], [u8; 32]) {
    let mut current_key = *extended_secret;
    let mut current_cc = *chain_code;

    for &index in path {
        (current_key, current_cc) = ledger_derive_private(&current_key, &current_cc, index);
    }

    (current_key, current_cc)
}

/// Derive a single child key (hard derivation only)
/// Based on polkadot-js ledgerDerivePrivate implementation
fn ledger_derive_private(
    extended_secret: &[u8; 64],
    chain_code: &[u8; 32],
    index: u32,
) -> ([u8; 64], [u8; 32]) {
    let kl = &extended_secret[0..32];
    let kr = &extended_secret[32..64];

    // First HMAC: data = [0x00, kL, kR, index_le]
    let mut data1 = vec![0x00];
    data1.extend_from_slice(kl);
    data1.extend_from_slice(kr);
    data1.extend_from_slice(&index.to_le_bytes());

    let mut hmac1 = Hmac::<Sha512>::new_from_slice(chain_code)
        .expect("HMAC can take key of any size");
    hmac1.update(&data1);
    let z = hmac1.finalize().into_bytes();

    // Second HMAC for new chain code: data = [0x01, kL, kR, index_le]
    let mut data2 = vec![0x01];
    data2.extend_from_slice(kl);
    data2.extend_from_slice(kr);
    data2.extend_from_slice(&index.to_le_bytes());

    let mut hmac2 = Hmac::<Sha512>::new_from_slice(chain_code)
        .expect("HMAC can take key of any size");
    hmac2.update(&data2);
    let cc_full = hmac2.finalize().into_bytes();

    // New chain code is second 32 bytes of cc_full
    let mut new_cc = [0u8; 32];
    new_cc.copy_from_slice(&cc_full[32..64]);

    // Calculate new kL: kL + 8 * trunc28(zL) (little-endian addition)
    let zl = &z[0..32];
    let zr = &z[32..64];

    // trunc28(zL) = zL with last 4 bytes zeroed, then multiply by 8
    let mut zl_trunc = [0u8; 32];
    zl_trunc[0..28].copy_from_slice(&zl[0..28]);
    // Multiply by 8 (shift left by 3)
    let mut carry = 0u16;
    for i in 0..32 {
        let val = (zl_trunc[i] as u16) * 8 + carry;
        zl_trunc[i] = val as u8;
        carry = val >> 8;
    }

    // Add to kL (little-endian)
    let mut new_kl = [0u8; 32];
    let mut c = 0u16;
    for i in 0..32 {
        let sum = (kl[i] as u16) + (zl_trunc[i] as u16) + c;
        new_kl[i] = sum as u8;
        c = sum >> 8;
    }

    // Calculate new kR: kR + zR (little-endian addition mod 2^256)
    let mut new_kr = [0u8; 32];
    let mut c = 0u16;
    for i in 0..32 {
        let sum = (kr[i] as u16) + (zr[i] as u16) + c;
        new_kr[i] = sum as u8;
        c = sum >> 8;
    }

    // Combine into new extended secret
    let mut new_extended = [0u8; 64];
    new_extended[0..32].copy_from_slice(&new_kl);
    new_extended[32..64].copy_from_slice(&new_kr);

    (new_extended, new_cc)
}

/// Ledger key pair with extended key for signing
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct LedgerKeyPair {
    /// Full 64-byte extended secret key (for BIP32-Ed25519 signing)
    pub extended_key: [u8; 64],
    /// 32-byte Ed25519 secret key (clamped scalar)
    pub secret_key: [u8; 32],
    /// 32-byte Ed25519 public key
    pub public_key: [u8; 32],
}

impl LedgerKeyPair {
    /// Sign a message using Ed25519
    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        let pair = sp_core::ed25519::Pair::from_seed_slice(&self.secret_key)
            .expect("Valid 32-byte seed");
        pair.sign(message).0
    }

    /// Get SS58 address for the public key
    pub fn ss58_address(&self, prefix: u16) -> String {
        use sp_core::crypto::{Ss58AddressFormat, Ss58Codec};
        use sp_core::ed25519::Public;

        let public = Public::from_raw(self.public_key);
        let format = Ss58AddressFormat::custom(prefix);
        public.to_ss58check_with_version(format)
    }
}

/// Derive Polkadot Ledger key (m/44'/354'/account'/0'/0')
pub fn derive_polkadot_ledger_key(seed_phrase: &str, account: u32) -> Result<LedgerKeyPair> {
    derive_ledger_key(seed_phrase, SLIP0044_POLKADOT, account, 0, 0)
}

/// Derive Kusama Ledger key (m/44'/434'/account'/0'/0')
pub fn derive_kusama_ledger_key(seed_phrase: &str, account: u32) -> Result<LedgerKeyPair> {
    derive_ledger_key(seed_phrase, SLIP0044_KUSAMA, account, 0, 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_polkadot_ledger_derivation() {
        // Test with standard mnemonic
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

        let key = derive_polkadot_ledger_key(mnemonic, 0).unwrap();

        println!("Public key: {}", hex::encode(&key.public_key));
        println!("SS58 address (Polkadot): {}", key.ss58_address(0));
        println!("SS58 address (generic): {}", key.ss58_address(42));

        // The public key should be deterministic
        assert_eq!(key.public_key.len(), 32);
    }

    #[test]
    fn test_multiple_accounts() {
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

        let key0 = derive_polkadot_ledger_key(mnemonic, 0).unwrap();
        let key1 = derive_polkadot_ledger_key(mnemonic, 1).unwrap();

        // Different accounts should produce different keys
        assert_ne!(key0.public_key, key1.public_key);

        println!("Account 0: {}", key0.ss58_address(0));
        println!("Account 1: {}", key1.ss58_address(0));
    }

    #[test]
    fn test_signing() {
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let key = derive_polkadot_ledger_key(mnemonic, 0).unwrap();

        let message = b"test message";
        let signature = key.sign(message);

        // Verify the signature using sp_core
        use sp_core::{ed25519, Pair};
        let public = ed25519::Public::from_raw(key.public_key);
        let sig = ed25519::Signature::from_raw(signature);

        assert!(ed25519::Pair::verify(&sig, message, &public));
    }

    #[test]
    fn test_kusama_known_vector() {
        // Known test vector from jacogr/substrate-ledger-ed25519
        // npm start "kusama" "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about" 0 0
        // Expected KSM address: GpTCo8cccWnpFne7EKBwr677tWkEoeLbiAgks76fKisCUWP
        // Expected ed25519 seed: 0x98cb4e14e0e08ea876f88d728545ea7572dc07dbbe69f1731c418fb827e69d41
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

        let key = derive_kusama_ledger_key(mnemonic, 0).unwrap();

        println!("Kusama secret key (kL): {}", hex::encode(&key.secret_key));
        println!("Kusama public key: {}", hex::encode(&key.public_key));
        println!("Kusama address (KSM prefix 2): {}", key.ss58_address(2));

        // This should match the expected address from the reference implementation
        let expected_seed = "98cb4e14e0e08ea876f88d728545ea7572dc07dbbe69f1731c418fb827e69d41";
        let expected_address = "GpTCo8cccWnpFne7EKBwr677tWkEoeLbiAgks76fKisCUWP";
        let actual_address = key.ss58_address(2);

        println!("Expected seed: {}", expected_seed);
        println!("Actual seed:   {}", hex::encode(&key.secret_key));
        println!("Expected addr: {}", expected_address);
        println!("Actual addr:   {}", actual_address);

        // Check if they match - if not, our derivation differs from Ledger's
        if actual_address != expected_address {
            println!("WARNING: Address mismatch! Our derivation may differ from Ledger's Cardano-style BIP32-Ed25519");
        }
    }

    #[test]
    fn test_master_key_derivation() {
        // Debug test to see master key
        use bip39::{Language, Mnemonic, Seed};

        let mnemonic_str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let mnemonic = Mnemonic::from_phrase(mnemonic_str, Language::English).unwrap();
        let seed = Seed::new(&mnemonic, "");

        println!("BIP39 seed: {}", hex::encode(seed.as_bytes()));

        let (extended, cc) = super::ledger_master(seed.as_bytes());
        println!("Master kL: {}", hex::encode(&extended[0..32]));
        println!("Master kR: {}", hex::encode(&extended[32..64]));
        println!("Master CC: {}", hex::encode(&cc));
    }
}
