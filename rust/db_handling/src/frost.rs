//! FROST multisig key package storage
//!
//! Stores key shares from DKG so zigner can participate in threshold signing.
//! Key: wallet_id (8 bytes, truncated blake3 of public_key_package hex).
//! Value: JSON-encoded FrostWalletData.

use crate::error::{Error, Result};
use constants::FROST_KEYS_TREE;

/// Data stored per FROST wallet
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FrostWalletData {
    pub key_package_hex: String,
    pub public_key_package_hex: String,
    pub ephemeral_seed_hex: String,
    pub label: String,
    pub min_signers: u16,
    pub max_signers: u16,
    pub mainnet: bool,
    pub created_at: u64,
}

/// Summary for listing wallets (no secrets)
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FrostWalletSummary {
    pub wallet_id: String,
    pub label: String,
    pub min_signers: u16,
    pub max_signers: u16,
    pub mainnet: bool,
    pub created_at: u64,
}

/// Compute wallet_id from public_key_package hex (first 8 bytes of simple hash)
fn wallet_id_bytes(public_key_package_hex: &str) -> [u8; 8] {
    // Simple FNV-1a inspired hash, producing 8 stable bytes from the hex string.
    // Not cryptographic — just a deterministic key for sled lookup.
    let mut h: u64 = 0xcbf29ce484222325;
    for &b in public_key_package_hex.as_bytes() {
        h ^= b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h.to_le_bytes()
}

pub fn wallet_id_hex(public_key_package_hex: &str) -> String {
    hex::encode(wallet_id_bytes(public_key_package_hex))
}

/// Store a FROST wallet after DKG completion.
/// Also sets the sticky attestation-required flag — once a FROST wallet exists,
/// anchor attestation is required for all future note syncs, even if the wallet
/// is later deleted.
pub fn store_frost_wallet(database: &sled::Db, data: &FrostWalletData) -> Result<String> {
    let tree = database.open_tree(FROST_KEYS_TREE)?;
    let id = wallet_id_bytes(&data.public_key_package_hex);
    let json = serde_json::to_vec(data)
        .map_err(|e| Error::Other(anyhow::anyhow!("FROST serialize: {e}")))?;
    tree.insert(&id, json.as_slice())?;
    tree.flush()?;

    // Set sticky flag: attestation now required permanently
    crate::zcash::set_attestation_required(database)?;

    Ok(hex::encode(id))
}

/// Get a FROST wallet by id (hex string)
pub fn get_frost_wallet(
    database: &sled::Db,
    wallet_id_hex: &str,
) -> Result<Option<FrostWalletData>> {
    let tree = database.open_tree(FROST_KEYS_TREE)?;
    let id = hex::decode(wallet_id_hex)
        .map_err(|e| Error::Other(anyhow::anyhow!("bad wallet id hex: {e}")))?;
    match tree.get(&id)? {
        Some(bytes) => {
            let data: FrostWalletData = serde_json::from_slice(&bytes)
                .map_err(|e| Error::Other(anyhow::anyhow!("FROST deserialize: {e}")))?;
            Ok(Some(data))
        }
        None => Ok(None),
    }
}

/// List all stored FROST wallets (summaries only, no secrets)
pub fn list_frost_wallets(database: &sled::Db) -> Result<Vec<FrostWalletSummary>> {
    let tree = database.open_tree(FROST_KEYS_TREE)?;
    let mut wallets = Vec::new();
    for entry in tree.iter() {
        let (key, value) = entry?;
        let data: FrostWalletData = serde_json::from_slice(&value)
            .map_err(|e| Error::Other(anyhow::anyhow!("FROST deserialize: {e}")))?;
        wallets.push(FrostWalletSummary {
            wallet_id: hex::encode(key.as_ref()),
            label: data.label,
            min_signers: data.min_signers,
            max_signers: data.max_signers,
            mainnet: data.mainnet,
            created_at: data.created_at,
        });
    }
    Ok(wallets)
}

/// Delete a FROST wallet by id
pub fn delete_frost_wallet(database: &sled::Db, wallet_id_hex: &str) -> Result<()> {
    let tree = database.open_tree(FROST_KEYS_TREE)?;
    let id = hex::decode(wallet_id_hex)
        .map_err(|e| Error::Other(anyhow::anyhow!("bad wallet id hex: {e}")))?;
    tree.remove(&id)?;
    tree.flush()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wallet_id_deterministic() {
        let id1 = wallet_id_hex("abcdef1234");
        let id2 = wallet_id_hex("abcdef1234");
        assert_eq!(id1, id2);
        assert_eq!(id1.len(), 16); // 8 bytes = 16 hex chars
    }

    #[test]
    fn test_store_and_retrieve() {
        let db = sled::Config::new().temporary(true).open().unwrap();
        let data = FrostWalletData {
            key_package_hex: "aabb".to_string(),
            public_key_package_hex: "ccdd".to_string(),
            ephemeral_seed_hex: "eeff".to_string(),
            label: "test 2-of-3".to_string(),
            min_signers: 2,
            max_signers: 3,
            mainnet: true,
            created_at: 1234567890,
        };
        let id = store_frost_wallet(&db, &data).unwrap();
        let retrieved = get_frost_wallet(&db, &id).unwrap().unwrap();
        assert_eq!(retrieved.label, "test 2-of-3");
        assert_eq!(retrieved.min_signers, 2);

        let list = list_frost_wallets(&db).unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].wallet_id, id);

        delete_frost_wallet(&db, &id).unwrap();
        assert!(get_frost_wallet(&db, &id).unwrap().is_none());
    }
}
