//! Zcash key derivation and address management
//! Uses ZIP-32 derivation for Orchard keys

use crate::error::{Error, Result};
use constants::{ZCASH_ADDRESS_TREE, ZCASH_NOTES_TREE};
use zeroize::Zeroize;

/// Store Zcash address in database (keyed by public key hex)
pub fn store_zcash_address(database: &sled::Db, pubkey_hex: &str, address: &str) -> Result<()> {
    let addresses = database.open_tree(ZCASH_ADDRESS_TREE)?;
    addresses.insert(pubkey_hex.as_bytes(), address.as_bytes())?;
    Ok(())
}

/// Get Zcash address from database by public key hex
pub fn get_zcash_address(database: &sled::Db, pubkey_hex: &str) -> Result<Option<String>> {
    let addresses = database.open_tree(ZCASH_ADDRESS_TREE)?;
    match addresses.get(pubkey_hex.as_bytes())? {
        Some(bytes) => Ok(Some(String::from_utf8(bytes.to_vec()).map_err(|e| {
            Error::Other(anyhow::anyhow!("Invalid UTF-8 in stored address: {}", e))
        })?)),
        None => Ok(None),
    }
}

/// Derive Zcash keys from seed phrase
/// Path format: m/32'/133'/account' (ZIP-32 for Orchard)
/// Returns (32-byte public key for MultiSigner, unified address string)
pub fn derive_zcash_keys(
    seed_phrase: &str,
    path: &str,
    mainnet: bool,
) -> Result<([u8; 32], String)> {
    // Parse account from path (format: m/32'/133'/account' or just account number)
    let account = parse_account_from_path(path)?;

    // Use the orchard crate for ZIP-32 key derivation
    use bip32::Mnemonic;
    use orchard::keys::SpendingKey;
    use zip32::AccountId;

    // Parse mnemonic
    let mnemonic = Mnemonic::new(seed_phrase, bip32::Language::English)
        .map_err(|e| Error::Other(anyhow::anyhow!("Invalid mnemonic: {e}")))?;

    // Derive seed
    let seed = mnemonic.to_seed("");
    let seed_bytes: &[u8] = seed.as_bytes();

    // Convert account to AccountId
    let account_id = AccountId::try_from(account)
        .map_err(|_| Error::Other(anyhow::anyhow!("Invalid account index")))?;

    // Derive orchard spending key using ZIP-32
    let sk = SpendingKey::from_zip32_seed(seed_bytes, 133, account_id)  // 133 = Zcash coin type
        .map_err(|e| Error::Other(anyhow::anyhow!("Orchard key derivation failed: {e:?}")))?;

    // Get full viewing key
    use orchard::keys::FullViewingKey;
    let fvk = FullViewingKey::from(&sk);

    // Get default address (diversifier index 0)
    let address = fvk.address_at(0u32, orchard::keys::Scope::External);

    // Build unified address with Orchard receiver
    use zcash_address::unified::{Address as UnifiedAddress, Encoding, Receiver};
    use zcash_address::Network;

    let orchard_receiver = Receiver::Orchard(address.to_raw_address_bytes());
    let network = if mainnet {
        Network::Main
    } else {
        Network::Test
    };

    let unified_address = UnifiedAddress::try_from_items(vec![orchard_receiver])
        .map_err(|e| Error::Other(anyhow::anyhow!("Failed to create unified address: {e}")))?
        .encode(&network);

    // Use first 32 bytes of FVK as the "public key" for MultiSigner storage
    let fvk_bytes = fvk.to_bytes();
    let mut pubkey = [0u8; 32];
    pubkey.copy_from_slice(&fvk_bytes[0..32]);

    // Zeroize sensitive data
    let mut sk_bytes = *sk.to_bytes();
    sk_bytes.zeroize();

    Ok((pubkey, unified_address))
}

/// Parse account number from derivation path
/// Supports formats: "m/32'/133'/0'", "0", empty string (defaults to 0)
fn parse_account_from_path(path: &str) -> Result<u32> {
    if path.is_empty() {
        return Ok(0);
    }

    // If it's just a number
    if let Ok(account) = path.parse::<u32>() {
        return Ok(account);
    }

    // Parse ZIP-32 style path: m/32'/133'/account'
    let parts: Vec<&str> = path.split('/').collect();

    // Find the account component (should be after 133')
    for (i, part) in parts.iter().enumerate() {
        if *part == "133'" && i + 1 < parts.len() {
            let account_str = parts[i + 1].trim_end_matches('\'');
            return account_str
                .parse::<u32>()
                .map_err(|_| Error::Other(anyhow::anyhow!("Invalid account in path: {}", path)));
        }
    }

    // Default to account 0 if we can't parse
    Ok(0)
}

// ============================================================================
// Verified note storage (synced via animated QR)
// ============================================================================

/// Stored note value in sled: CBOR-encoded { value, cmx, position, block_height }
/// Key: nullifier (32 bytes)

/// Store verified notes in the database (clear-and-replace model)
///
/// Also stores anchor and height in special keys prefixed with 0xff.
pub fn store_verified_notes(
    database: &sled::Db,
    notes: &[(u64, [u8; 32], [u8; 32], u32, u32)], // (value, nullifier, cmx, position, block_height)
    anchor: &[u8; 32],
    anchor_height: u32,
    mainnet: bool,
) -> Result<()> {
    let tree = database.open_tree(ZCASH_NOTES_TREE)?;

    // Clear existing data
    tree.clear()?;

    // Store anchor metadata under special key
    // Format: anchor(32) + height(4) + mainnet(1) + synced_at(8)
    let synced_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let mut meta = Vec::with_capacity(45);
    meta.extend_from_slice(anchor);
    meta.extend_from_slice(&anchor_height.to_le_bytes());
    meta.push(if mainnet { 1 } else { 0 });
    meta.extend_from_slice(&synced_at.to_le_bytes());
    tree.insert(b"__anchor__", meta.as_slice())?;

    // Store each note keyed by nullifier
    for (value, nullifier, cmx, position, block_height) in notes {
        let mut note_data = Vec::with_capacity(72);
        note_data.extend_from_slice(&value.to_le_bytes()); // 8 bytes
        note_data.extend_from_slice(cmx);                  // 32 bytes
        note_data.extend_from_slice(&position.to_le_bytes()); // 4 bytes
        note_data.extend_from_slice(&block_height.to_le_bytes()); // 4 bytes
        tree.insert(&nullifier[..], note_data.as_slice())?;
    }

    tree.flush()?;
    Ok(())
}

/// Retrieve all verified notes from the database
/// Returns: Vec<(value, nullifier_hex, cmx, position, block_height)>
pub fn get_verified_notes(
    database: &sled::Db,
) -> Result<Vec<(u64, String, [u8; 32], u32, u32)>> {
    let tree = database.open_tree(ZCASH_NOTES_TREE)?;
    let mut notes = Vec::new();

    for entry in tree.iter() {
        let (key, value) = entry?;
        // Skip metadata keys
        if key.as_ref() == b"__anchor__" {
            continue;
        }
        if value.len() < 48 {
            continue;
        }

        let val = u64::from_le_bytes(value[0..8].try_into().unwrap());
        let mut cmx = [0u8; 32];
        cmx.copy_from_slice(&value[8..40]);
        let position = u32::from_le_bytes(value[40..44].try_into().unwrap());
        let block_height = u32::from_le_bytes(value[44..48].try_into().unwrap());
        let nullifier_hex = hex::encode(key.as_ref());

        notes.push((val, nullifier_hex, cmx, position, block_height));
    }

    Ok(notes)
}

/// Get the sum of all verified note values
pub fn get_verified_balance(database: &sled::Db) -> Result<u64> {
    let notes = get_verified_notes(database)?;
    Ok(notes.iter().map(|(value, _, _, _, _)| value).sum())
}

/// Get the stored anchor, height, mainnet flag, and sync timestamp
pub fn get_verified_anchor(database: &sled::Db) -> Result<Option<([u8; 32], u32, bool, u64)>> {
    let tree = database.open_tree(ZCASH_NOTES_TREE)?;
    match tree.get(b"__anchor__")? {
        Some(data) => {
            if data.len() < 37 {
                return Ok(None);
            }
            let mut anchor = [0u8; 32];
            anchor.copy_from_slice(&data[0..32]);
            let height = u32::from_le_bytes(data[32..36].try_into().unwrap());
            let mainnet = data[36] == 1;
            // synced_at was added later; old entries won't have it
            let synced_at = if data.len() >= 45 {
                u64::from_le_bytes(data[37..45].try_into().unwrap())
            } else {
                0
            };
            Ok(Some((anchor, height, mainnet, synced_at)))
        }
        None => Ok(None),
    }
}

/// Clear all zcash notes from the database
pub fn clear_zcash_notes(database: &sled::Db) -> Result<()> {
    let tree = database.open_tree(ZCASH_NOTES_TREE)?;
    tree.clear()?;
    tree.flush()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_account_from_path() {
        assert_eq!(parse_account_from_path("").unwrap(), 0);
        assert_eq!(parse_account_from_path("0").unwrap(), 0);
        assert_eq!(parse_account_from_path("5").unwrap(), 5);
        assert_eq!(parse_account_from_path("m/32'/133'/0'").unwrap(), 0);
        assert_eq!(parse_account_from_path("m/32'/133'/1'").unwrap(), 1);
        assert_eq!(parse_account_from_path("m/32'/133'/42'").unwrap(), 42);
    }

    #[test]
    fn test_key_derivation() {
        // Standard 24-word test mnemonic
        let test_mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";

        let (pubkey, address) = derive_zcash_keys(test_mnemonic, "m/32'/133'/0'", true).unwrap();

        assert_eq!(pubkey.len(), 32);
        assert!(address.starts_with("u1")); // Unified address prefix

        println!("Zcash pubkey: {}", hex::encode(pubkey));
        println!("Zcash address: {}", address);
    }

    #[test]
    fn test_different_accounts() {
        // Standard 24-word test mnemonic
        let test_mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";

        let (pubkey0, addr0) = derive_zcash_keys(test_mnemonic, "m/32'/133'/0'", true).unwrap();
        let (pubkey1, addr1) = derive_zcash_keys(test_mnemonic, "m/32'/133'/1'", true).unwrap();

        // Different accounts should have different keys and addresses
        assert_ne!(pubkey0, pubkey1);
        assert_ne!(addr0, addr1);
    }
}
