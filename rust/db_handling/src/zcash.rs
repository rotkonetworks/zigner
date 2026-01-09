//! Zcash key derivation and address management
//! Uses ZIP-32 derivation for Orchard keys

use crate::error::{Error, Result};
use constants::ZCASH_ADDRESS_TREE;
use zeroize::Zeroize;

/// Store Zcash address in database (keyed by FVK identifier hex)
pub fn store_zcash_address(database: &sled::Db, fvk_id_hex: &str, address: &str) -> Result<()> {
    let addresses = database.open_tree(ZCASH_ADDRESS_TREE)?;
    addresses.insert(fvk_id_hex.as_bytes(), address.as_bytes())?;
    Ok(())
}

/// Get Zcash address from database by FVK identifier hex
pub fn get_zcash_address(database: &sled::Db, fvk_id_hex: &str) -> Result<Option<String>> {
    let addresses = database.open_tree(ZCASH_ADDRESS_TREE)?;
    match addresses.get(fvk_id_hex.as_bytes())? {
        Some(bytes) => Ok(Some(
            String::from_utf8(bytes.to_vec())
                .map_err(|e| Error::Other(anyhow::anyhow!("Invalid UTF-8 in stored address: {}", e)))?
        )),
        None => Ok(None),
    }
}

/// Derive Zcash keys from seed phrase
/// Path format: m/32'/133'/account' (ZIP-32 for Orchard)
/// Returns (32-byte FVK identifier for storage, unified address string)
/// Note: The returned identifier is derived from the FVK (Full Viewing Key), not a public key
pub fn derive_zcash_keys(seed_phrase: &str, path: &str, mainnet: bool) -> Result<([u8; 32], String)> {
    // Parse account from path (format: m/32'/133'/account' or just account number)
    let account = parse_account_from_path(path)?;

    // Use the orchard crate for ZIP-32 key derivation
    use orchard::keys::SpendingKey;
    use bip32::Mnemonic;
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
    use zcash_address::unified::{Address as UnifiedAddress, Receiver, Encoding};
    use zcash_address::Network;

    let orchard_receiver = Receiver::Orchard(address.to_raw_address_bytes());
    let network = if mainnet { Network::Main } else { Network::Test };

    let unified_address = UnifiedAddress::try_from_items(vec![orchard_receiver])
        .map_err(|e| Error::Other(anyhow::anyhow!("Failed to create unified address: {e}")))?
        .encode(&network);

    // Store first 32 bytes of FVK (Full Viewing Key) as identifier
    // Note: FVK is private - allows viewing transactions, not a public key
    let fvk_bytes = fvk.to_bytes();
    if fvk_bytes.len() < 32 {
        return Err(Error::Other(anyhow::anyhow!(
            "FVK too short: expected at least 32 bytes, got {}",
            fvk_bytes.len()
        )));
    }
    let mut fvk_id = [0u8; 32];
    fvk_id.copy_from_slice(&fvk_bytes[0..32]);

    // Zeroize sensitive data
    let mut sk_bytes = *sk.to_bytes();
    sk_bytes.zeroize();

    Ok((fvk_id, unified_address))
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
            return account_str.parse::<u32>()
                .map_err(|_| Error::Other(anyhow::anyhow!("Invalid account number in path: {}", path)));
        }
    }

    // If we can't parse the path format, return error - don't silently default
    Err(Error::Other(anyhow::anyhow!(
        "Invalid path format: '{}'. Expected 'm/32'/133'/N' or account number",
        path
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_account_from_path() {
        // Valid formats
        assert_eq!(parse_account_from_path("").unwrap(), 0);
        assert_eq!(parse_account_from_path("0").unwrap(), 0);
        assert_eq!(parse_account_from_path("5").unwrap(), 5);
        assert_eq!(parse_account_from_path("m/32'/133'/0'").unwrap(), 0);
        assert_eq!(parse_account_from_path("m/32'/133'/1'").unwrap(), 1);
        assert_eq!(parse_account_from_path("m/32'/133'/42'").unwrap(), 42);

        // Invalid formats should error, not silently default
        assert!(parse_account_from_path("invalid").is_err());
        assert!(parse_account_from_path("m/32'/133'/").is_err());
        assert!(parse_account_from_path("//polkadot//0").is_err());
    }

    #[test]
    fn test_key_derivation() {
        // Standard 24-word test mnemonic
        let test_mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";

        let (fvk_id, address) = derive_zcash_keys(test_mnemonic, "m/32'/133'/0'", true).unwrap();

        assert_eq!(fvk_id.len(), 32);
        assert!(address.starts_with("u1"));  // Unified address prefix

        println!("Zcash FVK ID: {}", hex::encode(&fvk_id));
        println!("Zcash address: {}", address);
    }

    #[test]
    fn test_different_accounts() {
        // Standard 24-word test mnemonic
        let test_mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";

        let (fvk_id0, addr0) = derive_zcash_keys(test_mnemonic, "m/32'/133'/0'", true).unwrap();
        let (fvk_id1, addr1) = derive_zcash_keys(test_mnemonic, "m/32'/133'/1'", true).unwrap();

        // Different accounts should have different FVK IDs and addresses
        assert_ne!(fvk_id0, fvk_id1);
        assert_ne!(addr0, addr1);
    }
}
