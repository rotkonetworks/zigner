//! minimal zcash orchard key derivation for wasm
//!
//! isolated module for browser hot wallet support
//! no substrate deps, no database, just zcash crypto

use wasm_bindgen::prelude::*;
use zeroize::Zeroize;

const ZCASH_COIN_TYPE: u32 = 133;

/// derive zcash orchard address from mnemonic
///
/// returns unified address (u1...) containing orchard receiver
#[wasm_bindgen]
pub fn derive_zcash_address(
    mnemonic: &str,
    account: u32,
    mainnet: bool,
) -> Result<String, JsError> {
    let sk = derive_spending_key(mnemonic, account)?;
    let address = get_address(&sk, mainnet);
    Ok(address)
}

/// derive zcash unified full viewing key (ufvk) from mnemonic
///
/// returns ufvk string (uview1...) for watch-only wallet import
/// includes both orchard and transparent components so watch-only wallets
/// can derive t-addresses
#[wasm_bindgen]
pub fn derive_zcash_ufvk(mnemonic: &str, account: u32, mainnet: bool) -> Result<String, JsError> {
    get_ufvk_with_transparent(mnemonic, account, mainnet)
}

/// derive zcash orchard full viewing key bytes from mnemonic
///
/// returns 96-byte fvk as hex string
#[wasm_bindgen]
pub fn derive_zcash_fvk_bytes(mnemonic: &str, account: u32) -> Result<String, JsError> {
    let sk = derive_spending_key(mnemonic, account)?;
    let fvk_bytes = get_fvk_bytes(&sk);
    Ok(hex::encode(fvk_bytes))
}

/// derive zcash unified address from a UFVK string (uview1... or uviewtest1...)
///
/// used by watch-only wallets (zigner import) to display receive address
#[wasm_bindgen]
pub fn address_from_ufvk(ufvk_str: &str) -> Result<String, JsError> {
    use orchard::keys::FullViewingKey;
    use zcash_address::unified::{
        Address as UnifiedAddress, Container, Encoding, Fvk, Receiver, Ufvk,
    };

    // detect network from UFVK prefix
    let (network, parsed) =
        Ufvk::decode(ufvk_str).map_err(|e| JsError::new(&format!("invalid ufvk: {}", e)))?;

    // extract orchard FVK bytes from the parsed UFVK
    let orchard_fvk_bytes = parsed
        .items_as_parsed()
        .iter()
        .find_map(|item| {
            if let Fvk::Orchard(bytes) = item {
                Some(*bytes)
            } else {
                None
            }
        })
        .ok_or_else(|| JsError::new("ufvk does not contain orchard component"))?;

    // reconstruct FullViewingKey from bytes and derive address
    let fvk = FullViewingKey::from_bytes(&orchard_fvk_bytes)
        .ok_or_else(|| JsError::new("invalid orchard fvk bytes in ufvk"))?;

    let addr = fvk.address_at(0u32, orchard::keys::Scope::External);
    let receiver = Receiver::Orchard(addr.to_raw_address_bytes());

    let ua = UnifiedAddress::try_from_items(vec![receiver])
        .map_err(|e| JsError::new(&format!("failed to build address: {}", e)))?;

    Ok(ua.encode(&network))
}

// === internal helpers ===

#[derive(Zeroize)]
#[zeroize(drop)]
struct SpendingKeyBytes([u8; 32]);

fn derive_spending_key(mnemonic: &str, account: u32) -> Result<SpendingKeyBytes, JsError> {
    use bip32::Mnemonic;
    use orchard::keys::SpendingKey;
    use zip32::AccountId;

    let mnemonic = Mnemonic::new(mnemonic, bip32::Language::English)
        .map_err(|e| JsError::new(&format!("invalid mnemonic: {}", e)))?;

    let seed = mnemonic.to_seed("");
    let seed_bytes: &[u8] = seed.as_bytes();

    let account_id =
        AccountId::try_from(account).map_err(|_| JsError::new("invalid account index"))?;

    let sk = SpendingKey::from_zip32_seed(seed_bytes, ZCASH_COIN_TYPE, account_id)
        .map_err(|e| JsError::new(&format!("key derivation failed: {:?}", e)))?;

    Ok(SpendingKeyBytes(*sk.to_bytes()))
}

fn get_fvk_bytes(sk: &SpendingKeyBytes) -> [u8; 96] {
    use orchard::keys::FullViewingKey;
    let orchard_sk = orchard::keys::SpendingKey::from_bytes(sk.0)
        .into_option()
        .expect("valid spending key");
    let fvk = FullViewingKey::from(&orchard_sk);
    fvk.to_bytes()
}

fn get_address(sk: &SpendingKeyBytes, mainnet: bool) -> String {
    use orchard::keys::FullViewingKey;
    use zcash_address::unified::{Address as UnifiedAddress, Encoding, Receiver};
    use zcash_address::Network;

    let orchard_sk = orchard::keys::SpendingKey::from_bytes(sk.0)
        .into_option()
        .expect("valid spending key");
    let fvk = FullViewingKey::from(&orchard_sk);
    let addr = fvk.address_at(0u32, orchard::keys::Scope::External);

    let receiver = Receiver::Orchard(addr.to_raw_address_bytes());
    let network = if mainnet {
        Network::Main
    } else {
        Network::Test
    };

    UnifiedAddress::try_from_items(vec![receiver])
        .expect("valid receiver")
        .encode(&network)
}

fn get_ufvk(sk: &SpendingKeyBytes, mainnet: bool) -> String {
    use orchard::keys::FullViewingKey;
    use zcash_address::unified::{Encoding, Fvk, Ufvk};
    use zcash_address::Network;

    let orchard_sk = orchard::keys::SpendingKey::from_bytes(sk.0)
        .into_option()
        .expect("valid spending key");
    let fvk = FullViewingKey::from(&orchard_sk);

    let orchard_fvk = Fvk::Orchard(fvk.to_bytes());
    let network = if mainnet {
        Network::Main
    } else {
        Network::Test
    };

    Ufvk::try_from_items(vec![orchard_fvk])
        .expect("valid fvk")
        .encode(&network)
}

/// Build UFVK with both orchard and transparent components from mnemonic seed.
/// The transparent component allows watch-only wallets to derive t-addresses.
fn get_ufvk_with_transparent(
    mnemonic_str: &str,
    account: u32,
    mainnet: bool,
) -> Result<String, JsError> {
    use orchard::keys::FullViewingKey;
    use zcash_address::unified::{Encoding, Fvk, Ufvk};
    use zcash_address::Network;

    let mnemonic = bip32::Mnemonic::new(mnemonic_str, bip32::Language::English)
        .map_err(|e| JsError::new(&format!("invalid mnemonic: {}", e)))?;
    let seed = mnemonic.to_seed("");
    let seed_bytes: &[u8] = seed.as_bytes();

    // orchard FVK
    let account_id =
        zip32::AccountId::try_from(account).map_err(|_| JsError::new("invalid account index"))?;
    let orchard_sk =
        orchard::keys::SpendingKey::from_zip32_seed(seed_bytes, ZCASH_COIN_TYPE, account_id)
            .map_err(|e| JsError::new(&format!("orchard key derivation failed: {:?}", e)))?;
    let fvk = FullViewingKey::from(&orchard_sk);
    let orchard_fvk = Fvk::Orchard(fvk.to_bytes());

    // transparent account pubkey: derive m/44'/133'/account'
    let root_xprv = bip32::XPrv::new(seed_bytes)
        .map_err(|e| JsError::new(&format!("bip32 root key failed: {}", e)))?;
    let purpose = bip32::ChildNumber::new(44, true)
        .map_err(|e| JsError::new(&format!("bip32 purpose: {}", e)))?;
    let coin_type = bip32::ChildNumber::new(ZCASH_COIN_TYPE, true)
        .map_err(|e| JsError::new(&format!("bip32 coin_type: {}", e)))?;
    let account_child = bip32::ChildNumber::new(account, true)
        .map_err(|e| JsError::new(&format!("bip32 account: {}", e)))?;

    let account_xprv = root_xprv
        .derive_child(purpose)
        .and_then(|k| k.derive_child(coin_type))
        .and_then(|k| k.derive_child(account_child))
        .map_err(|e| JsError::new(&format!("bip32 derivation failed: {}", e)))?;

    let account_xpub = bip32::XPub::from(&account_xprv);

    // Fvk::P2pkh is 65 bytes: chain_code (32) + compressed_pubkey (33)
    let mut p2pkh_data = [0u8; 65];
    p2pkh_data[..32].copy_from_slice(&account_xpub.attrs().chain_code);
    use bip32::PublicKey as _;
    let pubkey_bytes = account_xpub.public_key().to_bytes();
    p2pkh_data[32..65].copy_from_slice(&pubkey_bytes);

    let transparent_fvk = Fvk::P2pkh(p2pkh_data);

    let network = if mainnet {
        Network::Main
    } else {
        Network::Test
    };

    let ufvk = Ufvk::try_from_items(vec![orchard_fvk, transparent_fvk])
        .map_err(|e| JsError::new(&format!("failed to build UFVK: {}", e)))?;

    Ok(ufvk.encode(&network))
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";

    #[test]
    fn test_derive_address() {
        let addr = derive_zcash_address(TEST_MNEMONIC, 0, true).unwrap();
        assert!(addr.starts_with("u1"));
    }

    #[test]
    fn test_derive_ufvk() {
        let ufvk = derive_zcash_ufvk(TEST_MNEMONIC, 0, true).unwrap();
        assert!(ufvk.starts_with("uview"));
    }

    #[test]
    fn test_derive_fvk_bytes() {
        let fvk_hex = derive_zcash_fvk_bytes(TEST_MNEMONIC, 0).unwrap();
        assert_eq!(fvk_hex.len(), 192); // 96 bytes = 192 hex chars
    }

    #[test]
    fn test_address_from_ufvk() {
        // derive ufvk and address from mnemonic, then verify address_from_ufvk matches
        let ufvk = derive_zcash_ufvk(TEST_MNEMONIC, 0, true).unwrap();
        let expected_addr = derive_zcash_address(TEST_MNEMONIC, 0, true).unwrap();
        let addr = address_from_ufvk(&ufvk).unwrap();
        assert_eq!(addr, expected_addr);
    }

    #[test]
    fn test_address_from_ufvk_testnet() {
        let ufvk = derive_zcash_ufvk(TEST_MNEMONIC, 0, false).unwrap();
        let expected_addr = derive_zcash_address(TEST_MNEMONIC, 0, false).unwrap();
        let addr = address_from_ufvk(&ufvk).unwrap();
        assert_eq!(addr, expected_addr);
    }
}
