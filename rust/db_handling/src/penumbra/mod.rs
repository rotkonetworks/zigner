//! Penumbra key derivation module
//!
//! Implements Penumbra key derivation based on the ledger-penumbra implementation.
//! Key hierarchy:
//! - SpendKeyBytes (32 bytes) - derived from BIP32 path m/44'/6532'/account'
//! - SpendKey contains: ask (authorization signing key), fvk (full viewing key)
//! - FullViewingKey contains: ak (verification key), nk (nullifier key)
//! - Address derived from FVK with an index

#[cfg(feature = "penumbra")]
pub mod keys;

#[cfg(feature = "penumbra")]
pub mod prf;

#[cfg(feature = "penumbra")]
pub use keys::*;

use constants::PENUMBRA_ADDRS;
use crate::error::Result;

/// Store a Penumbra bech32m address for a given spend verification key (ak)
pub fn store_penumbra_address(database: &sled::Db, ak_hex: &str, bech32m_address: &str) -> Result<()> {
    let tree = database.open_tree(PENUMBRA_ADDRS)?;
    tree.insert(ak_hex.as_bytes(), bech32m_address.as_bytes())?;
    Ok(())
}

/// Retrieve a Penumbra bech32m address for a given spend verification key (ak)
pub fn get_penumbra_address(database: &sled::Db, ak_hex: &str) -> Result<Option<String>> {
    let tree = database.open_tree(PENUMBRA_ADDRS)?;
    match tree.get(ak_hex.as_bytes())? {
        Some(bytes) => {
            let address = String::from_utf8(bytes.to_vec())
                .map_err(|e| crate::error::Error::Other(anyhow::anyhow!("Invalid UTF-8: {}", e)))?;
            Ok(Some(address))
        }
        None => Ok(None),
    }
}
