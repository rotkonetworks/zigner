//! Database key types
//!
//! Cold database trees and their keys:
//!
//! - `SPECSTREE`, network specs `OrderedNetworkSpecs` entries, with keys
//!   [`NetworkSpecsKey`]
//! - `ADDRTREE`, [`AddressDetails`](crate::users::AddressDetails) entries
//!   with public information associated with user addresses, with keys
//!   [`AddressKey`]
//! - `SETTREE`, danger status and database schema version
//! - `HISTORY`, [`Entry`](crate::history::Entry) log of all events
//!   happening in Vault, with keys [`Order`]
//!
//! Databases from before Substrate signing was removed also hold `METATREE`,
//! `VERIFIERS` and `TRANSACTION`, and `TYPES` / `GENERALVERIFIER` entries in
//! `SETTREE`. Nothing reads them.
use parity_scale_codec::{Decode, Encode};
use sled::IVec;
use sp_core::H256;
use sp_runtime::MultiSigner;

use crate::helpers::{get_multisigner, unhex};
use crate::{crypto::Encryption, error::Result};

/// Key in `SPECSTREE` tree (cold database) and in `SPECSPREPTREE` (hot database)  
///
/// [`NetworkSpecsKey`] is used to retrieve the
/// [`OrderedNetworkSpecs`](crate::network_specs::OrderedNetworkSpecs) in cold database and
/// [`NetworkSpecs`](crate::network_specs::NetworkSpecs) in hot
/// database.  
///
/// Key is derived from network genesis hash and encryption algorithm.  
///
/// Network could support more than one encryption algorithm. In this case
/// there would be more than one database entry with different
/// [`NetworkSpecsKey`] values. Such entries do not conflict.  
#[derive(Decode, Hash, Encode, PartialEq, Eq, Debug, Clone)]
pub struct NetworkSpecsKey(Vec<u8>);

/// Decoded `NetworkSpecsKey` content, encryption-based variants with vector
/// genesis hash inside
#[derive(Decode, Encode)]
enum NetworkSpecsKeyContent {
    Ed25519(H256),
    Sr25519(H256),
    Ecdsa(H256),
    Ethereum(H256),
    Penumbra(H256),
    Zcash(H256),
    LedgerEd25519(H256),
    Cosmos(H256),
    Bitcoin(H256),
    Nostr(H256),
    AtProtocol(H256),
}

impl NetworkSpecsKey {
    /// Generate [`NetworkSpecsKey`] from parts: network genesis hash and
    /// [`Encryption`]
    pub fn from_parts(genesis_hash: &H256, encryption: &Encryption) -> Self {
        let network_key_content = match encryption {
            Encryption::Ed25519 => NetworkSpecsKeyContent::Ed25519(*genesis_hash),
            Encryption::Sr25519 => NetworkSpecsKeyContent::Sr25519(*genesis_hash),
            Encryption::Ecdsa => NetworkSpecsKeyContent::Ecdsa(*genesis_hash),
            Encryption::Ethereum => NetworkSpecsKeyContent::Ethereum(*genesis_hash),
            Encryption::Penumbra => NetworkSpecsKeyContent::Penumbra(*genesis_hash),
            Encryption::Zcash => NetworkSpecsKeyContent::Zcash(*genesis_hash),
            Encryption::LedgerEd25519 => NetworkSpecsKeyContent::LedgerEd25519(*genesis_hash),
            Encryption::Cosmos => NetworkSpecsKeyContent::Cosmos(*genesis_hash),
            Encryption::Bitcoin => NetworkSpecsKeyContent::Bitcoin(*genesis_hash),
            Encryption::Nostr => NetworkSpecsKeyContent::Nostr(*genesis_hash),
            Encryption::AtProtocol => NetworkSpecsKeyContent::AtProtocol(*genesis_hash),
        };
        Self(network_key_content.encode())
    }

    /// Transform database `IVec` key into [`NetworkSpecsKey`] prior to processing  
    ///
    /// Infallible, no check of encryption validity is done here.
    pub fn from_ivec(ivec: &IVec) -> Self {
        Self(ivec.to_vec())
    }

    /// Transform hexadecimal `String` into [`NetworkSpecsKey`]  
    ///
    /// Vault receives hexadecimal strings from user interface.
    ///
    /// This function checks only that hexadecimal format is valid, no check
    /// of encryption validity is done here.  
    pub fn from_hex(hex_line: &str) -> Result<Self> {
        Ok(Self(unhex(hex_line)?))
    }

    /// Get genesis hash as `H256` and [`Encryption`] from [`NetworkSpecsKey`]
    pub fn genesis_hash_encryption(&self) -> Result<(H256, Encryption)> {
        match <NetworkSpecsKeyContent>::decode(&mut &self.0[..])? {
            NetworkSpecsKeyContent::Ed25519(b) => Ok((b, Encryption::Ed25519)),
            NetworkSpecsKeyContent::Sr25519(b) => Ok((b, Encryption::Sr25519)),
            NetworkSpecsKeyContent::Ecdsa(b) => Ok((b, Encryption::Ecdsa)),
            NetworkSpecsKeyContent::Ethereum(b) => Ok((b, Encryption::Ethereum)),
            NetworkSpecsKeyContent::Penumbra(b) => Ok((b, Encryption::Penumbra)),
            NetworkSpecsKeyContent::Zcash(b) => Ok((b, Encryption::Zcash)),
            NetworkSpecsKeyContent::LedgerEd25519(b) => Ok((b, Encryption::LedgerEd25519)),
            NetworkSpecsKeyContent::Cosmos(b) => Ok((b, Encryption::Cosmos)),
            NetworkSpecsKeyContent::Bitcoin(b) => Ok((b, Encryption::Bitcoin)),
            NetworkSpecsKeyContent::Nostr(b) => Ok((b, Encryption::Nostr)),
            NetworkSpecsKeyContent::AtProtocol(b) => Ok((b, Encryption::AtProtocol)),
        }
    }

    /// Transform [`NetworkSpecsKey`] into `Vec<u8>` database key  
    pub fn key(&self) -> Vec<u8> {
        self.0.to_vec()
    }
}

/// Key in `ADDRTREE` tree (cold database)  
///
/// [`AddressKey`] is used to retrieve the address associated public information.  
///
/// Key is derived from public key and encryption algorithm.  
///
/// To create an address in Vault, sufficient information is:
///
/// - seed phrase  
/// - derivation: soft (`/`) and hard (`//`) junctions and password (`///`)  
/// - encryption algorithm  
/// - network for address to be used with (network must support the encryption
///   algorithm)  
///
/// The seed phrase and password are **not** stored in rust-managed database.
/// For storing seed phrases, Vault device's own key management system is used.
/// Passwords are never stored.  
/// Cold database stores only **non-secret** address associated information.  
///
/// Each address is defined by combination of public key, encryption algorithm,
/// and network.  
///
/// More than one address could be created for same seed phrase and derivation,
/// with same encryption algorithm, but for different networks.
///
/// For the user interface these addresses would appear as separate entities,
/// however, the database stores them under same [`AddressKey`], with a set of
/// allowed networks.  
#[derive(Decode, Encode, Debug, PartialEq, Eq, Clone)]
pub struct AddressKey {
    multisigner: MultiSigner,
    /// the root address is not used on any network and hence has no genesis hash.
    genesis_hash: Option<H256>,
}

impl AddressKey {
    /// Generate [`AddressKey`] from corresponding
    /// [`MultiSigner`](https://docs.rs/sp-runtime/6.0.0/sp_runtime/enum.MultiSigner.html) value  
    /// and a network prefix.
    pub fn new(multisigner: MultiSigner, genesis_hash: Option<H256>) -> Self {
        Self {
            multisigner,
            genesis_hash,
        }
    }

    /// Generate [`AddressKey`] from parts: raw public key and [`Encryption`]  
    ///
    /// Could result in error if public key length does not match the
    /// expected length for chosen encryption algorithm.  
    pub fn from_parts(
        public: &[u8],
        encryption: &Encryption,
        genesis_hash: Option<H256>,
    ) -> Result<Self> {
        let multisigner = get_multisigner(public, encryption)?;
        Ok(Self::new(multisigner, genesis_hash))
    }

    /// Transform database `IVec` key into [`AddressKey`] prior to processing  
    ///
    /// Infallible, the validity of resulting `AddressKey` is not checked.
    pub fn from_ivec(ivec: &IVec) -> Result<Self> {
        let vec = ivec.to_vec();
        Ok(Self::decode(&mut &vec[..])?)
    }

    /// Transform hexadecimal `String` into [`AddressKey`]  
    ///
    /// Vault receives hexadecimal strings from user interface.
    ///
    /// This function checks only that hexadecimal format is valid, no length
    /// check happens here.  
    pub fn from_hex(hex_address_key: &str) -> Result<Self> {
        Ok(Self::decode(&mut &unhex(hex_address_key)?[..])?)
    }

    /// Get public key and [`Encryption`] from the [`AddressKey`]  
    pub fn public_key_encryption(&self) -> Result<(Vec<u8>, Encryption)> {
        match &self.multisigner {
            MultiSigner::Ed25519(b) => Ok((b.to_vec(), Encryption::Ed25519)),
            MultiSigner::Sr25519(b) => Ok((b.to_vec(), Encryption::Sr25519)),
            MultiSigner::Ecdsa(b) => Ok((b.0.to_vec(), Encryption::Ecdsa)),
        }
    }

    /// Get [`MultiSigner`](https://docs.rs/sp-runtime/6.0.0/sp_runtime/enum.MultiSigner.html)
    /// from the [`AddressKey`]  
    pub fn multi_signer(&self) -> &MultiSigner {
        &self.multisigner
    }

    /// Transform [`AddressKey`] into `Vec<u8>` database key  
    pub fn key(&self) -> Vec<u8> {
        self.encode()
    }
}

/// Key in `HISTORY` tree (cold database)  
///
/// [`Order`] is used to retrieve history log entry.  
///
/// History log [`Entry`](crate::history::Entry) contains timestamp and a set
/// of simultaneously occurred events.
///
/// Order is generated from the number of the history entry in the database
/// `HISTORY` tree.  
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Order(u32);

impl Order {
    /// Transform database `IVec` key into [`Order`].  
    ///
    /// If `Order` could not be decoded, i.e. entry is corrupted, produces an
    /// error.  
    pub fn from_ivec(ivec: &IVec) -> Result<Self> {
        Ok(Self(<u32>::decode(&mut &ivec[..])?))
    }

    /// Generate [`Order`] from `u32` number
    pub fn from_number(n: u32) -> Self {
        Self(n)
    }

    /// Produce `u32` number from the [`Order`].
    ///
    /// Number here is the number of history entry in the `HISTORY` database.
    pub fn stamp(&self) -> u32 {
        self.0
    }

    /// Transform [`Order`] into `Vec<u8>` database key
    pub fn store(&self) -> Vec<u8> {
        self.0.encode()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::Error;

    #[test]
    fn error_in_network_specs_key_signer() {
        let network_specs_key_hex =
            "0f50e143f23803ac50e8f6f8e62695d1ce9e4e1d68aa36c1cd2cfd15340213f3423e";
        let network_specs_key = NetworkSpecsKey::from_hex(network_specs_key_hex).unwrap();
        let error = network_specs_key.genesis_hash_encryption().unwrap_err();
        if let Error::CodecError(_) = error {
        } else {
            panic!("Expected codec error, received {error:?}");
        }
    }

    #[test]
    fn error_in_network_specs_key_active() {
        let network_specs_key_hex =
            "0f50e143f23803ac50e8f6f8e62695d1ce9e4e1d68aa36c1cd2cfd15340213f3423e";
        let network_specs_key =
            NetworkSpecsKey::from_ivec(&IVec::from(hex::decode(network_specs_key_hex).unwrap()));
        let error = network_specs_key.genesis_hash_encryption().unwrap_err();
        if let Error::CodecError(_) = error {
        } else {
            panic!("Expected codec error, received {error:?}");
        }
    }
}
