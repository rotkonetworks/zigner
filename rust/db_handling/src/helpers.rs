//! Common helper functions for database operations
use definitions::crypto::Encryption;
#[cfg(feature = "active")]
use parity_scale_codec::Encode;
use sled::{Batch, Db, Tree};
use sp_core::H256;

use constants::{ADDRTREE, DANGER, SCHEMA_VERSION};
use constants::{SETTREE, SPECSTREE};

use definitions::network_specs::OrderedNetworkSpecs;
use definitions::schema_version::SchemaVersion;
use definitions::{danger::DangerRecord, keyring::NetworkSpecsKey};
#[cfg(feature = "active")]
use definitions::{keyring::AddressKey, users::AddressDetails};
use sp_runtime::MultiSigner;

use crate::identities::find_address_details_for_multisigner;
use crate::{Error, Result};

/// Open a tree in the database.
///
/// Wrapper for `open_tree()` method for database [`Db`] from [`sled`].
/// Input is `&[u8]` tree identifier.
pub fn open_tree(database: &Db, tree_name: &[u8]) -> Result<Tree> {
    Ok(database.open_tree(tree_name)?)
}

/// Check database schema version.
/// Prevents app stash when user upgrades the app without re-install.
pub fn assert_db_version(database: &Db) -> Result<()> {
    let expected = *SchemaVersion::current();
    let settings = open_tree(database, SETTREE)?;
    let ivec = settings
        .get(SCHEMA_VERSION)?
        .ok_or(Error::DbSchemaMismatch { expected, found: 0 })?;
    let found = *SchemaVersion::from_ivec(&ivec)?;
    if expected != found {
        return Err(Error::DbSchemaMismatch { expected, found });
    }
    Ok(())
}

/// Assemble a [`Batch`] that removes all elements from a tree.
pub fn make_batch_clear_tree(database: &sled::Db, tree_name: &[u8]) -> Result<Batch> {
    let tree = open_tree(database, tree_name)?;
    let mut out = Batch::default();
    for (key, _) in tree.iter().flatten() {
        out.remove(key)
    }
    Ok(out)
}

/// Get [`OrderedNetworkSpecs`] for all networks from the cold database.
///
/// Function is used both on active and Vault side, but only for the cold
/// database.
pub fn get_all_networks(database: &sled::Db) -> Result<Vec<OrderedNetworkSpecs>> {
    let chainspecs = open_tree(database, SPECSTREE)?;
    let mut out: Vec<OrderedNetworkSpecs> = Vec::new();
    for x in chainspecs.iter().flatten() {
        out.push(OrderedNetworkSpecs::from_entry_checked(x)?)
    }
    Ok(out)
}

/// Specs invariants that are expected to stay unchanged for the network over
/// time and can not be different for same genesis hash and different encryption
/// algorithms.
pub struct SpecsInvariants {
    pub base58prefix: u16,

    /// network with lowest order, for correct navigation when updating the
    /// network metadata
    pub first_network_specs_key: NetworkSpecsKey,
    pub genesis_hash: H256,
    pub name: String,
}

/// Search for network genesis hash in [`OrderedNetworkSpecs`] entries in [`SPECSTREE`]
/// of the Vault database.
///
/// If there are more than one network corresponding to the same genesis hash,
/// outputs network specs key for the network with the lowest order.
///
/// If there are several entries with same genesis hash, all of them must have
/// identical base58 prefix and network name. Network name is, and base58 prefix
/// could be a part of the network metadata, and therefore must not depend on
/// encryption used.
pub fn genesis_hash_in_specs(
    database: &sled::Db,
    genesis_hash: H256,
) -> Result<Option<SpecsInvariants>> {
    let chainspecs = open_tree(database, SPECSTREE)?;
    let mut specs_set: Vec<(NetworkSpecsKey, OrderedNetworkSpecs)> = Vec::new();
    let mut found_permanent_specs: Option<(u16, String)> = None;
    for (network_specs_key_vec, network_specs_encoded) in chainspecs.iter().flatten() {
        let network_specs_key = NetworkSpecsKey::from_ivec(&network_specs_key_vec);
        let network_specs = OrderedNetworkSpecs::from_entry_with_key_checked(
            &network_specs_key,
            network_specs_encoded,
        )?;
        if network_specs.specs.genesis_hash.as_bytes() == &genesis_hash[..] {
            found_permanent_specs = match found_permanent_specs {
                Some((base58prefix, name)) => {
                    if base58prefix == network_specs.specs.base58prefix {
                        if name == network_specs.specs.name {
                            Some((base58prefix, name))
                        } else {
                            return Err(Error::DifferentNamesSameGenesisHash {
                                name1: name,
                                name2: network_specs.specs.name.to_string(),
                                genesis_hash: network_specs.specs.genesis_hash,
                            });
                        }
                    } else {
                        return Err(Error::DifferentBase58Specs {
                            genesis_hash: network_specs.specs.genesis_hash,
                            base58_1: base58prefix,
                            base58_2: network_specs.specs.base58prefix,
                        });
                    }
                }
                None => Some((
                    network_specs.specs.base58prefix,
                    network_specs.specs.name.to_string(),
                )),
            };
            specs_set.push((network_specs_key, network_specs))
        }
    }
    specs_set.sort_by_key(|a| a.1.order);
    match specs_set.first() {
        Some(a) => Ok(Some(SpecsInvariants {
            base58prefix: a.1.specs.base58prefix,
            first_network_specs_key: a.0.to_owned(),
            genesis_hash,
            name: a.1.specs.name.to_string(),
        })),
        None => Ok(None),
    }
}

/// Try to get network specs [`OrderedNetworkSpecs`] from the Vault database.
///
/// If the [`NetworkSpecsKey`] and associated [`OrderedNetworkSpecs`] are not found in
/// the [`SPECSTREE`], the result is `Ok(None)`.
pub fn try_get_network_specs(
    database: &sled::Db,
    network_specs_key: &NetworkSpecsKey,
) -> Result<Option<OrderedNetworkSpecs>> {
    let chainspecs = open_tree(database, SPECSTREE)?;
    Ok(chainspecs
        .get(network_specs_key.key())?
        .map(|network_specs_encoded| {
            OrderedNetworkSpecs::from_entry_with_key_checked(
                network_specs_key,
                network_specs_encoded,
            )
        })
        .transpose()?)
}

/// Get network specs [`OrderedNetworkSpecs`] from the Vault database.
///
/// Network specs here are expected to be found, not finding them results in an
/// error.
pub fn get_network_specs(
    database: &sled::Db,
    network_specs_key: &NetworkSpecsKey,
) -> Result<OrderedNetworkSpecs> {
    try_get_network_specs(database, network_specs_key)?
        .ok_or_else(|| Error::NetworkSpecsNotFound(network_specs_key.clone()))
}

/// Try to get [`AddressDetails`] from the Vault database, using
/// [`AddressKey`].
///
/// If no entry with provided [`AddressKey`] is found, the result is `Ok(None)`.
pub fn try_get_address_details(
    database: &sled::Db,
    address_key: &AddressKey,
) -> Result<Option<AddressDetails>> {
    let identities = open_tree(database, ADDRTREE)?;
    identities
        .get(address_key.key())?
        .map(|address_details_encoded| -> Result<AddressDetails> {
            Ok(AddressDetails::from_entry_with_key_checked(
                address_key,
                address_details_encoded,
            )?)
        })
        .transpose()
}

/// Try to get [`AddressDetails`] from the Vault database, matching by
/// [`MultiSigner`].
///
/// If no entry is found, the result is `Ok(None)`.
pub fn try_get_address_details_by_multisigner(
    database: &sled::Db,
    multisigner: &MultiSigner,
    genesis_hash: &H256,
    encryption: &Encryption,
) -> Result<Option<AddressDetails>> {
    let maybe_address_details =
        find_address_details_for_multisigner(database, multisigner, vec![*genesis_hash])?;

    let network_specs_key = NetworkSpecsKey::from_parts(genesis_hash, encryption);

    let new_details = maybe_address_details.map(|address_details| AddressDetails {
        seed_name: address_details.seed_name,
        path: address_details.path,
        has_pwd: address_details.has_pwd,
        network_id: Some(network_specs_key),
        encryption: *encryption,
        secret_exposed: address_details.secret_exposed,
    });

    Ok(new_details)
}

/// Get [`AddressDetails`] from the Vault database, using
/// [`AddressKey`].
///
/// Address is expected to exist, not finding it results in an error.
pub fn get_address_details(
    database: &sled::Db,
    address_key: &AddressKey,
) -> Result<AddressDetails> {
    try_get_address_details(database, address_key)?
        .ok_or_else(|| Error::AddressNotFound(address_key.clone()))
}

/// Modify existing batch for [`ADDRTREE`](constants::ADDRTREE) with incoming
/// vector of additions.
#[cfg(feature = "active")]
pub(crate) fn upd_id_batch(mut batch: Batch, adds: Vec<(AddressKey, AddressDetails)>) -> Batch {
    for (address_key, address_details) in adds.iter() {
        batch.insert(address_key.key(), address_details.encode());
    }
    batch
}

/// Get the danger status from the Vault database.
///
/// Currently, the only flag contributing to the danger status is whether the
/// device was online. This may change eventually.
pub fn get_danger_status(database: &sled::Db) -> Result<bool> {
    let settings = open_tree(database, SETTREE)?;
    let a = settings.get(DANGER)?.ok_or(Error::DangerStatusNotFound)?;
    Ok(DangerRecord::from_ivec(&a).device_was_online()?)
}

pub fn validate_mnemonic(mnemonic: &str) -> bool {
    bip39::Mnemonic::validate(mnemonic, bip39::Language::English).is_ok()
}
