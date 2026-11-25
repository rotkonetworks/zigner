//! Making and initiating the **cold** database with default content
//!
//! Cold database is the database that is operated from inside the Vault.
//!
//! For release, the cold database is generated at build time
//! (`cargo run --features active --bin make_cold_release` in this crate)
//! and copied verbatim into the app assets. It holds:
//!
//! - `SPECSTREE` with the default network specs (Zcash, Penumbra and the
//!   Cosmos chains); keys are stored against these
//! - `SETTREE` with the danger record and the database schema version
//!
//! Before the database could be used, it must be initiated with [`init_db`]:
//! old history log entries (if any) are removed and a new entry
//! `Event::DatabaseInitiated` is added.
//!
//! Databases written by older releases also hold `METATREE`, `VERIFIERS`,
//! `TRANSACTION` and the `TYPES` / `GENERALVERIFIER` settings, all for
//! Substrate signing. Nothing reads them any more; they are left in place.
#[cfg(feature = "active")]
use parity_scale_codec::Encode;
#[cfg(feature = "active")]
use sled::Batch;
#[cfg(feature = "active")]
use sp_core::H256;

use constants::HISTORY;
#[cfg(feature = "active")]
use constants::{DANGER, SCHEMA_VERSION, SETTREE, SPECSTREE};

use definitions::history::Event;
#[cfg(feature = "active")]
use definitions::{
    crypto::Encryption,
    danger::DangerRecord,
    keyring::NetworkSpecsKey,
    network_specs::{NetworkSpecs, OrderedNetworkSpecs},
    schema_version::SchemaVersion,
};

use crate::{
    db_transactions::TrDbCold, helpers::make_batch_clear_tree, manage_history::events_in_batch,
    Result,
};

/// A network every new database starts with.
#[cfg(feature = "active")]
struct DefaultNetwork {
    color: &'static str,
    decimals: u8,
    encryption: Encryption,
    /// Not a chain genesis hash for these networks: a fixed 32-byte
    /// identifier. Keys are stored under it, so it must never change.
    genesis_hash: [u8; 32],
    logo: &'static str,
    name: &'static str,
    order: u8,
    path_id: &'static str,
    secondary_color: &'static str,
    title: &'static str,
    unit: &'static str,
}

/// Right-aligns an ASCII tag in 32 zero bytes, ending in `suffix`.
#[cfg(feature = "active")]
const fn id(tag: &[u8], suffix: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let start = 32 - tag.len() - suffix.len();
    let mut i = 0;
    while i < tag.len() {
        out[start + i] = tag[i];
        i += 1;
    }
    let mut j = 0;
    while j < suffix.len() {
        out[start + tag.len() + j] = suffix[j];
        j += 1;
    }
    out
}

/// The default networks, as shipped since 0.12. Their identifiers and
/// encryptions are what existing keys point at.
#[cfg(feature = "active")]
const DEFAULT_NETWORKS: [DefaultNetwork; 7] = [
    DefaultNetwork {
        color: "#F4B728",
        decimals: 8,
        encryption: Encryption::Zcash,
        genesis_hash: [
            0x00, 0x04, 0x0f, 0xe8, 0xec, 0x84, 0x71, 0x91, 0x1b, 0xaa, 0x1d, 0xb1, 0x26, 0x6e,
            0xa1, 0x5d, 0xd0, 0x6b, 0x4a, 0x8a, 0x5c, 0x45, 0x38, 0x83, 0xc0, 0x00, 0xb0, 0x31,
            0x97, 0x3d, 0xce, 0x08,
        ],
        logo: "zcash",
        name: "zcash",
        order: 3,
        path_id: "m/32'/133'/0'",
        secondary_color: "#C9941E",
        title: "Zcash",
        unit: "ZEC",
    },
    DefaultNetwork {
        color: "#F4A31E",
        decimals: 6,
        encryption: Encryption::Penumbra,
        genesis_hash: id(b"", &[0x65, 0x32]),
        logo: "penumbra",
        name: "penumbra",
        order: 4,
        path_id: "m/44'/6532'/0'",
        secondary_color: "#B8841A",
        title: "Penumbra",
        unit: "UM",
    },
    DefaultNetwork {
        color: "#5E12A0",
        decimals: 6,
        encryption: Encryption::Cosmos,
        genesis_hash: id(b"osmosis-1", &[0, 0, 1]),
        logo: "osmosis",
        name: "osmosis",
        order: 5,
        path_id: "m/44'/118'/0'/0/0",
        secondary_color: "#4A0E80",
        title: "Osmosis",
        unit: "OSMO",
    },
    DefaultNetwork {
        color: "#00D2FF",
        decimals: 6,
        encryption: Encryption::Cosmos,
        genesis_hash: id(b"noble-1", &[0, 0, 1]),
        logo: "noble",
        name: "noble",
        order: 6,
        path_id: "m/44'/118'/0'/0/0",
        secondary_color: "#00A8CC",
        title: "Noble",
        unit: "USDC",
    },
    DefaultNetwork {
        color: "#7B2BF9",
        decimals: 6,
        encryption: Encryption::Cosmos,
        genesis_hash: id(b"celestia", &[0, 0, 0, 0, 1]),
        logo: "celestia",
        name: "celestia",
        order: 7,
        path_id: "m/44'/118'/0'/0/0",
        secondary_color: "#6222C7",
        title: "Celestia",
        unit: "TIA",
    },
    DefaultNetwork {
        color: "#2E3148",
        decimals: 6,
        encryption: Encryption::Cosmos,
        genesis_hash: id(b"cosmoshub-4", &[0, 0, 1]),
        logo: "cosmos",
        name: "cosmos",
        order: 8,
        path_id: "m/44'/118'/0'/0/0",
        secondary_color: "#1B1E36",
        title: "Cosmos Hub",
        unit: "ATOM",
    },
    DefaultNetwork {
        color: "#5493F7",
        decimals: 6,
        encryption: Encryption::Cosmos,
        genesis_hash: id(b"phoenix-1", &[0, 0, 1]),
        logo: "terra",
        name: "terra",
        order: 9,
        path_id: "m/44'/330'/0'/0/0",
        secondary_color: "#3B6FC5",
        title: "Terra",
        unit: "LUNA",
    },
];

/// Network specs of the default networks, for the cold database.
#[cfg(feature = "active")]
pub fn default_chainspecs() -> Vec<OrderedNetworkSpecs> {
    DEFAULT_NETWORKS
        .iter()
        .map(|x| OrderedNetworkSpecs {
            specs: NetworkSpecs {
                base58prefix: 0,
                color: x.color.to_string(),
                decimals: x.decimals,
                encryption: x.encryption,
                genesis_hash: H256::from(x.genesis_hash),
                logo: x.logo.to_string(),
                name: x.name.to_string(),
                path_id: x.path_id.to_string(),
                secondary_color: x.secondary_color.to_string(),
                title: x.title.to_string(),
                unit: x.unit.to_string(),
            },
            order: x.order,
        })
        .collect()
}

/// Wipe the database and load the default network specs, danger record and
/// schema version. The result is not initiated: see [`init_db`].
#[cfg(feature = "active")]
pub(crate) fn populate_cold_release(database: &sled::Db) -> Result<()> {
    for tree in database.tree_names() {
        if tree != b"__sled__default" {
            database.drop_tree(tree)?;
        }
    }
    database.clear()?;

    let mut specs = Batch::default();
    for x in default_chainspecs() {
        let key = NetworkSpecsKey::from_parts(&x.specs.genesis_hash, &x.specs.encryption);
        specs.insert(key.key(), x.encode());
    }
    let mut settings = Batch::default();
    settings.insert(DANGER, DangerRecord::safe().store());
    settings.insert(SCHEMA_VERSION, SchemaVersion::store_current());

    database.open_tree(SPECSTREE)?.apply_batch(specs)?;
    database.open_tree(SETTREE)?.apply_batch(settings)?;
    Ok(())
}

/// Initiate the database: clear the history log and start it with
/// `Event::DatabaseInitiated`.
///
/// Applied on the first start of the Vault and after `Wipe all data`.
/// After this the database is ready to be used by the Vault.
pub fn init_db(database: &sled::Db) -> Result<()> {
    let clear_history_batch = make_batch_clear_tree(database, HISTORY)?;
    let events = vec![Event::DatabaseInitiated];
    let start_zero = true;
    let history_batch = events_in_batch(database, start_zero, clear_history_batch, events)?;

    TrDbCold::new()
        .set_history(history_batch) // set *start* history
        .apply(database)?;

    Ok(())
}
