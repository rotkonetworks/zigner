//! This crate deals with standard database-related procedures used in
//! [Zigner](https://github.com/rotkonetworks/zigner) and Zigner-supporting
//! ecosystem.  
//!
//! This crate:
//!
//! - contains helpers to operate the databases, used throughout Vault system
//! - generates the cold database (used in air-gapped Vault) with default
//!   settings
//! - deals with taking data out of the database and putting the data in the
//!   database
//! - contains Vault interface interactions, allowing exports of data to the
//!   interface
//! - deals with address generation for Vault
//!
//! # Features
//!
//! Feature `"active"` corresponds to all Vault-related things happening
//! **without** air-gap, including the generation of the database for Vault
//! during the build.

#![deny(rustdoc::broken_intra_doc_links)]
#![allow(rustdoc::redundant_explicit_links)]

// possibly TODO: rename all database_name into database_path or whatever,
// currently it is quite confusing

#[cfg(feature = "active")]
use constants::COLD_DB_NAME_RELEASE;

pub mod cold_default;

pub mod db_transactions;

pub mod helpers;

pub mod identities;

pub mod interface_signer;

pub mod manage_history;

mod error;

#[cfg(feature = "penumbra")]
pub mod penumbra;

#[cfg(feature = "ledger")]
pub mod ledger_ed25519;

#[cfg(feature = "cosmos")]
pub mod cosmos;

#[cfg(feature = "zcash")]
pub mod zcash;

pub mod anchor_verifiers;

#[cfg(feature = "zcash")]
pub mod frost;

#[cfg(all(feature = "active", feature = "zcash"))]
pub mod scan_policy;

pub mod contacts;

pub use error::{Error, Result};

#[cfg(test)]
pub mod tests;

#[cfg(feature = "active")]
use cold_default::populate_cold_release;

/// Generate or restore "cold" database with default values, **for release
/// build**.
///
/// Resulting database should be copied verbatim into Vault files during the
/// build.
///
/// The location of the generated database is either optional user-provided
/// path, or default [`COLD_DB_NAME_RELEASE`] folder.
///
/// The cold release database, as generated, contains network specs for the
/// default networks (Zcash, Penumbra, the Cosmos chains), a clean danger
/// status and the schema version. The history log is not initiated yet.
///
/// This operation is performed **not** on Vault device, and is governed by
/// the active side.
#[cfg(feature = "active")]
pub fn default_cold_release(database: Option<&sled::Db>) -> Result<()> {
    let database = if let Some(database) = database {
        database.clone()
    } else {
        sled::open(COLD_DB_NAME_RELEASE)?
    };
    populate_cold_release(&database)
}
