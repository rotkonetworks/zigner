//! Definitions and common methods for types used in [Zigner](https://github.com/rotkonetworks/zigner)
//! and Zigner-supporting ecosystem.
//!
//! ## Features
//! Feature `"signer"` corresponds to everything related to the Zigner air-gapped
//! device.
//!
//! Feature `"active"` corresponds to all Vault-related things happening
//! **without** air-gap.
//!
//! Feature `"test"` includes both `"signer"` and `"active"` features, along
//! with some testing, and is the default one.

#![deny(unused_crate_dependencies)]
#![deny(rustdoc::broken_intra_doc_links)]
#![allow(rustdoc::redundant_explicit_links)]

pub mod crypto;

pub mod danger;

pub mod error;

pub mod helpers;

pub mod history;

pub mod keyring;

pub mod network_specs;

pub mod users;

pub mod navigation;

pub mod schema_version;
