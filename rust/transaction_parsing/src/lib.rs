#![deny(unused_crate_dependencies)]
#![deny(rustdoc::broken_intra_doc_links)]

//! Parsing of signing requests read from the camera.
//!
//! Only Penumbra requests are parsed here. Zcash requests go through the
//! protocol module and the PCZT inspector, Cosmos through
//! `transaction_signing::cosmos`.

#[cfg(feature = "penumbra")]
pub mod penumbra;

mod error;

pub use crate::error::{Error, Result};
