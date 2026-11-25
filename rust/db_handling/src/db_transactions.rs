//! Atomic transactions in the cold database
//!
//! Additions and removals of entries in the cold database occur through
//! atomic [transactions](sled::transaction).
//! Each tree gets updated with its own [`Batch`], updates occur within a single
//! transaction.
use sled::{transaction::TransactionResult, Batch, Transactional};

use constants::{ADDRTREE, HISTORY, SETTREE};

use crate::helpers::open_tree;
use crate::Result;

/// Cold database transaction data containing [`Batch`] elements that will be
/// applied to each [`Tree`](sled::Tree).
///
/// Cold database tree names and content information could be found in
/// [`constants`] crate. All trees are routinely updated as Vault is used.
///
/// [`TrDbCold`] is applied to the cold database in an atomic transaction.
///
/// [`TrDbCold`] is used both by the Vault side (for all database-related
/// actions) and the active side (to generate and populate the cold database).
///
/// Note that all the checking is done as the [`TrDbCold`] is generated,
/// `apply` method does not do any checks on its own.
#[derive(Debug)]
pub struct TrDbCold {
    /// `Batch` to be applied to [`ADDRTREE`] tree
    for_addresses: Batch,

    /// `Batch` to be applied to [`HISTORY`] tree
    for_history: Batch,

    /// `Batch` to be applied to [`SETTREE`] tree
    for_settings: Batch,
}

impl TrDbCold {
    /// Construct new empty [`TrDbCold`].
    pub fn new() -> Self {
        Self {
            for_addresses: Batch::default(),
            for_history: Batch::default(),
            for_settings: Batch::default(),
        }
    }

    /// Set `for_addresses` field in [`TrDbCold`] with `Batch` that will be
    /// applied to [`ADDRTREE`] tree.
    pub fn set_addresses(mut self, for_addresses: Batch) -> Self {
        self.for_addresses = for_addresses;
        self
    }

    /// Set `for_history` field in [`TrDbCold`] with `Batch` that will be
    /// applied to [`HISTORY`] tree.
    pub fn set_history(mut self, for_history: Batch) -> Self {
        self.for_history = for_history;
        self
    }

    /// Set `for_settings` field in [`TrDbCold`] with `Batch` that will be
    /// applied to [`SETTREE`] tree.
    pub fn set_settings(mut self, for_settings: Batch) -> Self {
        self.for_settings = for_settings;
        self
    }

    /// Apply constructed set of batches within [`TrDbCold`] to the database
    /// with a given name, in a single transaction.
    ///
    /// Note that both `ErrorSource` variants are available.
    pub fn apply(&self, database: &sled::Db) -> Result<()> {
        let addresses = open_tree(database, ADDRTREE)?;
        let history = open_tree(database, HISTORY)?;
        let settings = open_tree(database, SETTREE)?;
        let s = (&addresses, &history, &settings);
        let res: TransactionResult<(), sled::Error> =
            s.transaction(|(tx_addresses, tx_history, tx_settings)| {
                tx_addresses.apply_batch(&self.for_addresses)?;
                tx_addresses.flush();
                tx_history.apply_batch(&self.for_history)?;
                tx_history.flush();
                tx_settings.apply_batch(&self.for_settings)?;
                tx_settings.flush();
                Ok(())
            });

        Ok(res?)
    }
}

impl Default for TrDbCold {
    /// Default value for [`TrDbCold`]. Empty.
    fn default() -> Self {
        Self::new()
    }
}
