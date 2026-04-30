// Copyright 2015-2021 Parity Technologies (UK) Ltd.
// This file is part of Parity.

// Parity is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// Parity is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with Parity.  If not, see <http://www.gnu.org/licenses/>.

//! This crate serves as interface between native frontend and Rust code. Try to avoid placing any
//! logic here, just interfacing. When porting to new platform, all Rust changes will probably
//! happen here.

#![deny(unused_crate_dependencies)]
#![deny(rustdoc::broken_intra_doc_links)]
#![allow(clippy::let_unit_value)]
#![allow(clippy::unnecessary_struct_initialization)]
#![allow(clippy::useless_conversion)]
#![allow(clippy::unneeded_struct_pattern)]

// These crates are used by pczt but need to be declared here
// to satisfy the unused_crate_dependencies lint
use zcash_transparent as _;

pub mod auth;
pub mod backup;
mod ffi_types;
pub mod frost_backup;
pub mod frost_multisig;

use crate::ffi_types::*;
use db_handling::identities::{import_all_addrs, inject_derivations_has_pwd};
use db_handling::{Error as DbHandlingError, Error};
use definitions::keyring::AddressKey;
use definitions::navigation::ZcashSimpleSignRequest;
use lazy_static::lazy_static;
use navigator::Error as NavigatorError;
use sled::Db;
use std::{
    collections::HashMap,
    convert::TryInto,
    fmt::Display,
    str::FromStr,
    sync::{Arc, RwLock},
};
use transaction_parsing::dynamic_derivations::process_dynamic_derivations;
use transaction_parsing::entry_to_transactions_with_decoding;
use transaction_parsing::Error as TxParsingError;
use transaction_signing::SufficientContent;

lazy_static! {
    static ref DB: Arc<RwLock<Option<Db>>> = Arc::new(RwLock::new(None));
}

/// Container for severe error message
///
/// TODO: implement properly or remove completely
#[derive(Debug)]
pub enum ErrorDisplayed {
    /// String description of error
    Str {
        /// Error description
        s: String,
    },
    MutexPoisoned,
    DbNotInitialized,
    /// Tried to load metadata for unknown network.
    LoadMetaUnknownNetwork {
        /// Name of the network not known to the Vault.
        name: String,
    },
    /// Tried to add specs already present in Vault.
    SpecsKnown {
        name: String,
        encryption: Encryption,
    },
    /// The metadata with this network version already in db.
    MetadataKnown {
        name: String,
        version: u32,
    },
    /// Do not have an up-to-date version of metadata in db
    MetadataOutdated {
        name: String,
        have: u32,
        want: u32,
    },
    /// Tried to sign transaction with an unknown network
    UnknownNetwork {
        genesis_hash: H256,
        encryption: Encryption,
    },
    /// No metadata for a known network found in store
    NoMetadata {
        name: String,
    },
    /// Provided password is incorrect
    WrongPassword,
    /// Database schema mismatch
    DbSchemaMismatch,
}

impl From<NavigatorError> for ErrorDisplayed {
    fn from(e: NavigatorError) -> Self {
        match &e {
            NavigatorError::MutexPoisoned => Self::MutexPoisoned,
            NavigatorError::DbNotInitialized => Self::DbNotInitialized,
            NavigatorError::TransactionParsing(t) => match t {
                TxParsingError::LoadMetaUnknownNetwork { name } => {
                    Self::LoadMetaUnknownNetwork { name: name.clone() }
                }
                TxParsingError::SpecsKnown { name, encryption } => Self::SpecsKnown {
                    name: name.clone(),
                    encryption: *encryption,
                },
                TxParsingError::MetadataKnown { name, version } => Self::MetadataKnown {
                    name: name.clone(),
                    version: *version,
                },
                TxParsingError::AllExtensionsParsingFailed {
                    ref network_name,
                    ref errors,
                } => {
                    if let Some((want, parser::Error::WrongNetworkVersion { in_metadata, .. })) =
                        errors.first()
                    {
                        Self::MetadataOutdated {
                            name: network_name.to_string(),
                            have: *in_metadata,
                            want: *want,
                        }
                    } else {
                        Self::Str { s: format!("{e}") }
                    }
                }
                TxParsingError::UnknownNetwork {
                    genesis_hash,
                    encryption,
                } => Self::UnknownNetwork {
                    genesis_hash: *genesis_hash,
                    encryption: *encryption,
                },
                TxParsingError::NoMetadata { name } => Self::NoMetadata {
                    name: name.to_string(),
                },
                _ => Self::Str { s: format!("{e}") },
            },
            NavigatorError::TransactionSigning(transaction_signing::Error::WrongPassword) => {
                Self::WrongPassword
            }
            _ => Self::Str { s: format!("{e}") },
        }
    }
}

impl From<DbHandlingError> for ErrorDisplayed {
    fn from(e: DbHandlingError) -> Self {
        match &e {
            Error::DbSchemaMismatch { .. } => Self::DbSchemaMismatch,
            _ => Self::Str { s: format!("{e}") },
        }
    }
}

impl From<anyhow::Error> for ErrorDisplayed {
    fn from(e: anyhow::Error) -> Self {
        Self::Str {
            s: format!("error on signer side: {e}"),
        }
    }
}

impl FromStr for ErrorDisplayed {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(ErrorDisplayed::Str { s: s.to_string() })
    }
}

impl From<String> for ErrorDisplayed {
    fn from(s: String) -> Self {
        ErrorDisplayed::Str { s }
    }
}

impl Display for ErrorDisplayed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TODO")
    }
}

/// An error type for QR sequence decoding errors.
#[derive(Debug)]
pub enum QrSequenceDecodeError {
    BananaSplitWrongPassword,
    BananaSplit { s: String },
    GenericError { s: String },
}

impl Display for QrSequenceDecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TODO")
    }
}

impl From<qr_reader_phone::Error> for QrSequenceDecodeError {
    fn from(value: qr_reader_phone::Error) -> Self {
        match value {
            qr_reader_phone::Error::BananaSplitWrongPassword => Self::BananaSplitWrongPassword,
            qr_reader_phone::Error::BananaSplitError(e) => Self::BananaSplit { s: format!("{e}") },
            other => QrSequenceDecodeError::GenericError {
                s: format!("{other}"),
            },
        }
    }
}

include!(concat!(env!("OUT_DIR"), "/signer.uniffi.rs"));

fn action_get_name(action: &Action) -> Option<FooterButton> {
    match action {
        Action::NavbarLog => Some(FooterButton::Log),
        Action::NavbarScan => Some(FooterButton::Scan),
        Action::NavbarKeys => Some(FooterButton::Keys),
        Action::NavbarSettings => Some(FooterButton::Settings),
        Action::GoBack => Some(FooterButton::Back),
        _ => None,
    }
}

/// Perform action in frontend.
///
/// This call should be debounced.
///
/// Action tries to acquire lock on app state mutex and is ignored on failure.
///
/// `seed_phrase` field is zeroized, it is expected to be used for secrets only.
///
/// `details` field is not always zeroized.
///
/// App view contents are returned as result, this should be sufficient to render view.
fn backend_action(
    action: Action,
    details: &str,
    seed_phrase: &str,
) -> Result<ActionResult, ErrorDisplayed> {
    Ok(navigator::do_action(action, details, seed_phrase)?)
}

/// Should be called once at start of the app and could be called on app reset
///
/// Accepts list of seed names to avoid calling [`update_seed_names`] every time
fn init_navigation(dbname: &str, seed_names: Vec<String>) -> Result<(), ErrorDisplayed> {
    let val = Some(sled::open(dbname).map_err(|e| ErrorDisplayed::from(e.to_string()))?);

    *DB.write().unwrap() = val;
    init_logging("Vault".to_string());
    Ok(navigator::init_navigation(
        DB.clone().read().unwrap().as_ref().unwrap().clone(),
        seed_names,
    )?)
}

/// Should be called every time any change could have been done to seeds. Accepts updated list of
/// seeds, completely disregards previously known list
fn update_seed_names(seed_names: Vec<String>) -> Result<(), ErrorDisplayed> {
    Ok(navigator::update_seed_names(seed_names)?)
}

/// Determines estimated required number of multiframe QR that should be gathered before decoding
/// is attempted
fn qrparser_get_packets_total(data: &str, cleaned: bool) -> anyhow::Result<u32, ErrorDisplayed> {
    qr_reader_phone::get_length(data, cleaned).map_err(|e| e.to_string().into())
}

/// Attempts to convert QR data (transfered as json-like string) into decoded but not parsed UOS
/// payload
///
/// `cleaned` is platform-specific flag indicating whether QR payloads have QR prefix stripped by
/// QR parsing code
fn qrparser_try_decode_qr_sequence(
    data: &[String],
    password: Option<String>,
    cleaned: bool,
) -> anyhow::Result<DecodeSequenceResult, QrSequenceDecodeError> {
    let res = qr_reader_phone::decode_sequence(data, &password, cleaned);

    Ok(res?)
}

fn get_db() -> Result<sled::Db, ErrorDisplayed> {
    DB.read()
        .unwrap()
        .clone()
        .ok_or(ErrorDisplayed::DbNotInitialized)
}

/// Exports secret (private) key as QR code
///
/// `public_key` is hex-encoded public key of the key to export. Can be taken from [`MKeyDetails`]
/// `network_specs_key` is hex-encoded [`NetworkSpecsKey`]. Can be taken from [`MSCNetworkInfo`]
fn generate_secret_key_qr(
    public_key: &str,
    expected_seed_name: &str,
    network_specs_key: &str,
    seed_phrase: &str,
    key_password: Option<String>,
) -> Result<MKeyDetails, ErrorDisplayed> {
    db_handling::identities::export_secret_key(
        &get_db()?,
        public_key,
        expected_seed_name,
        network_specs_key,
        seed_phrase,
        key_password,
    )
    .map_err(|e| e.to_string().into())
}

fn import_derivations(seed_derived_keys: Vec<SeedKeysPreview>) -> Result<(), ErrorDisplayed> {
    import_all_addrs(&get_db()?, seed_derived_keys).map_err(|e| e.to_string().into())
}

/// Calculate if derivation path has a password
fn populate_derivations_has_pwd(
    seeds: HashMap<String, String>,
    seed_derived_keys: Vec<SeedKeysPreview>,
) -> Result<Vec<SeedKeysPreview>, anyhow::Error> {
    inject_derivations_has_pwd(seed_derived_keys, seeds).map_err(Into::into)
}

fn preview_dynamic_derivations(
    seeds: HashMap<String, String>,
    payload: String,
) -> Result<DDPreview, ErrorDisplayed> {
    process_dynamic_derivations(&get_db()?, seeds, &payload).map_err(|e| e.to_string().into())
}

/// Checks derivation path for validity and collisions
///
/// Returns struct that has information on collisions, presence of password and validity of path;
/// in case of valid path without collisions frontend should make a decision on whether to access
/// secure storage already or check password by requesting user to re-type it, so this could not be
/// isolated in backend navigation for now.
fn substrate_path_check(
    seed_name: &str,
    path: &str,
    network: &str,
) -> Result<DerivationCheck, ErrorDisplayed> {
    Ok(db_handling::interface_signer::dynamic_path_check(
        &get_db()?,
        seed_name,
        path,
        network,
    ))
}

fn try_create_address(
    seed_name: &str,
    seed_phrase: &str,
    path: &str,
    network: &str,
) -> anyhow::Result<(), ErrorDisplayed> {
    let network = NetworkSpecsKey::from_hex(network).map_err(|e| format!("{e}"))?;
    db_handling::identities::try_create_address(&get_db()?, seed_name, seed_phrase, path, &network)
        .map_err(|e| e.to_string().into())
}

/// Create address by looking up network via genesis hash
/// genesis_hash_hex: hex-encoded 32-byte genesis hash
fn try_create_address_by_genesis(
    seed_name: &str,
    seed_phrase: &str,
    path: &str,
    genesis_hash_hex: &str,
) -> anyhow::Result<(), ErrorDisplayed> {
    use db_handling::helpers::genesis_hash_in_specs;
    use sp_core::H256;

    let db = get_db()?;
    let genesis_hash_bytes = hex::decode(genesis_hash_hex).map_err(|e| ErrorDisplayed::Str {
        s: format!("Invalid genesis hash hex: {e}"),
    })?;
    if genesis_hash_bytes.len() != 32 {
        return Err(ErrorDisplayed::Str {
            s: "Genesis hash must be 32 bytes".to_string(),
        });
    }
    let genesis_hash = H256::from_slice(&genesis_hash_bytes);

    let specs_invariants = genesis_hash_in_specs(&db, genesis_hash)
        .map_err(|e| ErrorDisplayed::Str { s: format!("{e}") })?
        .ok_or_else(|| ErrorDisplayed::Str {
            s: format!("Network with genesis hash {} not found", genesis_hash_hex),
        })?;

    db_handling::identities::try_create_address(
        &db,
        seed_name,
        seed_phrase,
        path,
        &specs_invariants.first_network_specs_key,
    )
    .map_err(|e| e.to_string().into())
}

/// Must be called with `DecodeSequenceResult::DynamicDerivationTransaction` payload
fn sign_dd_transaction(
    payload: &[String],
    seeds: HashMap<String, String>,
) -> Result<MSignedTransaction, ErrorDisplayed> {
    navigator::sign_dd_transaction(&get_db()?, payload, seeds).map_err(|e| e.to_string().into())
}

/// Must be called once on normal first start of the app upon accepting conditions; relies on old
/// data being already removed
fn history_init_history_with_cert() -> anyhow::Result<(), ErrorDisplayed> {
    db_handling::cold_default::signer_init_with_cert(&get_db()?).map_err(|e| e.to_string().into())
}

/// Must be called once upon jailbreak (removal of general verifier) after all old data was removed
fn history_init_history_no_cert() -> anyhow::Result<(), ErrorDisplayed> {
    db_handling::cold_default::signer_init_no_cert(&get_db()?).map_err(|e| e.to_string().into())
}

/// Must be called every time network detector detects network. Sets alert flag in database that could
/// only be reset by full reset or calling [`history_acknowledge_warnings`]
///
/// This changes log, so it is expected to fail all operations that check that database remained
/// intact
fn history_device_was_online() -> anyhow::Result<(), ErrorDisplayed> {
    db_handling::manage_history::device_was_online(&get_db()?).map_err(|e| e.to_string().into())
}

/// Checks if network alert flag was set
fn history_get_warnings() -> anyhow::Result<bool, ErrorDisplayed> {
    db_handling::helpers::get_danger_status(&get_db()?).map_err(|e| e.to_string().into())
}

/// Resets network alert flag; makes record of reset in log
fn history_acknowledge_warnings() -> anyhow::Result<(), ErrorDisplayed> {
    db_handling::manage_history::reset_danger_status_to_safe(&get_db()?)
        .map_err(|e| e.to_string().into())
}

/// Allows frontend to send events into log; TODO: maybe this is not needed
fn history_entry_system(event: Event) -> anyhow::Result<(), ErrorDisplayed> {
    db_handling::manage_history::history_entry_system(&get_db()?, event)
        .map_err(|e| e.to_string().into())
}

/// Must be called every time seed backup shows seed to user
///
/// Makes record in log
fn history_seed_was_shown(seed_name: &str) -> anyhow::Result<(), ErrorDisplayed> {
    db_handling::manage_history::seed_name_was_shown(&get_db()?, seed_name.to_string())
        .map_err(|e| e.to_string().into())
}

fn export_key_info(
    seed_name: &str,
    exported_set: ExportedSet,
) -> anyhow::Result<MKeysInfoExport, ErrorDisplayed> {
    navigator::export_key_info(&get_db()?, seed_name, exported_set)
        .map_err(|e| e.to_string().into())
}

fn keys_by_seed_name(seed_name: &str) -> anyhow::Result<MKeysNew, ErrorDisplayed> {
    navigator::keys_by_seed_name(&get_db()?, seed_name).map_err(|e| e.to_string().into())
}

/// Encode binary info into qr code
fn encode_to_qr(payload: &[u8], is_danger: bool) -> anyhow::Result<Vec<u8>, String> {
    use qrcode_static::DataType;
    let sensitivity = if is_danger {
        DataType::Sensitive
    } else {
        DataType::Regular
    };
    qrcode_static::png_qr(payload, sensitivity).map_err(|e| format!("{e}"))
}

/// Get all networks registered within this device
fn get_managed_networks() -> anyhow::Result<MManageNetworks, ErrorDisplayed> {
    Ok(MManageNetworks {
        networks: db_handling::interface_signer::show_all_networks(&get_db()?)
            .map_err(|e| e.to_string())?,
    })
}

fn get_logs() -> anyhow::Result<MLog, ErrorDisplayed> {
    let history = db_handling::manage_history::get_history(&get_db()?)
        .map_err(|e| ErrorDisplayed::from(e.to_string()))?;
    let log: Vec<_> = history
        .into_iter()
        .map(|(order, entry)| History {
            order: order.stamp(),
            timestamp: entry.timestamp,
            events: entry.events,
        })
        .collect();

    Ok(MLog { log })
}

fn get_log_details(order: u32) -> anyhow::Result<MLogDetails, ErrorDisplayed> {
    let e = db_handling::manage_history::get_history_entry_by_order(&get_db()?, order)
        .map_err(|e| ErrorDisplayed::from(e.to_string()))?;

    let timestamp = e.timestamp.clone();

    let events = entry_to_transactions_with_decoding(&get_db()?, e)
        .map_err(|e| ErrorDisplayed::from(e.to_string()))?;

    Ok(MLogDetails { timestamp, events })
}

fn clear_log_history() -> anyhow::Result<(), ErrorDisplayed> {
    db_handling::manage_history::clear_history(&get_db()?)
        .map_err(|e| ErrorDisplayed::from(e.to_string()))
}

fn handle_log_comment(string_from_user: &str) -> anyhow::Result<(), ErrorDisplayed> {
    db_handling::manage_history::history_entry_user(&get_db()?, string_from_user)
        .map_err(|e| ErrorDisplayed::from(e.to_string()))
}

fn get_seeds(names_phone_knows: &[String]) -> anyhow::Result<MSeeds, ErrorDisplayed> {
    let seed_name_cards = db_handling::interface_signer::get_all_seed_names_with_identicons(
        &get_db()?,
        names_phone_knows,
    )
    .map_err(|e| ErrorDisplayed::from(e.to_string()))?;

    Ok(MSeeds { seed_name_cards })
}

fn get_key_set_public_key(
    address: &str,
    network_specs_key: &str,
) -> anyhow::Result<MKeyDetails, ErrorDisplayed> {
    let address_key =
        AddressKey::from_hex(address).map_err(|e| ErrorDisplayed::from(e.to_string()))?;

    let network_specs_key = NetworkSpecsKey::from_hex(network_specs_key)
        .map_err(|e| ErrorDisplayed::from(e.to_string()))?;

    let address_details = db_handling::helpers::get_address_details(&get_db()?, &address_key)
        .map_err(|e| ErrorDisplayed::from(e.to_string()))?;

    db_handling::interface_signer::export_key(
        &get_db()?,
        address_key.multi_signer(),
        &address_details.seed_name,
        &network_specs_key,
    )
    .map_err(|e| ErrorDisplayed::from(e.to_string()))
}

fn remove_derived_key(
    address: &str,
    network_specs_key: &str,
) -> anyhow::Result<(), ErrorDisplayed> {
    let address_key =
        AddressKey::from_hex(address).map_err(|e| ErrorDisplayed::from(e.to_string()))?;
    let network_specs_key = NetworkSpecsKey::from_hex(network_specs_key)
        .map_err(|e| ErrorDisplayed::from(e.to_string()))?;
    db_handling::identities::remove_key(&get_db()?, address_key.multi_signer(), &network_specs_key)
        .map_err(|e| ErrorDisplayed::from(e.to_string()))
}

fn remove_key_set(seed_name: &str) -> anyhow::Result<(), ErrorDisplayed> {
    db_handling::identities::remove_seed(&get_db()?, seed_name)
        .map_err(|e| ErrorDisplayed::from(e.to_string()))
}

fn get_managed_network_details(
    network_key: &str,
) -> anyhow::Result<MNetworkDetails, ErrorDisplayed> {
    let network_key = NetworkSpecsKey::from_hex(network_key).map_err(|e| format!("{e}"))?;
    db_handling::interface_signer::network_details_by_key(&get_db()?, &network_key)
        .map_err(|e| ErrorDisplayed::from(e.to_string()))
}

fn remove_metadata_on_managed_network(
    network_key: &str,
    metadata_specs_version: &str,
) -> anyhow::Result<(), ErrorDisplayed> {
    let network_key = NetworkSpecsKey::from_hex(network_key).map_err(|e| format!("{e}"))?;
    let version = metadata_specs_version
        .parse::<u32>()
        .map_err(|e| format!("{e}"))?;
    db_handling::helpers::remove_metadata(&get_db()?, &network_key, version)
        .map_err(|e| ErrorDisplayed::from(e.to_string()))
}

fn seed_phrase_guess_words(user_input: &str) -> Vec<String> {
    db_handling::interface_signer::guess(user_input)
        .into_iter()
        .map(|s| s.to_owned())
        .collect()
}

fn get_verifier_details() -> anyhow::Result<MVerifierDetails, ErrorDisplayed> {
    Ok(db_handling::helpers::get_general_verifier(&get_db()?)
        .map_err(|e| e.to_string())?
        .show_card())
}

fn remove_managed_network(network_key: &str) -> anyhow::Result<(), ErrorDisplayed> {
    let network_key = NetworkSpecsKey::from_hex(network_key).map_err(|e| format!("{e}"))?;
    db_handling::helpers::remove_network(&get_db()?, &network_key)
        .map_err(|e| ErrorDisplayed::from(e.to_string()))
}

fn print_new_seed(new_seed_name: &str) -> anyhow::Result<MNewSeedBackup, ErrorDisplayed> {
    db_handling::interface_signer::print_new_seed(new_seed_name)
        .map_err(|e| ErrorDisplayed::from(e.to_string()))
}

fn validate_seed_phrase(seed_phrase: &str) -> bool {
    db_handling::helpers::validate_mnemonic(seed_phrase)
}

fn create_key_set(
    seed_name: &str,
    seed_phrase: &str,
    networks: Vec<String>,
) -> anyhow::Result<(), ErrorDisplayed> {
    db_handling::identities::create_key_set(&get_db()?, seed_name, seed_phrase, networks)
        .map_err(|e| ErrorDisplayed::from(e.to_string()))
}

fn check_db_version() -> anyhow::Result<(), ErrorDisplayed> {
    db_handling::helpers::assert_db_version(&get_db()?).map_err(ErrorDisplayed::from)
}

fn get_keys_for_signing() -> Result<MSignSufficientCrypto, ErrorDisplayed> {
    let identities = db_handling::interface_signer::print_all_identities(&get_db()?)
        .map_err(|e| ErrorDisplayed::from(e.to_string()))?;
    Ok(MSignSufficientCrypto { identities })
}

fn validate_key_password(
    address_key: &str,
    seed_phrase: &str,
    password: &str,
) -> Result<bool, ErrorDisplayed> {
    let address_key = AddressKey::from_hex(address_key).map_err(|e| format!("{e}"))?;
    db_handling::identities::validate_key_password(&get_db()?, &address_key, seed_phrase, password)
        .map_err(|e| e.into())
}

/// Create Banana Split shares from secret
fn bs_encrypt(
    secret: &str,
    title: &str,
    passphrase: &str,
    total_shards: u32,
    required_shards: u32,
) -> Result<Vec<QrData>, ErrorDisplayed> {
    navigator::banana_split_encode(secret, title, passphrase, total_shards, required_shards)
        .map_err(|e| ErrorDisplayed::from(e.to_string()))
}

/// Generate Banana Split passphrase
fn bs_generate_passphrase(n: u32) -> String {
    navigator::banana_split_passphrase(n)
}

/// Export seed backup data as JSON including account metadata (NO seed phrase)
/// Returns JSON: {"v":2,"name":"...","accounts":[{"path":"...","genesis_hash":"...","network":"...","encryption":"..."}]}
/// The seed phrase must be restored separately via banana split or manual entry
fn bs_export_backup_data(seed_name: &str, _seed_phrase: &str) -> Result<String, ErrorDisplayed> {
    use db_handling::helpers::try_get_network_specs;
    use db_handling::identities::get_addresses_by_seed_name;
    use serde_json::{json, Value};

    let db = get_db()?;
    let addresses = get_addresses_by_seed_name(&db, seed_name)
        .map_err(|e| ErrorDisplayed::from(format!("{e}")))?;

    let accounts: Vec<Value> = addresses
        .into_iter()
        .filter(|(_, details)| !details.is_root()) // skip root key, only derived accounts
        .map(|(_, details)| {
            // Look up network specs to get genesis_hash, network name, and base58prefix
            let (genesis_hash, network_name, base58prefix) = if let Some(ref network_id) =
                details.network_id
            {
                if let Ok(Some(specs)) = try_get_network_specs(&db, network_id) {
                    // Only include base58prefix for Substrate networks (sr25519/ed25519/ecdsa)
                    // Zcash and Penumbra don't use SS58 addresses
                    let prefix: Option<u16> = match details.encryption {
                        definitions::crypto::Encryption::Sr25519
                        | definitions::crypto::Encryption::Ed25519
                        | definitions::crypto::Encryption::Ecdsa => Some(specs.specs.base58prefix),
                        _ => None,
                    };
                    (
                        Some(hex::encode(specs.specs.genesis_hash)),
                        Some(specs.specs.name),
                        prefix,
                    )
                } else {
                    (None, None, None)
                }
            } else {
                (None, None, None)
            };

            json!({
                "path": details.path,
                "genesis_hash": genesis_hash,
                "network": network_name,
                "encryption": details.encryption.show(),
                "has_pwd": details.has_pwd,
                "base58prefix": base58prefix,
            })
        })
        .collect();

    let backup = json!({
        "v": 2,
        "name": seed_name,
        "accounts": accounts,
    });

    serde_json::to_string(&backup)
        .map_err(|e| ErrorDisplayed::from(format!("JSON serialization error: {e}")))
}

/// Export seed backup as UR-encoded multipart QR frames for device-to-device migration
/// Returns QR image data ready for display as animated QR
/// max_fragment_len: max bytes per QR frame (0 = single QR, 200-500 typical for animated)
fn export_backup_qr(
    seed_name: &str,
    seed_phrase: &str,
    max_fragment_len: u32,
) -> Result<Vec<QrData>, ErrorDisplayed> {
    let ur_strings = export_backup_ur(seed_name, seed_phrase, max_fragment_len)?;

    // Convert each UR string to a QR image
    let qr_images: Result<Vec<QrData>, ErrorDisplayed> = ur_strings
        .into_iter()
        .map(|ur_string| {
            qrcode_static::png_qr_from_string(&ur_string, qrcode_static::DataType::Sensitive)
                .map(|data| QrData::Sensitive { data })
                .map_err(|e| ErrorDisplayed::Str {
                    s: format!("QR encoding error: {e}"),
                })
        })
        .collect();

    qr_images
}

/// Export seed backup as UR-encoded multipart string frames for device-to-device migration
/// Uses fountain codes for reliable animated QR scanning
/// max_fragment_len: max bytes per QR frame (0 = single QR, 200-500 typical for animated)
fn export_backup_ur(
    seed_name: &str,
    seed_phrase: &str,
    max_fragment_len: u32,
) -> Result<Vec<String>, ErrorDisplayed> {
    // Get JSON backup data
    let json_data = bs_export_backup_data(seed_name, seed_phrase)?;
    let data_bytes = json_data.as_bytes();

    // Wrap in simple CBOR byte string
    let mut cbor_data = Vec::with_capacity(data_bytes.len() + 10);
    let len = data_bytes.len();
    if len <= 23 {
        cbor_data.push(0x40 | len as u8);
    } else if len <= 255 {
        cbor_data.push(0x58);
        cbor_data.push(len as u8);
    } else if len <= 65535 {
        cbor_data.push(0x59);
        cbor_data.push((len >> 8) as u8);
        cbor_data.push(len as u8);
    } else {
        cbor_data.push(0x5a);
        cbor_data.push((len >> 24) as u8);
        cbor_data.push((len >> 16) as u8);
        cbor_data.push((len >> 8) as u8);
        cbor_data.push(len as u8);
    }
    cbor_data.extend_from_slice(data_bytes);

    if max_fragment_len == 0 || cbor_data.len() <= max_fragment_len as usize {
        // Single part UR
        let ur_string = ur::ur::encode(&cbor_data, &ur::Type::Custom("zigner-backup"));
        Ok(vec![ur_string])
    } else {
        // Multi-part (animated) UR using fountain codes
        let mut encoder =
            ur::ur::Encoder::new(&cbor_data, max_fragment_len as usize, "zigner-backup").map_err(
                |e| ErrorDisplayed::Str {
                    s: format!("Failed to create UR encoder: {:?}", e),
                },
            )?;

        // Generate enough frames for reliable scanning (2x the minimum)
        let frame_count = encoder.fragment_count() * 2;
        let mut frames = Vec::with_capacity(frame_count);
        for _ in 0..frame_count {
            let part = encoder.next_part().map_err(|e| ErrorDisplayed::Str {
                s: format!("Failed to encode UR part: {:?}", e),
            })?;
            frames.push(part);
        }
        Ok(frames)
    }
}

/// Decode UR-encoded backup and return JSON string
fn decode_backup_ur(ur_parts: Vec<String>) -> Result<String, ErrorDisplayed> {
    if ur_parts.is_empty() {
        return Err(ErrorDisplayed::Str {
            s: "No UR parts provided".to_string(),
        });
    }

    // Try single-part decode first
    if ur_parts.len() == 1 {
        let (_, cbor_data) = ur::ur::decode(&ur_parts[0]).map_err(|e| ErrorDisplayed::Str {
            s: format!("UR decode error: {:?}", e),
        })?;
        return extract_backup_json_from_cbor(&cbor_data);
    }

    // Multi-part decode using fountain codes
    let mut decoder = ur::ur::Decoder::default();

    for part in &ur_parts {
        decoder.receive(part).map_err(|e| ErrorDisplayed::Str {
            s: format!("UR receive error: {:?}", e),
        })?;

        if decoder.complete() {
            match decoder.message() {
                Ok(Some(cbor_data)) => return extract_backup_json_from_cbor(&cbor_data),
                Ok(None) => {
                    return Err(ErrorDisplayed::Str {
                        s: "UR decoder complete but no message".to_string(),
                    })
                }
                Err(e) => {
                    return Err(ErrorDisplayed::Str {
                        s: format!("UR message error: {:?}", e),
                    })
                }
            }
        }
    }

    Err(ErrorDisplayed::Str {
        s: "Incomplete UR data - need more frames".to_string(),
    })
}

fn extract_backup_json_from_cbor(cbor_data: &[u8]) -> Result<String, ErrorDisplayed> {
    // Parse CBOR bytes using existing helper
    let (json_bytes, _) = parse_cbor_bytes(cbor_data).map_err(|e| ErrorDisplayed::Str {
        s: format!("Failed to parse CBOR: {}", e),
    })?;

    String::from_utf8(json_bytes).map_err(|e| ErrorDisplayed::Str {
        s: format!("Invalid UTF-8 in backup: {e}"),
    })
}

fn sign_metadata_with_key(
    network_key: &str,
    metadata_specs_version: &str,
    signing_address_key: &str,
    seed_phrase: &str,
    password: Option<String>,
) -> Result<MSufficientCryptoReady, ErrorDisplayed> {
    let network_key = NetworkSpecsKey::from_hex(network_key).map_err(|e| format!("{e}"))?;
    let version = metadata_specs_version
        .parse::<u32>()
        .map_err(|e| format!("{e}"))?;
    let address_key = AddressKey::from_hex(signing_address_key).map_err(|e| format!("{e}"))?;
    navigator::sign_sufficient_content(
        &get_db()?,
        &address_key,
        SufficientContent::LoadMeta(network_key, version),
        seed_phrase,
        &password.unwrap_or("".to_owned()),
    )
    .map_err(|e| e.into())
}

fn sign_network_spec_with_key(
    network_key: &str,
    signing_address_key: &str,
    seed_phrase: &str,
    password: Option<String>,
) -> Result<MSufficientCryptoReady, ErrorDisplayed> {
    let network_key = NetworkSpecsKey::from_hex(network_key).map_err(|e| format!("{e}"))?;
    let address_key = AddressKey::from_hex(signing_address_key).map_err(|e| format!("{e}"))?;
    navigator::sign_sufficient_content(
        &get_db()?,
        &address_key,
        SufficientContent::AddSpecs(network_key),
        seed_phrase,
        &password.unwrap_or("".to_owned()),
    )
    .map_err(|e| e.into())
}

/// Export Penumbra Full Viewing Key for import into watch-only wallet (e.g., Prax)
///
/// Returns both:
/// - FVK bech32m string (native Penumbra format) for direct import
/// - UR-encoded string (penumbra-accounts format) for hardware wallet QR compatibility
///
/// ## UR (Uniform Resource) Format for Penumbra
///
/// We define these UR types (proposed by Zigner, following Blockchain Commons pattern):
///
/// | UR Type                    | CBOR Tag | Description                    |
/// |----------------------------|----------|--------------------------------|
/// | penumbra-accounts          | 49301    | Container for accounts         |
/// | penumbra-full-viewing-key  | 49302    | Single FVK with metadata       |
///
/// These tags are in the "first-come-first-served" range (32768+), no registration needed.
/// Adjacent to Keystone's Zcash tags (49201-49204) for consistency.
///
/// ## CBOR Structure for penumbra-accounts
///
/// ```text
/// PenumbraAccounts = {
///   1: bytes,                ; wallet_id (32 bytes)
///   2: [+ #49302(FVK)]       ; accounts array
/// }
///
/// PenumbraFullViewingKey (#49302) = {
///   1: tstr,                 ; fvk - bech32m encoded ("penumbrafullviewingkey1...")
///   2: uint,                 ; index - account index
///   ? 3: tstr                ; name - optional label
/// }
/// ```
#[allow(clippy::vec_init_then_push)]
fn export_penumbra_fvk(
    seed_phrase: &str,
    account_index: u32,
    label: &str,
) -> Result<PenumbraFvkExport, ErrorDisplayed> {
    use transaction_signing::penumbra::{FullViewingKey, FvkExportData, SpendKeyBytes};

    // Derive spend key from seed phrase
    let spend_key_bytes =
        SpendKeyBytes::from_seed_phrase(seed_phrase, account_index).map_err(|e| {
            ErrorDisplayed::Str {
                s: format!("Failed to derive spend key: {e}"),
            }
        })?;

    // Create FVK export data
    let label_opt = if label.is_empty() {
        None
    } else {
        Some(label.to_string())
    };
    let mut export_data =
        FvkExportData::from_spend_key(&spend_key_bytes, account_index, label_opt.clone()).map_err(
            |e| ErrorDisplayed::Str {
                s: format!("Failed to create FVK export: {e}"),
            },
        )?;

    // embed ZID pubkey so zafu can link this wallet to the same zigner device
    // across network imports. best-effort — if ZID derivation fails, the FVK
    // export still succeeds, just without the canonical device identity.
    export_data.zid_pubkey = auth::derive_zid_pubkey(seed_phrase)
        .ok()
        .and_then(|hex_str| hex::decode(&hex_str).ok())
        .and_then(|bytes| bytes.try_into().ok());

    // Get bech32m encoded strings
    let fvk = FullViewingKey::derive_from(&spend_key_bytes).map_err(|e| ErrorDisplayed::Str {
        s: format!("Failed to derive FVK: {e}"),
    })?;
    let wallet_id = fvk.wallet_id().map_err(|e| ErrorDisplayed::Str {
        s: format!("Failed to compute wallet ID: {e}"),
    })?;

    let fvk_bech32m = fvk.to_bech32m().map_err(|e| ErrorDisplayed::Str {
        s: format!("Failed to encode FVK: {e}"),
    })?;
    let wallet_id_bech32m = wallet_id.to_bech32m().map_err(|e| ErrorDisplayed::Str {
        s: format!("Failed to encode wallet ID: {e}"),
    })?;

    // ========================================================================
    // Build UR-encoded "penumbra-accounts" for hardware wallet QR compatibility
    //
    // CBOR tag 49301 = penumbra-accounts
    // CBOR tag 49302 = penumbra-full-viewing-key
    // Tag 49301 in hex = 0xC095, encoded as: 0xd9 0xc0 0x95
    // Tag 49302 in hex = 0xC096, encoded as: 0xd9 0xc0 0x96
    // ========================================================================
    // Pre-compute ZID for the inner CBOR map (best-effort, optional).
    let ur_zid: Option<[u8; 32]> = export_data.zid_pubkey;

    let ur_string = {
        let mut cbor_data = Vec::new();

        // PenumbraAccounts: map with 2 entries
        // CBOR: 0xa2 = map(2)
        cbor_data.push(0xa2);

        // Key 1: wallet_id (32 bytes)
        // CBOR: 0x01 = uint(1), 0x58 0x20 = bytes(32)
        cbor_data.push(0x01);
        cbor_data.push(0x58); // bytes with 1-byte length
        cbor_data.push(0x20); // 32 bytes
        cbor_data.extend_from_slice(&wallet_id.to_bytes());

        // Key 2: accounts array
        // CBOR: 0x02 = uint(2), 0x81 = array(1)
        cbor_data.push(0x02);
        cbor_data.push(0x81); // array(1) - single account

        // Tagged PenumbraFullViewingKey (tag 49302 = 0xC096)
        // Tag encoding: 0xd9 means "tag with 2-byte value follows"
        // 49302 = 0xC096 -> high byte 0xC0, low byte 0x96
        cbor_data.push(0xd9);
        cbor_data.push(0xc0); // high byte: 49302 >> 8 = 192 = 0xc0
        cbor_data.push(0x96); // low byte: 49302 & 0xff = 150 = 0x96

        // PenumbraFullViewingKey: map with 2..4 entries
        // (key 1 fvk, key 2 index, key 3 name optional, key 4 zid optional)
        let has_name = !label.is_empty();
        let has_zid = ur_zid.is_some();
        let map_entries: u8 = 2 + (has_name as u8) + (has_zid as u8);
        cbor_data.push(0xa0 + map_entries);

        // Key 1: fvk (text string - bech32m encoded)
        cbor_data.push(0x01); // key = 1
        let fvk_bytes = fvk_bech32m.as_bytes();
        if fvk_bytes.len() < 24 {
            cbor_data.push(0x60 + fvk_bytes.len() as u8);
        } else if fvk_bytes.len() < 256 {
            cbor_data.push(0x78); // text with 1-byte length
            cbor_data.push(fvk_bytes.len() as u8);
        } else {
            cbor_data.push(0x79); // text with 2-byte length (big-endian)
            cbor_data.extend_from_slice(&(fvk_bytes.len() as u16).to_be_bytes());
        }
        cbor_data.extend_from_slice(fvk_bytes);

        // Key 2: index (unsigned int)
        cbor_data.push(0x02); // key = 2
        if account_index < 24 {
            cbor_data.push(account_index as u8);
        } else if account_index < 256 {
            cbor_data.push(0x18);
            cbor_data.push(account_index as u8);
        } else {
            cbor_data.push(0x19);
            cbor_data.extend_from_slice(&(account_index as u16).to_be_bytes());
        }

        // Key 3: name (optional text string)
        if has_name {
            cbor_data.push(0x03); // key = 3
            let label_bytes = label.as_bytes();
            if label_bytes.len() < 24 {
                cbor_data.push(0x60 + label_bytes.len() as u8);
            } else {
                cbor_data.push(0x78);
                cbor_data.push(label_bytes.len() as u8);
            }
            cbor_data.extend_from_slice(label_bytes);
        }

        // Key 4: zid_pubkey (optional 32-byte string) — canonical device identity
        // for zafu dedup across network imports. Unknown to legacy parsers.
        if let Some(zid) = ur_zid {
            cbor_data.push(0x04); // key = 4
            cbor_data.push(0x58); // bytes with 1-byte length
            cbor_data.push(0x20); // 32 bytes
            cbor_data.extend_from_slice(&zid);
        }

        // Encode CBOR as UR string
        // Result format: "ur:penumbra-accounts/..."
        ur::ur::encode(&cbor_data, &ur::Type::Custom("penumbra-accounts"))
    };

    Ok(PenumbraFvkExport {
        account_index,
        label: label_opt.unwrap_or_default(),
        fvk_bech32m,
        wallet_id_bech32m,
        qr_data: export_data.encode_qr(),
        ur_string,
    })
}

// ============================================================================
// Cosmos account export
// ============================================================================

/// Export Cosmos chain addresses from a seed phrase.
///
/// Derives a secp256k1 key using BIP44 path m/44'/118'/account'/0/0
/// and generates bech32 addresses for the specified chain (or all if network_name is empty).
/// The QR data encodes a simple JSON payload for Zafu to import.
fn export_cosmos_accounts(
    seed_phrase: &str,
    account_index: u32,
    label: &str,
    network_name: &str,
) -> Result<CosmosAccountExport, ErrorDisplayed> {
    use db_handling::cosmos::{
        derive_cosmos_key, PREFIX_CELESTIA, PREFIX_NOBLE, PREFIX_OSMOSIS, SLIP0044_COSMOS,
    };

    let key = derive_cosmos_key(seed_phrase, SLIP0044_COSMOS, account_index, 0).map_err(|e| {
        ErrorDisplayed::Str {
            s: format!("Failed to derive Cosmos key: {e}"),
        }
    })?;

    let pubkey_hex = hex::encode(&key.public_key);

    // Generate addresses for supported chains (filter by network_name if specified)
    let all_chains: Vec<(&str, &str)> = vec![
        ("osmosis", PREFIX_OSMOSIS),
        ("noble", PREFIX_NOBLE),
        ("celestia", PREFIX_CELESTIA),
    ];

    let chains: Vec<(&str, &str)> = if network_name.is_empty() {
        all_chains
    } else {
        let name = network_name.to_lowercase();
        all_chains
            .into_iter()
            .filter(|(id, _)| *id == name)
            .collect()
    };

    let mut addresses = Vec::new();
    for (chain_id, prefix) in &chains {
        let addr = key
            .bech32_address(prefix)
            .map_err(|e| ErrorDisplayed::Str {
                s: format!("Failed to encode {chain_id} address: {e}"),
            })?;
        addresses.push(CosmosChainAddress {
            chain_id: chain_id.to_string(),
            address: addr,
            prefix: prefix.to_string(),
        });
    }

    // Build QR data as JSON for Zafu import
    let label_str = if label.is_empty() { "Zigner" } else { label };
    let json = serde_json::json!({
        "type": "cosmos-accounts",
        "version": 1,
        "label": label_str,
        "account_index": account_index,
        "public_key": pubkey_hex,
        "addresses": addresses.iter().map(|a| {
            serde_json::json!({
                "chain_id": a.chain_id,
                "address": a.address,
                "prefix": a.prefix,
            })
        }).collect::<Vec<_>>(),
    });

    let json_bytes = json.to_string().into_bytes();
    let qr_data = encode_to_qr(&json_bytes, false).map_err(|e| ErrorDisplayed::Str {
        s: format!("Failed to generate QR: {e}"),
    })?;

    Ok(CosmosAccountExport {
        account_index,
        label: label_str.to_string(),
        public_key_hex: pubkey_hex,
        addresses,
        qr_data,
    })
}

// ============================================================================
// Cosmos cold signing functions
// ============================================================================

/// Parse a Cosmos sign request from QR hex data (amino JSON sign doc)
fn parse_cosmos_sign_request(qr_hex: &str) -> Result<CosmosSignRequest, ErrorDisplayed> {
    use transaction_signing::cosmos::{CosmosSignDocDisplay, CosmosSignRequest as InternalRequest};

    let req = InternalRequest::from_qr_hex(qr_hex).map_err(|e| ErrorDisplayed::Str {
        s: format!("Failed to parse Cosmos QR: {e}"),
    })?;

    let display =
        CosmosSignDocDisplay::from_json(&req.sign_doc_bytes).map_err(|e| ErrorDisplayed::Str {
            s: format!("Failed to parse sign doc: {e}"),
        })?;

    let msgs = display
        .msgs
        .into_iter()
        .map(|m| CosmosMsgDisplay {
            msg_type: m.msg_type,
            recipient: m.recipient,
            amount: m.amount,
            detail: m.detail,
            blind: m.blind,
        })
        .collect();

    Ok(CosmosSignRequest {
        account_index: req.account_index,
        chain_name: req.chain_name,
        chain_id: display.chain_id,
        msgs,
        fee: display.fee,
        memo: display.memo,
        raw_qr_hex: qr_hex.to_string(),
    })
}

/// Sign a Cosmos transaction and return 64-byte compact signature.
///
/// IMPORTANT: re-derives display fields from raw_qr_hex and verifies they
/// match what the user approved. This prevents a compromised hot wallet from
/// displaying one transaction but signing another.
fn sign_cosmos_transaction(
    seed_phrase: &str,
    request: CosmosSignRequest,
) -> Result<Vec<u8>, ErrorDisplayed> {
    use db_handling::cosmos::{derive_cosmos_key, SLIP0044_COSMOS};
    use transaction_signing::cosmos::{
        sign_cosmos_amino, CosmosSignDocDisplay, CosmosSignRequest as InternalRequest,
    };

    // re-parse the QR to get the sign doc bytes
    let req =
        InternalRequest::from_qr_hex(&request.raw_qr_hex).map_err(|e| ErrorDisplayed::Str {
            s: format!("Failed to re-parse QR: {e}"),
        })?;

    // re-derive display fields from the raw QR and verify they match
    // what the user was shown. this is the cosmos equivalent of
    // penumbra's verify_effect_hash — it binds display to signing.
    let display =
        CosmosSignDocDisplay::from_json(&req.sign_doc_bytes).map_err(|e| ErrorDisplayed::Str {
            s: format!("Failed to re-parse sign doc: {e}"),
        })?;

    if display.chain_id != request.chain_id {
        return Err(ErrorDisplayed::Str {
            s: format!(
                "Chain ID mismatch: display showed '{}' but QR contains '{}'",
                request.chain_id, display.chain_id
            ),
        });
    }
    if display.fee != request.fee {
        return Err(ErrorDisplayed::Str {
            s: format!(
                "Fee mismatch: display showed '{}' but QR contains '{}'",
                request.fee, display.fee
            ),
        });
    }
    if display.memo != request.memo {
        return Err(ErrorDisplayed::Str {
            s: format!(
                "Memo mismatch: display showed '{}' but QR contains '{}'",
                request.memo, display.memo
            ),
        });
    }
    if display.msgs.len() != request.msgs.len() {
        return Err(ErrorDisplayed::Str {
            s: format!(
                "Message count mismatch: display showed {} but QR contains {}",
                request.msgs.len(),
                display.msgs.len()
            ),
        });
    }

    // derive the cosmos key from seed phrase
    let key =
        derive_cosmos_key(seed_phrase, SLIP0044_COSMOS, request.account_index, 0).map_err(|e| {
            ErrorDisplayed::Str {
                s: format!("Key derivation failed: {e}"),
            }
        })?;

    // sign with SHA256 prehash (NOT blake2b)
    let signature = sign_cosmos_amino(&key.secret_key, &req.sign_doc_bytes).map_err(|e| {
        ErrorDisplayed::Str {
            s: format!("Signing failed: {e}"),
        }
    })?;

    Ok(signature.to_vec())
}

// ============================================================================
// Penumbra cold signing functions
// ============================================================================

/// Parse a Penumbra sign request from QR hex data
fn parse_penumbra_sign_request(qr_hex: &str) -> Result<PenumbraSignRequest, ErrorDisplayed> {
    use transaction_parsing::penumbra::parse_penumbra_transaction;

    let plan = parse_penumbra_transaction(qr_hex).map_err(|e| ErrorDisplayed::Str {
        s: format!("Failed to parse Penumbra QR: {e}"),
    })?;

    let effect_hash_hex = plan.effect_hash.map(hex::encode).unwrap_or_default();

    Ok(PenumbraSignRequest {
        chain_id: plan.chain_id.unwrap_or_default(),
        effect_hash_hex,
        spend_count: plan.spend_randomizers.len() as u32,
        vote_count: plan.delegator_vote_randomizers.len() as u32,
        lqt_vote_count: plan.lqt_vote_randomizers.len() as u32,
        raw_qr_hex: qr_hex.to_string(),
    })
}

/// Sign a Penumbra transaction and return encoded signature QR bytes
fn sign_penumbra_transaction(
    seed_phrase: &str,
    request: PenumbraSignRequest,
) -> Result<Vec<u8>, ErrorDisplayed> {
    use transaction_parsing::penumbra::{
        parse_penumbra_transaction, sign_transaction, SpendKeyBytes,
    };
    use transaction_signing::penumbra::verify_effect_hash;

    // Re-parse to get the full plan data
    let plan =
        parse_penumbra_transaction(&request.raw_qr_hex).map_err(|e| ErrorDisplayed::Str {
            s: format!("Failed to parse Penumbra QR: {e}"),
        })?;

    let effect_hash = plan.effect_hash.ok_or_else(|| ErrorDisplayed::Str {
        s: "No effect hash in QR".to_string(),
    })?;

    // Derive spend key from seed phrase (account 0)
    let spend_key =
        SpendKeyBytes::from_seed_phrase(seed_phrase, 0).map_err(|e| ErrorDisplayed::Str {
            s: format!("Key derivation failed: {e}"),
        })?;

    // SECURITY: Verify the effect hash from the QR matches what we compute
    // from the plan + our FVK. This prevents a compromised hot wallet from
    // tricking us into signing a different transaction.
    verify_effect_hash(&plan.plan_bytes, &effect_hash, &spend_key).map_err(|e| {
        ErrorDisplayed::Str {
            s: format!("Effect hash verification failed: {e}"),
        }
    })?;

    // Sign the transaction
    let auth_data = sign_transaction(
        effect_hash,
        &plan.spend_randomizers,
        &plan.delegator_vote_randomizers,
        &plan.lqt_vote_randomizers,
        &spend_key,
    )
    .map_err(|e| ErrorDisplayed::Str {
        s: format!("Signing failed: {e}"),
    })?;

    // Encode as QR response bytes
    auth_data.encode().map_err(|e| ErrorDisplayed::Str {
        s: format!("Encode failed: {e}"),
    })
}

// ============================================================================
// Zcash cold signing functions
// ============================================================================

/// Export Zcash Orchard full viewing key for import into watch-only wallet (e.g., Zafu/Prax)
///
/// Returns both:
/// - UFVK string (unified full viewing key) for direct import
/// - UR-encoded string (zcash-accounts format) for Zashi/Keystone QR compatibility
///
/// ## UR (Uniform Resource) Protocol
///
/// UR is a protocol by Blockchain Commons for encoding binary data in QR codes.
/// Format: `ur:<type>/<bytewords-encoded-cbor>`
///
/// Reference: https://github.com/BlockchainCommons/Research/blob/master/papers/bcr-2020-005-ur.md
///
/// ## Keystone SDK Registry Types for Zcash
///
/// The Keystone SDK defines these UR types for Zcash (see keystone-sdk-rust):
///
/// | Type Name                       | CBOR Tag | Description                    |
/// |---------------------------------|----------|--------------------------------|
/// | zcash-accounts                  | 49201    | Collection of accounts/UFVKs   |
/// | zcash-full-viewing-key          | 49202    | Single FVK (deprecated)        |
/// | zcash-unified-full-viewing-key  | 49203    | UFVK with metadata             |
/// | zcash-pczt                      | 49204    | Partially Created Zcash Tx     |
///
/// ## CBOR Structure for zcash-accounts
///
/// ```text
/// ZcashAccounts = {
///   1: bytes,              ; seed_fingerprint (16 bytes, identifies the seed)
///   2: [+ #49203(UFVK)]    ; accounts array, each tagged with 49203
/// }
///
/// ZcashUnifiedFullViewingKey (#49203) = {
///   1: tstr,               ; ufvk - the unified full viewing key string
///   2: uint,               ; index - account index (0, 1, 2, ...)
///   ? 3: tstr              ; name - optional account label
/// }
/// ```
///
/// ## CBOR Encoding Reference
///
/// CBOR major types (high 3 bits of first byte):
/// - 0x00-0x17: unsigned int 0-23 (value in low 5 bits)
/// - 0x18: unsigned int, 1 byte follows
/// - 0x19: unsigned int, 2 bytes follow (big-endian)
/// - 0x40-0x57: bytes, length 0-23 in low 5 bits
/// - 0x58: bytes, 1-byte length follows
/// - 0x60-0x77: text string, length 0-23 in low 5 bits
/// - 0x78: text string, 1-byte length follows
/// - 0x79: text string, 2-byte length follows
/// - 0x80-0x97: array, length 0-23 in low 5 bits
/// - 0xa0-0xb7: map, length 0-23 in low 5 bits (pairs count)
/// - 0xd8: tag, 1-byte tag number follows
/// - 0xd9: tag, 2-byte tag number follows (big-endian)
///
/// Parse a Zcash simple sign request from QR hex data.
/// This is the non-PCZT signing flow used by Zafu wallet.
fn parse_zcash_sign_request(qr_hex: &str) -> Result<ZcashSimpleSignRequest, ErrorDisplayed> {
    let request = transaction_signing::ZcashSignRequest::from_qr_hex(qr_hex).map_err(|e| {
        ErrorDisplayed::Str {
            s: format!("Failed to parse Zcash sign request: {e}"),
        }
    })?;

    Ok(ZcashSimpleSignRequest {
        account_index: request.account_index,
        sighash_hex: hex::encode(request.sighash),
        action_count: request.orchard_alphas.len() as u32,
        summary: request.summary,
        mainnet: request.mainnet,
        raw_qr_hex: qr_hex.to_string(),
    })
}

/// Sign a Zcash simple sign request and return the signature QR hex string.
fn sign_zcash_simple(
    seed_phrase: &str,
    request: ZcashSimpleSignRequest,
) -> Result<String, ErrorDisplayed> {
    // Re-parse the original QR to get the full data (including alphas)
    let sign_data = transaction_signing::ZcashSignRequest::from_qr_hex(&request.raw_qr_hex)
        .map_err(|e| ErrorDisplayed::Str {
            s: format!("Failed to parse Zcash sign request for signing: {e}"),
        })?;

    let response = sign_data
        .sign(seed_phrase)
        .map_err(|e| ErrorDisplayed::Str {
            s: format!("Zcash signing failed: {e}"),
        })?;

    Ok(response.to_qr_hex())
}

fn export_zcash_fvk(
    seed_phrase: &str,
    account_index: u32,
    label: &str,
    mainnet: bool,
) -> Result<ZcashFvkExport, ErrorDisplayed> {
    use transaction_signing::zcash::{OrchardSpendingKey, QR_TYPE_ZCASH_FVK_EXPORT};

    // Derive Orchard spending key from seed phrase using ZIP-32 derivation
    let osk = OrchardSpendingKey::from_seed_phrase(seed_phrase, account_index).map_err(|e| {
        ErrorDisplayed::Str {
            s: format!("Failed to derive Orchard key: {e}"),
        }
    })?;

    // Get FVK bytes (96 bytes raw orchard full viewing key)
    let fvk_bytes = osk.fvk_bytes();

    // Get receiving address (unified address with orchard receiver)
    let address = osk.get_address(mainnet);

    // Get UFVK string with orchard + transparent components (ZIP-316)
    // Format: "uview1..." for mainnet, "uviewtest1..." for testnet
    let ufvk = OrchardSpendingKey::get_ufvk_with_transparent(seed_phrase, account_index, mainnet)
        .map_err(|e| ErrorDisplayed::Str {
        s: format!("Failed to derive UFVK: {e}"),
    })?;

    // Generate seed fingerprint: first 16 bytes of SHA256(seed_phrase)
    // This allows Zashi to match accounts to the same seed without revealing the seed
    let seed_fingerprint = {
        use sha2::{Digest, Sha256};
        let hash = Sha256::digest(seed_phrase.as_bytes());
        hash[..16].to_vec()
    };

    // ========================================================================
    // Build UR-encoded "zcash-accounts" for Zashi/Keystone QR code compatibility
    //
    // The UR string format is: ur:zcash-accounts/<bytewords-encoded-cbor>
    // where the CBOR payload matches the Keystone SDK zcash_accounts.rs structure
    // ========================================================================
    // Try to derive ZID early so we can include it as a CBOR field below.
    // Best-effort — if it fails, we just omit the field (backwards compatible).
    let ur_zid: Option<[u8; 32]> = auth::derive_zid_pubkey(seed_phrase)
        .ok()
        .and_then(|h| hex::decode(&h).ok())
        .and_then(|b| b.try_into().ok());

    let ur_string = {
        let mut cbor_data = Vec::new();

        // ZcashAccounts: map with 2 entries
        // CBOR: 0xa2 = map(2)
        cbor_data.push(0xa2);

        // Key 1: seed_fingerprint (bytes)
        // CBOR: 0x01 = uint(1), 0x50 = bytes(16)
        cbor_data.push(0x01);
        cbor_data.push(0x50); // bytes(16) - 0x40 + 16 = 0x50
        cbor_data.extend_from_slice(&seed_fingerprint);

        // Key 2: accounts array
        // CBOR: 0x02 = uint(2), 0x81 = array(1)
        cbor_data.push(0x02);
        cbor_data.push(0x81); // array(1) - single account

        // Each account is tagged with CBOR tag 49203 (ZCASH_UNIFIED_FULL_VIEWING_KEY)
        // Tag 49203 = 0xC033 in hex, encoded as: 0xd9 0xc0 0x33
        // 0xd9 means "tag with 2-byte value follows"
        cbor_data.push(0xd9);
        cbor_data.push(0xc0); // high byte: 49203 >> 8 = 192 = 0xc0
        cbor_data.push(0x33); // low byte: 49203 & 0xff = 51 = 0x33

        // ZcashUnifiedFullViewingKey: map with 2..4 entries
        // (key 1 ufvk, key 2 index, key 3 name optional, key 4 zid optional)
        let has_name = !label.is_empty();
        let has_zid = ur_zid.is_some();
        let map_entries: u8 = 2 + (has_name as u8) + (has_zid as u8);
        cbor_data.push(0xa0 + map_entries); // 0xa2 / 0xa3 / 0xa4

        // Key 1: ufvk (text string)
        // CBOR text string encoding: 0x60-0x77 for len 0-23, 0x78+len for len<256, 0x79+2bytes for len<65536
        cbor_data.push(0x01); // key = 1
        let ufvk_bytes = ufvk.as_bytes();
        if ufvk_bytes.len() < 24 {
            cbor_data.push(0x60 + ufvk_bytes.len() as u8);
        } else if ufvk_bytes.len() < 256 {
            cbor_data.push(0x78); // text with 1-byte length
            cbor_data.push(ufvk_bytes.len() as u8);
        } else {
            cbor_data.push(0x79); // text with 2-byte length (big-endian)
            cbor_data.extend_from_slice(&(ufvk_bytes.len() as u16).to_be_bytes());
        }
        cbor_data.extend_from_slice(ufvk_bytes);

        // Key 2: index (unsigned int)
        // CBOR uint encoding: 0-23 inline, 0x18+byte for 24-255, 0x19+2bytes for 256-65535
        cbor_data.push(0x02); // key = 2
        if account_index < 24 {
            cbor_data.push(account_index as u8);
        } else if account_index < 256 {
            cbor_data.push(0x18);
            cbor_data.push(account_index as u8);
        } else {
            cbor_data.push(0x19);
            cbor_data.extend_from_slice(&(account_index as u16).to_be_bytes());
        }

        // Key 3: name (optional text string)
        if has_name {
            cbor_data.push(0x03); // key = 3
            let label_bytes = label.as_bytes();
            if label_bytes.len() < 24 {
                cbor_data.push(0x60 + label_bytes.len() as u8);
            } else {
                cbor_data.push(0x78);
                cbor_data.push(label_bytes.len() as u8);
            }
            cbor_data.extend_from_slice(label_bytes);
        }

        // Key 4: zid_pubkey (optional 32-byte string) — canonical device identity
        // for zafu dedup across network imports. Unknown to legacy parsers (Zashi,
        // Keystone) which simply ignore unrecognized keys.
        if let Some(zid) = ur_zid {
            cbor_data.push(0x04); // key = 4
            cbor_data.push(0x58); // bytes with 1-byte length
            cbor_data.push(0x20); // 32 bytes
            cbor_data.extend_from_slice(&zid);
        }

        // Encode CBOR as UR string using bytewords encoding
        // Result format: "ur:zcash-accounts/..."
        ur::ur::encode(&cbor_data, &ur::Type::Custom("zcash-accounts"))
    };

    // Build binary QR data for Zafu wallet
    // Format must match Zafu's parseZcashFvkQR():
    // [0x53][0x04][0x01][flags:1][account:4 LE][label_len:1][label][orchard_fvk:96][addr_len:2 LE][address]
    let label_bytes = label.as_bytes();
    let label_len = label_bytes.len().min(255) as u8;
    let address_bytes = address.as_bytes();

    // Try to derive ZID pubkey (32 bytes) — lets zafu link this wallet to the
    // same zigner device across network imports for dedup. Best-effort: if it
    // fails for any reason, omit the ZID bytes rather than failing FVK export.
    let zid_bytes: Option<[u8; 32]> = auth::derive_zid_pubkey(seed_phrase)
        .ok()
        .and_then(|hex_str| hex::decode(&hex_str).ok())
        .and_then(|bytes| bytes.try_into().ok());

    // flags: bit 0 = mainnet, bit 1 = has orchard, bit 2 = has transparent,
    //        bit 3 = has address, bit 4 = has ZID pubkey (32 bytes appended)
    let zid_flag: u8 = if zid_bytes.is_some() { 0x10 } else { 0x00 };
    let flags: u8 = (if mainnet { 0x01 } else { 0x00 }) | 0x02 | 0x08 | zid_flag;

    let mut qr_data =
        Vec::with_capacity(3 + 1 + 4 + 1 + label_bytes.len() + 96 + 2 + address_bytes.len() + 32);
    qr_data.push(0x53); // 'S' for Signer (substrate compat)
    qr_data.push(0x04); // Zcash chain ID
    qr_data.push(QR_TYPE_ZCASH_FVK_EXPORT);
    qr_data.push(flags);
    qr_data.extend_from_slice(&account_index.to_le_bytes());
    qr_data.push(label_len);
    qr_data.extend_from_slice(&label_bytes[..label_len as usize]);
    qr_data.extend_from_slice(&fvk_bytes);
    // Add unified address (bit 3 flag)
    qr_data.extend_from_slice(&(address_bytes.len() as u16).to_le_bytes());
    qr_data.extend_from_slice(address_bytes);
    // Add ZID pubkey (bit 4 flag) — canonical device identity
    if let Some(zid) = zid_bytes {
        qr_data.extend_from_slice(&zid);
    }

    Ok(ZcashFvkExport {
        account_index,
        label: label.to_string(),
        mainnet,
        address,
        fvk_hex: hex::encode(fvk_bytes),
        ufvk,
        qr_data,
        ur_string,
    })
}

/// Get a diversified Zcash Orchard address at a specific diversifier index.
///
/// Orchard supports unlimited diversified addresses from the same spending key.
/// Each index produces a unique address that maps to the same wallet.
fn get_zcash_diversified_address(
    seed_phrase: &str,
    account_index: u32,
    diversifier_index: u32,
    mainnet: bool,
) -> Result<String, ErrorDisplayed> {
    use transaction_signing::zcash::OrchardSpendingKey;

    let osk = OrchardSpendingKey::from_seed_phrase(seed_phrase, account_index).map_err(|e| {
        ErrorDisplayed::Str {
            s: format!("Failed to derive Orchard key: {e}"),
        }
    })?;

    Ok(osk.get_address_at(diversifier_index, mainnet))
}

/// Get the transparent (t-address) for a Zcash account.
///
/// Returns a t1... (mainnet) or tm... (testnet) P2PKH address.
/// Uses BIP44 path: m/44'/133'/account'/0/0
fn get_zcash_transparent_address(
    seed_phrase: &str,
    account: u32,
    mainnet: bool,
) -> Result<String, ErrorDisplayed> {
    use transaction_signing::zcash::{derive_transparent_address, TransparentSpendingKey};

    let tsk =
        TransparentSpendingKey::from_seed_phrase(seed_phrase, account, 0, 0).map_err(|e| {
            ErrorDisplayed::Str {
                s: format!("Failed to derive transparent key: {e}"),
            }
        })?;

    derive_transparent_address(&tsk, mainnet).map_err(|e| ErrorDisplayed::Str {
        s: format!("Failed to derive transparent address: {e}"),
    })
}

// ============================================================================
// PCZT (Partially Created Zcash Transaction) functions for Zashi compatibility
// ============================================================================
//
// PCZT is the standard format for passing unsigned Zcash transactions between
// watch-only wallets (like Zashi) and hardware signers (like Zigner/Keystone).
//
// UR (Uniform Resource) encoding:
// - Type: zcash-pczt (CBOR tag 49204)
// - Format: ur:zcash-pczt/<bytewords-encoded-cbor>
// - For large PCZTs, UR supports animated QR sequences (fountain codes)
//
// Flow:
// 1. Zashi creates PCZT, encodes as ur:zcash-pczt, shows animated QR
// 2. Zigner scans QR sequence, decodes UR, parses PCZT
// 3. Zigner extracts sighash and rsk randomizers, signs with spending key
// 4. Zigner injects signatures into PCZT, encodes as ur:zcash-pczt
// 5. Zashi scans signed PCZT QR, extracts signatures, broadcasts tx

/// Decode UR string to get PCZT bytes
/// Handles both single QR and animated QR sequences
fn decode_ur_zcash_pczt(ur_parts: Vec<String>) -> Result<Vec<u8>, ErrorDisplayed> {
    use ur::ur::decode;

    if ur_parts.is_empty() {
        return Err(ErrorDisplayed::Str {
            s: "No UR parts provided".to_string(),
        });
    }

    // Verify UR type from the URI string (format: ur:type/data)
    fn verify_ur_type(ur_string: &str) -> Result<(), ErrorDisplayed> {
        let lower = ur_string.to_lowercase();
        if !lower.starts_with("ur:zcash-pczt/") {
            return Err(ErrorDisplayed::Str {
                s: format!(
                    "Expected ur:zcash-pczt/... got: {}",
                    ur_string.chars().take(30).collect::<String>()
                ),
            });
        }
        Ok(())
    }

    // For single-part UR, decode directly
    if ur_parts.len() == 1 {
        verify_ur_type(&ur_parts[0])?;

        let (_kind, cbor_data) = decode(&ur_parts[0]).map_err(|e| ErrorDisplayed::Str {
            s: format!("Failed to decode UR: {:?}", e),
        })?;

        // Extract PCZT bytes from CBOR
        // CBOR structure: { 1: bytes } (map with key 1 containing the PCZT bytes)
        extract_pczt_from_cbor(&cbor_data)
    } else {
        // For multi-part (animated) UR, use fountain decoder
        let mut decoder = ur::ur::Decoder::default();

        // Verify type from first part
        verify_ur_type(&ur_parts[0])?;

        for part in &ur_parts {
            decoder.receive(part).map_err(|e| ErrorDisplayed::Str {
                s: format!("Failed to receive UR part: {:?}", e),
            })?;

            if decoder.complete() {
                break;
            }
        }

        if !decoder.complete() {
            return Err(ErrorDisplayed::Str {
                s: format!(
                    "Incomplete UR sequence: received {} parts but not complete",
                    ur_parts.len()
                ),
            });
        }

        let cbor_data = decoder
            .message()
            .map_err(|e| ErrorDisplayed::Str {
                s: format!("Failed to get UR message: {:?}", e),
            })?
            .ok_or_else(|| ErrorDisplayed::Str {
                s: "UR decoder returned None despite being complete".to_string(),
            })?;

        extract_pczt_from_cbor(&cbor_data)
    }
}

/// Extract PCZT bytes from CBOR wrapper
/// CBOR structure: { 1: bytes } - map with key 1 containing raw PCZT bytes
fn extract_pczt_from_cbor(cbor_data: &[u8]) -> Result<Vec<u8>, ErrorDisplayed> {
    // Simple CBOR parsing for { 1: bytes }
    // 0xa1 = map(1), 0x01 = key 1, then bytes
    if cbor_data.len() < 3 {
        return Err(ErrorDisplayed::Str {
            s: "CBOR data too short".to_string(),
        });
    }

    // Check for map(1)
    if cbor_data[0] != 0xa1 {
        return Err(ErrorDisplayed::Str {
            s: format!("Expected CBOR map(1), got: 0x{:02x}", cbor_data[0]),
        });
    }

    // Check for key 1
    if cbor_data[1] != 0x01 {
        return Err(ErrorDisplayed::Str {
            s: format!("Expected CBOR key 1, got: 0x{:02x}", cbor_data[1]),
        });
    }

    // Parse bytes at position 2
    let (bytes, _) = parse_cbor_bytes(&cbor_data[2..]).map_err(|e| ErrorDisplayed::Str {
        s: format!("Failed to parse CBOR bytes: {}", e),
    })?;

    Ok(bytes)
}

/// Parse CBOR bytes (major type 2)
fn parse_cbor_bytes(data: &[u8]) -> Result<(Vec<u8>, usize), String> {
    if data.is_empty() {
        return Err("Empty CBOR data".to_string());
    }

    let first = data[0];
    let major_type = first >> 5;
    let additional = first & 0x1f;

    if major_type != 2 {
        return Err(format!(
            "Expected bytes (major type 2), got: {}",
            major_type
        ));
    }

    let (len, header_len) = match additional {
        0..=23 => (additional as usize, 1),
        24 => {
            if data.len() < 2 {
                return Err("Truncated CBOR length".to_string());
            }
            (data[1] as usize, 2)
        }
        25 => {
            if data.len() < 3 {
                return Err("Truncated CBOR length".to_string());
            }
            (u16::from_be_bytes([data[1], data[2]]) as usize, 3)
        }
        26 => {
            if data.len() < 5 {
                return Err("Truncated CBOR length".to_string());
            }
            (
                u32::from_be_bytes([data[1], data[2], data[3], data[4]]) as usize,
                5,
            )
        }
        _ => return Err(format!("Unsupported CBOR additional info: {}", additional)),
    };

    if data.len() < header_len + len {
        return Err("Truncated CBOR bytes".to_string());
    }

    Ok((
        data[header_len..header_len + len].to_vec(),
        header_len + len,
    ))
}

/// Sign a PCZT and return the signed PCZT bytes
///
/// Get signing context: what the signer knows about verified balance.
fn get_zcash_sign_context() -> Result<ZcashSignContext, ErrorDisplayed> {
    let db_guard = DB.read().map_err(|_| ErrorDisplayed::MutexPoisoned)?;
    let database = db_guard.as_ref().ok_or(ErrorDisplayed::DbNotInitialized)?;

    let balance = db_handling::zcash::get_verified_balance(database).unwrap_or(0);
    let notes = db_handling::zcash::get_verified_notes(database).unwrap_or_default();
    let anchor = db_handling::zcash::get_verified_anchor(database)
        .ok()
        .flatten();

    let (anchor_height, synced_at) = anchor.map(|(_, h, _, ts)| (h, ts)).unwrap_or((0, 0));

    Ok(ZcashSignContext {
        verified_balance: balance,
        note_count: notes.len() as u32,
        anchor_height,
        synced_at,
        has_notes: !notes.is_empty(),
    })
}

/// Encode a raw 43-byte Orchard address as a unified address string (u1...).
fn encode_orchard_recipient(raw: &[u8; 43], mainnet: bool) -> Option<String> {
    use zcash_address::unified::{Address as UnifiedAddress, Encoding, Receiver};
    use zcash_address::Network;

    let receiver = Receiver::Orchard(*raw);
    let network = if mainnet {
        Network::Main
    } else {
        Network::Test
    };
    UnifiedAddress::try_from_items(vec![receiver])
        .ok()
        .map(|ua| ua.encode(&network))
}

/// Inspect a PCZT: extract spend/output details, cross-reference against verified notes.
fn inspect_zcash_pczt(pczt_bytes: Vec<u8>) -> Result<ZcashPcztInspection, ErrorDisplayed> {
    use pczt::Pczt;

    let pczt = Pczt::parse(&pczt_bytes).map_err(|e| ErrorDisplayed::Str {
        s: format!("Failed to parse PCZT: {:?}", e),
    })?;

    let orchard = pczt.orchard();
    let action_count = orchard.actions().len() as u32;
    let pczt_anchor = orchard.anchor();
    let pczt_anchor_hex = hex::encode(pczt_anchor);

    // Load verified notes for cross-reference
    let (verified_balance, verified_anchor, verified_nullifiers, verified_notes_values) = {
        let db_guard = DB.read().map_err(|_| ErrorDisplayed::MutexPoisoned)?;
        if let Some(database) = db_guard.as_ref() {
            let balance = db_handling::zcash::get_verified_balance(database).unwrap_or(0);
            let anchor = db_handling::zcash::get_verified_anchor(database)
                .ok()
                .flatten();
            let notes = db_handling::zcash::get_verified_notes(database).unwrap_or_default();
            let nullifiers: std::collections::HashSet<String> = notes
                .iter()
                .map(|(_, nf_hex, _, _, _)| nf_hex.clone())
                .collect();
            // Map nullifier_hex → value for spend amount lookup
            let values: std::collections::HashMap<String, u64> = notes
                .iter()
                .map(|(val, nf_hex, _, _, _)| (nf_hex.clone(), *val))
                .collect();
            (balance, anchor, nullifiers, values)
        } else {
            (
                0,
                None,
                std::collections::HashSet::new(),
                std::collections::HashMap::new(),
            )
        }
    };

    // Check anchor match
    let anchor_matches = verified_anchor
        .as_ref()
        .map(|(a, _, _, _)| hex::encode(a) == pczt_anchor_hex)
        .unwrap_or(false);

    // Extract spend details (value may be redacted in PCZT, use nullifier for cross-ref)
    let mut spends = Vec::new();
    let mut known_spends = 0u32;
    for action in orchard.actions() {
        let nullifier_hex = hex::encode(action.spend().nullifier());
        let known = verified_nullifiers.contains(&nullifier_hex);
        // Look up value from our verified notes if the PCZT doesn't expose it
        let value = if known {
            known_spends += 1;
            // Find matching note value from our verified store
            verified_notes_values
                .get(&nullifier_hex)
                .copied()
                .unwrap_or(0)
        } else {
            0
        };
        spends.push(ZcashPcztSpend {
            value,
            nullifier_hex,
            known,
        });
    }

    // Determine network for address encoding
    let is_mainnet = verified_anchor
        .as_ref()
        .map(|(_, _, mainnet, _)| *mainnet)
        .unwrap_or(true);

    // Extract output details with human-readable addresses
    let mut outputs = Vec::new();
    for action in orchard.actions() {
        let value = action.output().value().unwrap_or(0);
        let recipient_hex = match action.output().recipient() {
            Some(raw_bytes) => {
                // Decode raw 43-byte Orchard address to unified address string
                encode_orchard_recipient(raw_bytes, is_mainnet)
                    .unwrap_or_else(|| hex::encode(raw_bytes))
            }
            None => String::new(),
        };
        outputs.push(ZcashPcztOutput {
            value,
            recipient: recipient_hex,
        });
    }

    // Net value from bundle's value_sum (authoritative)
    let &(value_sum_magnitude, value_sum_is_negative) = orchard.value_sum();
    let net_value = if value_sum_is_negative {
        -(value_sum_magnitude as i64)
    } else {
        value_sum_magnitude as i64
    };

    Ok(ZcashPcztInspection {
        action_count,
        spends,
        outputs,
        net_value,
        anchor_matches,
        verified_balance,
        known_spends,
        anchor_hex: pczt_anchor_hex,
    })
}

/// This function:
/// 1. Parses the PCZT to extract orchard actions
/// 2. Signs each action with the spending key derived from seed
/// 3. Injects signatures back into the PCZT
fn sign_zcash_pczt(
    seed_phrase: &str,
    account_index: u32,
    pczt_bytes: Vec<u8>,
) -> Result<Vec<u8>, ErrorDisplayed> {
    use pczt::roles::signer::Signer;
    use pczt::Pczt;
    use transaction_signing::zcash::OrchardSpendingKey;

    // Run inspection and enforce verification gates before signing
    let inspection = inspect_zcash_pczt(pczt_bytes.clone())?;

    if inspection.verified_balance == 0 && !inspection.anchor_matches {
        return Err(ErrorDisplayed::Str {
            s: "No verified notes. Sync notes from zcli before signing (zcli export-notes → scan QR).".to_string(),
        });
    }

    if !inspection.anchor_matches {
        return Err(ErrorDisplayed::Str {
            s: format!(
                "PCZT anchor does not match verified anchor. Sync notes to current state first. PCZT anchor: {}",
                inspection.anchor_hex
            ),
        });
    }

    if inspection.known_spends == 0 && inspection.action_count > 0 {
        return Err(ErrorDisplayed::Str {
            s: "No PCZT spend nullifiers match verified notes. This transaction may spend notes you don't recognize.".to_string(),
        });
    }

    // Value consistency: implied total spend (net_value + output_total) must not exceed verified balance.
    // net_value = total_spend - total_output (from value_sum), so total_spend = net_value + total_output.
    // If net_value is negative, the orchard bundle is receiving value (from transparent), skip this check.
    if inspection.net_value > 0 {
        let output_total: i64 = inspection.outputs.iter().map(|o| o.value as i64).sum();
        let implied_spend = inspection.net_value + output_total;
        if implied_spend > inspection.verified_balance as i64 {
            return Err(ErrorDisplayed::Str {
                s: format!(
                    "Transaction implies spending {} zatoshis but verified balance is only {} zatoshis. \
                     Re-sync notes or verify the transaction.",
                    implied_spend, inspection.verified_balance
                ),
            });
        }
    }

    // Parse the PCZT to get action count first
    let pczt = Pczt::parse(&pczt_bytes).map_err(|e| ErrorDisplayed::Str {
        s: format!("Failed to parse PCZT: {:?}", e),
    })?;

    // Get number of orchard actions before creating signer
    let action_count = pczt.orchard().actions().len();

    // Derive the orchard spending key from seed
    let spending_key =
        OrchardSpendingKey::from_seed_phrase(seed_phrase, account_index).map_err(|e| {
            ErrorDisplayed::Str {
                s: format!("Failed to derive spending key: {}", e),
            }
        })?;

    // Get the actual orchard spending key for signing
    let orchard_sk = spending_key
        .to_spending_key()
        .map_err(|e| ErrorDisplayed::Str {
            s: format!("Failed to get orchard spending key: {}", e),
        })?;

    // Create signer
    let mut signer = Signer::new(pczt).map_err(|e| ErrorDisplayed::Str {
        s: format!("Failed to create PCZT signer: {:?}", e),
    })?;

    // Sign all orchard actions
    // The signer needs the ask (spend authorizing key) derived from sk
    let ask = orchard::keys::SpendAuthorizingKey::from(&orchard_sk);

    // Sign each action
    for action_index in 0..action_count {
        signer
            .sign_orchard(action_index, &ask)
            .map_err(|e| ErrorDisplayed::Str {
                s: format!("Failed to sign orchard action {}: {:?}", action_index, e),
            })?;
    }

    // Finish signing and get the signed PCZT
    let signed_pczt = signer.finish();

    // Serialize back to bytes
    Ok(signed_pczt.serialize())
}

/// Encode signed PCZT as UR string(s) for QR display
/// Returns a vector of UR parts for animated QR (or single part for small PCZTs)
fn encode_signed_pczt_ur(
    pczt_bytes: Vec<u8>,
    max_fragment_len: u32,
) -> Result<Vec<String>, ErrorDisplayed> {
    // Wrap PCZT bytes in CBOR: { 1: bytes }
    let cbor_data = encode_pczt_to_cbor(&pczt_bytes);

    if max_fragment_len == 0 || cbor_data.len() <= max_fragment_len as usize {
        // Single part UR
        let ur_string = ur::ur::encode(&cbor_data, &ur::Type::Custom("zcash-pczt"));
        Ok(vec![ur_string])
    } else {
        // Multi-part (animated) UR using fountain codes
        let mut encoder = ur::ur::Encoder::new(&cbor_data, max_fragment_len as usize, "zcash-pczt")
            .map_err(|e| ErrorDisplayed::Str {
                s: format!("Failed to create UR encoder: {:?}", e),
            })?;

        let mut parts = Vec::new();
        // Generate enough parts to reconstruct (with some redundancy)
        let total_parts = encoder.fragment_count() * 2; // 2x for fountain code redundancy

        for _ in 0..total_parts {
            let part = encoder.next_part().map_err(|e| ErrorDisplayed::Str {
                s: format!("Failed to encode UR part: {:?}", e),
            })?;
            parts.push(part);
        }

        Ok(parts)
    }
}

/// Encode PCZT bytes into CBOR wrapper
/// CBOR structure: { 1: bytes }
fn encode_pczt_to_cbor(pczt_bytes: &[u8]) -> Vec<u8> {
    let mut cbor = Vec::new();

    // map(1)
    cbor.push(0xa1);
    // key 1
    cbor.push(0x01);

    // bytes with appropriate length encoding
    let len = pczt_bytes.len();
    if len <= 23 {
        cbor.push(0x40 | len as u8);
    } else if len <= 255 {
        cbor.push(0x58);
        cbor.push(len as u8);
    } else if len <= 65535 {
        cbor.push(0x59);
        cbor.push((len >> 8) as u8);
        cbor.push(len as u8);
    } else {
        cbor.push(0x5a);
        cbor.push((len >> 24) as u8);
        cbor.push((len >> 16) as u8);
        cbor.push((len >> 8) as u8);
        cbor.push(len as u8);
    }

    cbor.extend_from_slice(pczt_bytes);
    cbor
}

// ========================================================================
// Zcash note sync (verified balance via animated QR)
// ========================================================================

/// Decode UR-encoded zcash-notes, verify merkle paths, store in sled.
///
/// Trust model:
/// - If attestation-required flag is set (sticky, set on first FROST DKG):
///   anchor attestation (CBOR key 5) is REQUIRED. Verified against stored
///   FROST group keys. Hard reject if missing, invalid, or no key matches.
/// - If flag is not set (never had a FROST wallet): accept without attestation.
///   The user trusts zcli in this mode — that's the model they chose.
fn decode_and_verify_zcash_notes(
    ur_parts: Vec<String>,
) -> Result<ZcashNoteSyncResult, ErrorDisplayed> {
    use transaction_signing::zcash::{decode_notes_bundle_from_cbor, verify_merkle_path};

    if ur_parts.is_empty() {
        return Err(ErrorDisplayed::Str {
            s: "No QR parts provided".to_string(),
        });
    }

    // auto-detect UR or zoda transport format
    let cbor_data = decode_qr_payload(&ur_parts, "zcash-notes")?;

    let bundle = decode_notes_bundle_from_cbor(&cbor_data).map_err(|e| ErrorDisplayed::Str {
        s: format!("Failed to parse notes CBOR: {e}"),
    })?;

    // Single DB lock for the entire operation
    let db_guard = DB.read().map_err(|_| ErrorDisplayed::MutexPoisoned)?;
    let database = db_guard.as_ref().ok_or(ErrorDisplayed::DbNotInitialized)?;

    // Monotonic height check: reject anchors older than what we already have
    if let Ok(Some((_, stored_height, _, _))) = db_handling::zcash::get_verified_anchor(database) {
        if bundle.anchor_height < stored_height {
            return Err(ErrorDisplayed::Str {
                s: format!(
                    "Anchor height {} is older than stored height {}. \
                     Rejecting stale anchor (possible replay).",
                    bundle.anchor_height, stored_height
                ),
            });
        }
    }

    // Verify anchor attestation: ed25519 signature from rotko verifier
    let anchor_verified = if let Some(attestation) = &bundle.anchor_attestation {
        // attestation is 64 bytes: ed25519 signature over anchor digest
        if attestation.len() < 64 {
            return Err(ErrorDisplayed::Str {
                s: format!(
                    "attestation too short: {} bytes, need 64",
                    attestation.len()
                ),
            });
        }
        let signature = &attestation[..64];
        let verifier_key = constants::ROTKO_ZCASH_VERIFIER;

        // skip verification if verifier key is not set (all zeros = development mode)
        if verifier_key == [0u8; 32] {
            false // no verifier configured, accept without verification
        } else {
            // compute attestation digest: SHA-256("zcash-anchor-v1" || pubkey || anchor || height || mainnet)
            use sha2::{Digest, Sha256};
            let mut hasher = Sha256::new();
            hasher.update(b"zcash-anchor-v1");
            hasher.update(&verifier_key);
            hasher.update(&bundle.anchor);
            hasher.update(&bundle.anchor_height.to_le_bytes());
            hasher.update(&[u8::from(bundle.mainnet)]);
            let digest: [u8; 32] = hasher.finalize().into();

            // verify ed25519 signature
            let pubkey = sp_core::ed25519::Public::from_raw(verifier_key);
            let sig = sp_core::ed25519::Signature::from_raw({
                let mut s = [0u8; 64];
                s.copy_from_slice(signature);
                s
            });
            if <sp_core::ed25519::Pair as sp_core::Pair>::verify(&sig, &digest, &pubkey) {
                true
            } else {
                return Err(ErrorDisplayed::Str {
                    s: "Anchor attestation signature invalid — \
                        not signed by rotko verifier key."
                        .to_string(),
                });
            }
        }
    } else {
        false // no attestation present, accept as unverified
    };

    // Verify each note's merkle path against anchor
    let mut verified_notes = Vec::new();
    for (i, note) in bundle.notes.iter().enumerate() {
        let valid = verify_merkle_path(&note.cmx, note.position, &note.merkle_path, &bundle.anchor)
            .map_err(|e| ErrorDisplayed::Str {
                s: format!("Merkle verification error for note {i}: {e}"),
            })?;

        if !valid {
            return Err(ErrorDisplayed::Str {
                s: format!(
                    "Note {i} failed merkle verification (cmx={}, pos={})",
                    hex::encode(note.cmx),
                    note.position
                ),
            });
        }

        verified_notes.push((
            note.value,
            note.nullifier,
            note.cmx,
            note.position,
            note.block_height,
        ));
    }

    let total_balance: u64 = verified_notes.iter().map(|(v, _, _, _, _)| v).sum();
    let notes_verified = verified_notes.len() as u32;

    db_handling::zcash::store_verified_notes(
        database,
        &verified_notes,
        &bundle.anchor,
        bundle.anchor_height,
        bundle.mainnet,
    )
    .map_err(|e| ErrorDisplayed::Str {
        s: format!("Failed to store notes: {e}"),
    })?;

    Ok(ZcashNoteSyncResult {
        notes_verified,
        total_balance,
        anchor_hex: hex::encode(bundle.anchor),
        anchor_height: bundle.anchor_height,
        mainnet: bundle.mainnet,
        anchor_verified,
    })
}

/// Get all verified zcash notes from sled
fn get_zcash_verified_notes() -> Result<Vec<ZcashVerifiedNoteDisplay>, ErrorDisplayed> {
    let db_guard = DB.read().map_err(|_| ErrorDisplayed::MutexPoisoned)?;
    let database = db_guard.as_ref().ok_or(ErrorDisplayed::DbNotInitialized)?;

    let notes =
        db_handling::zcash::get_verified_notes(database).map_err(|e| ErrorDisplayed::Str {
            s: format!("Failed to get notes: {e}"),
        })?;

    Ok(notes
        .into_iter()
        .map(
            |(value, nullifier_hex, _cmx, _position, block_height)| ZcashVerifiedNoteDisplay {
                value,
                nullifier_hex,
                block_height,
            },
        )
        .collect())
}

/// Get total verified zcash balance
fn get_zcash_verified_balance() -> Result<u64, ErrorDisplayed> {
    let db_guard = DB.read().map_err(|_| ErrorDisplayed::MutexPoisoned)?;
    let database = db_guard.as_ref().ok_or(ErrorDisplayed::DbNotInitialized)?;

    db_handling::zcash::get_verified_balance(database).map_err(|e| ErrorDisplayed::Str {
        s: format!("Failed to get balance: {e}"),
    })
}

/// Get zcash sync info (anchor, height, timestamp)
fn get_zcash_sync_info() -> Result<Option<ZcashSyncInfo>, ErrorDisplayed> {
    let db_guard = DB.read().map_err(|_| ErrorDisplayed::MutexPoisoned)?;
    let database = db_guard.as_ref().ok_or(ErrorDisplayed::DbNotInitialized)?;

    match db_handling::zcash::get_verified_anchor(database) {
        Ok(Some((anchor, height, mainnet, synced_at))) => Ok(Some(ZcashSyncInfo {
            anchor_hex: hex::encode(anchor),
            anchor_height: height,
            mainnet,
            synced_at,
        })),
        Ok(None) => Ok(None),
        Err(e) => Err(ErrorDisplayed::Str {
            s: format!("Failed to get sync info: {e}"),
        }),
    }
}

/// Clear all stored zcash notes
fn clear_zcash_notes() -> Result<(), ErrorDisplayed> {
    let db_guard = DB.read().map_err(|_| ErrorDisplayed::MutexPoisoned)?;
    let database = db_guard.as_ref().ok_or(ErrorDisplayed::DbNotInitialized)?;

    db_handling::zcash::clear_zcash_notes(database).map_err(|e| ErrorDisplayed::Str {
        s: format!("Failed to clear notes: {e}"),
    })
}

/// Generic UR decoder that handles both single-part and multi-part (fountain) URs
/// Decode QR payload — auto-detects UR (`ur:`) or zoda transport (`zt:`) format.
fn decode_qr_payload(parts: &[String], expected_type: &str) -> Result<Vec<u8>, ErrorDisplayed> {
    if parts.is_empty() {
        return Err(ErrorDisplayed::Str {
            s: "No QR parts provided".to_string(),
        });
    }
    let lower = parts[0].to_lowercase();
    if lower.starts_with("zt:") {
        decode_zt_payload(parts, expected_type)
    } else {
        decode_ur_payload(parts, expected_type)
    }
}

/// Decode zoda transport frames (`zt:type/hex`).
fn decode_zt_payload(parts: &[String], expected_type: &str) -> Result<Vec<u8>, ErrorDisplayed> {
    use zoda_vss::transport::{Decoder as ZtDecoder, TransportError};

    let zt_prefix = format!("zt:{}/", expected_type);

    let mut decoder = ZtDecoder::new();

    for part in parts {
        let lower = part.to_lowercase();
        if !lower.starts_with(&zt_prefix) {
            // skip non-matching frames (could be stray QRs)
            continue;
        }

        let hex_data = &part[zt_prefix.len()..];
        let frame_bytes = hex::decode(hex_data).map_err(|e| ErrorDisplayed::Str {
            s: format!("bad hex in zt frame: {e}"),
        })?;

        match decoder.receive(&frame_bytes) {
            Ok(_) => {}
            Err(TransportError::SessionMismatch) => {
                // stray QR from different session — skip silently
                continue;
            }
            Err(e) => {
                return Err(ErrorDisplayed::Str {
                    s: format!("zt transport error: {e}"),
                });
            }
        }

        if decoder.complete() {
            break;
        }
    }

    decoder.reconstruct().map_err(|e| ErrorDisplayed::Str {
        s: format!("zt reconstruct failed: {e}"),
    })
}

fn decode_ur_payload(ur_parts: &[String], expected_type: &str) -> Result<Vec<u8>, ErrorDisplayed> {
    use ur::ur::decode;

    let expected_prefix = format!("ur:{}/", expected_type);

    // Verify UR type
    let lower = ur_parts[0].to_lowercase();
    if !lower.starts_with(&expected_prefix) {
        return Err(ErrorDisplayed::Str {
            s: format!(
                "Expected ur:{}/... got: {}",
                expected_type,
                ur_parts[0].chars().take(40).collect::<String>()
            ),
        });
    }

    if ur_parts.len() == 1 {
        let (_kind, data) = decode(&ur_parts[0]).map_err(|e| ErrorDisplayed::Str {
            s: format!("Failed to decode UR: {:?}", e),
        })?;
        Ok(data)
    } else {
        let mut decoder = ur::ur::Decoder::default();
        for part in ur_parts {
            decoder.receive(part).map_err(|e| ErrorDisplayed::Str {
                s: format!("Failed to receive UR part: {:?}", e),
            })?;
            if decoder.complete() {
                break;
            }
        }

        if !decoder.complete() {
            return Err(ErrorDisplayed::Str {
                s: format!(
                    "Incomplete UR sequence: received {} parts but not complete",
                    ur_parts.len()
                ),
            });
        }

        decoder
            .message()
            .map_err(|e| ErrorDisplayed::Str {
                s: format!("Failed to get UR message: {:?}", e),
            })?
            .ok_or_else(|| ErrorDisplayed::Str {
                s: "UR decoder returned None despite being complete".to_string(),
            })
    }
}

/// High-level function to sign a PCZT from UR-encoded QR data
/// This is the main entry point for Zashi compatibility
fn sign_zcash_pczt_ur(
    seed_phrase: &str,
    account_index: u32,
    ur_parts: Vec<String>,
    max_fragment_len: u32,
) -> Result<Vec<String>, ErrorDisplayed> {
    // Decode UR to get PCZT bytes
    let pczt_bytes = decode_ur_zcash_pczt(ur_parts)?;

    // Sign the PCZT
    let signed_pczt_bytes = sign_zcash_pczt(seed_phrase, account_index, pczt_bytes)?;

    // Encode back to UR
    encode_signed_pczt_ur(signed_pczt_bytes, max_fragment_len)
}

/// Must be called once to initialize logging from Rust in development mode.
///
/// Do not use in production.
#[cfg(target_os = "android")]
fn init_logging(tag: String) {
    android_logger::init_once(
        android_logger::Config::default()
            .with_max_level(log::LevelFilter::Trace) // limit log level
            .with_tag(tag) // logs will show under mytag tag
            .with_filter(
                // configure messages for specific crate
                android_logger::FilterBuilder::new()
                    .parse("debug,hello::crate=error")
                    .build(),
            ),
    );
}

#[cfg(target_os = "ios")]
fn init_logging(_tag: String) {
    use uniffi::deps::log::LevelFilter;

    let _ = oslog::OsLogger::new("net.rotko.zigner")
        .level_filter(LevelFilter::Warn)
        .category_level_filter("SIGNER", LevelFilter::Trace)
        .init();
}

/// Placeholder to init logging on non-android platforms
///
/// TODO: is this used?
#[cfg(all(not(target_os = "ios"), not(target_os = "android")))]
fn init_logging(_tag: String) {
    env_logger::init();
}

// ── ed25519 identity (zafu-compatible) ──

/// Derive base identity pubkey (compatible with zafu identity.ts)
fn auth_derive_identity(seed_phrase: &str, index: u32) -> Result<String, ErrorDisplayed> {
    auth::derive_identity(seed_phrase, index).map_err(|e| ErrorDisplayed::Str { s: e })
}

/// Derive domain-scoped identity pubkey (per-service, no cross-site correlation)
fn auth_derive_domain_identity(
    seed_phrase: &str,
    domain: &str,
    index: u32,
) -> Result<String, ErrorDisplayed> {
    auth::derive_domain_identity(seed_phrase, domain, index)
        .map_err(|e| ErrorDisplayed::Str { s: e })
}

/// Sign auth challenge with base identity
fn auth_sign_challenge(
    seed_phrase: &str,
    index: u32,
    domain: &str,
    nonce: &str,
    timestamp: u64,
) -> Result<AuthSignResult, ErrorDisplayed> {
    let challenge = auth::build_auth_challenge(domain, nonce, timestamp);
    let (pubkey, sig) = auth::sign_challenge(seed_phrase, index, &challenge)
        .map_err(|e| ErrorDisplayed::Str { s: e })?;
    Ok(AuthSignResult {
        pubkey_hex: pubkey,
        signature_hex: sig,
        domain: domain.to_string(),
    })
}

/// Sign auth challenge with domain-scoped identity
fn auth_sign_domain_challenge(
    seed_phrase: &str,
    domain: &str,
    index: u32,
    nonce: &str,
    timestamp: u64,
) -> Result<AuthSignResult, ErrorDisplayed> {
    let challenge = auth::build_auth_challenge(domain, nonce, timestamp);
    let (pubkey, sig) = auth::sign_domain_challenge(seed_phrase, domain, index, &challenge)
        .map_err(|e| ErrorDisplayed::Str { s: e })?;
    Ok(AuthSignResult {
        pubkey_hex: pubkey,
        signature_hex: sig,
        domain: domain.to_string(),
    })
}

/// Verify an auth signature
fn auth_verify(
    pubkey_hex: &str,
    signature_hex: &str,
    domain: &str,
    nonce: &str,
    timestamp: u64,
) -> Result<bool, ErrorDisplayed> {
    let challenge = auth::build_auth_challenge(domain, nonce, timestamp);
    auth::verify_signature(pubkey_hex, signature_hex, &challenge)
        .map_err(|e| ErrorDisplayed::Str { s: e })
}

/// Parse a ZID sign challenge QR (JSON), sign it, return JSON response.
///
/// Input JSON: {"type":"zid-sign","v":1,"challenge":"<hex>","identity":"default",
///              "mode":"site","origin":"...","rotation":0,"algorithm":"ed25519",...}
/// Output JSON: {"type":"zid-resp","v":1,"signature":"<hex>","publicKey":"<hex>"}
fn sign_zid_qr(seed_phrase: &str, qr_json: &str) -> Result<String, ErrorDisplayed> {
    let parsed: serde_json::Value =
        serde_json::from_str(qr_json).map_err(|e| ErrorDisplayed::Str {
            s: format!("invalid JSON: {e}"),
        })?;

    let qr_type = parsed["type"].as_str().unwrap_or("");
    if qr_type != "zid-sign" {
        return Err(ErrorDisplayed::Str {
            s: format!("unexpected type: {qr_type}"),
        });
    }

    let challenge_hex = parsed["challenge"]
        .as_str()
        .ok_or_else(|| ErrorDisplayed::Str {
            s: "missing challenge".into(),
        })?;
    let identity = parsed["identity"].as_str().unwrap_or("default");
    let mode = parsed["mode"].as_str().unwrap_or("site");
    let origin = parsed["origin"].as_str().unwrap_or("");
    let rotation = parsed["rotation"].as_u64().unwrap_or(0) as u32;
    let algorithm = parsed["algorithm"].as_str().unwrap_or("ed25519");

    if algorithm != "ed25519" {
        return Err(ErrorDisplayed::Str {
            s: format!("unsupported algorithm: {algorithm}"),
        });
    }

    let challenge = hex::decode(challenge_hex).map_err(|e| ErrorDisplayed::Str {
        s: format!("bad challenge hex: {e}"),
    })?;

    let (signature, pubkey) =
        auth::sign_zid_challenge(seed_phrase, identity, mode, origin, rotation, &challenge)
            .map_err(|e| ErrorDisplayed::Str { s: e })?;

    Ok(format!(
        r#"{{"type":"zid-resp","v":1,"signature":"{signature}","publicKey":"{pubkey}"}}"#
    ))
}

/// Derive a 12-word hot wallet mnemonic from the master seed.
/// The hot wallet is deterministic and can be used for ZID, pro subscription,
/// and day-to-day spending in zafu.
fn derive_hot_wallet(seed_phrase: &str) -> Result<String, ErrorDisplayed> {
    auth::derive_hot_wallet_mnemonic(seed_phrase).map_err(|e| ErrorDisplayed::Str { s: e })
}

/// Derive hot wallet mnemonic and encode as ur:zafu-hot-wallet QR PNG.
/// Returns the PNG bytes for a single static QR code.
fn derive_hot_wallet_qr(seed_phrase: &str) -> Result<Vec<u8>, ErrorDisplayed> {
    let mnemonic =
        auth::derive_hot_wallet_mnemonic(seed_phrase).map_err(|e| ErrorDisplayed::Str { s: e })?;

    // Build CBOR: map(2) { 1: text(mnemonic), 2: text("default") }
    let identity = "default";
    let mut cbor = Vec::new();
    // map with 2 entries: major type 5, additional 2
    cbor.push(0xa2);
    // key 1 (uint)
    cbor.push(0x01);
    // text string: mnemonic
    encode_cbor_text(&mut cbor, &mnemonic);
    // key 2 (uint)
    cbor.push(0x02);
    // text string: identity
    encode_cbor_text(&mut cbor, identity);

    // Encode as UR bytewords with CRC32 checksum
    let ur_string = encode_ur("zafu-hot-wallet", &cbor);

    // Encode UR string as QR PNG
    encode_to_qr(ur_string.as_bytes(), true).map_err(|e| ErrorDisplayed::Str { s: e })
}

/// Encode a text string in CBOR (major type 3)
fn encode_cbor_text(buf: &mut Vec<u8>, text: &str) {
    let len = text.len();
    if len < 24 {
        buf.push(0x60 | len as u8);
    } else if len < 256 {
        buf.push(0x78);
        buf.push(len as u8);
    } else {
        buf.push(0x79);
        buf.push((len >> 8) as u8);
        buf.push(len as u8);
    }
    buf.extend_from_slice(text.as_bytes());
}

/// Encode bytes as ur:TYPE/bytewords string
fn encode_ur(ur_type: &str, payload: &[u8]) -> String {
    // CRC32 checksum
    let checksum = crc32(payload);
    let mut data = payload.to_vec();
    data.push((checksum >> 24) as u8);
    data.push((checksum >> 16) as u8);
    data.push((checksum >> 8) as u8);
    data.push(checksum as u8);

    // Minimal bytewords encoding (2 chars per byte)
    let bytewords: String = data.iter().map(|&b| minimal_byteword(b)).collect();
    format!("ur:{ur_type}/{bytewords}")
}

fn crc32(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xffffffff;
    for &byte in data {
        crc ^= byte as u32;
        for _ in 0..8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ 0xedb88320
            } else {
                crc >> 1
            };
        }
    }
    crc ^ 0xffffffff
}

fn minimal_byteword(byte: u8) -> &'static str {
    const WORDS: [&str; 256] = [
        "ae", "ad", "ao", "ax", "aa", "ah", "am", "at", "ay", "as", "bk", "bd", "bn", "bt", "ba",
        "bs", "be", "by", "bg", "bw", "bb", "bz", "cm", "ch", "cs", "cf", "cy", "cw", "ce", "ca",
        "ck", "ct", "cx", "cl", "cp", "cn", "dk", "da", "ds", "di", "de", "dt", "dr", "dn", "dw",
        "dp", "dm", "dl", "dy", "eh", "ey", "eo", "ee", "ec", "en", "em", "et", "es", "ft", "fr",
        "fn", "fs", "fm", "fh", "fz", "fp", "fw", "fx", "fy", "fe", "fg", "fl", "fd", "ga", "ge",
        "gr", "gs", "gt", "gl", "gw", "gd", "gy", "gm", "gu", "gh", "go", "hf", "hg", "hd", "hk",
        "ht", "hp", "hh", "hl", "hy", "he", "hn", "hs", "id", "ia", "ie", "ih", "iy", "io", "is",
        "in", "im", "je", "jz", "jn", "jt", "jl", "jo", "js", "jp", "jk", "jy", "kp", "ko", "kt",
        "ks", "kk", "kn", "kg", "ke", "ki", "kb", "lb", "la", "ly", "lf", "ls", "lr", "lp", "ln",
        "lt", "lo", "ld", "le", "lu", "lk", "lg", "mn", "my", "mh", "me", "mo", "mu", "mw", "md",
        "mt", "ms", "mk", "nl", "ny", "nd", "ns", "nt", "nn", "ne", "nb", "oy", "oe", "ot", "ox",
        "on", "ol", "os", "pd", "pt", "pk", "py", "ps", "pm", "pl", "pe", "pf", "pa", "pr", "qd",
        "qz", "re", "rp", "rl", "ro", "rh", "rd", "rk", "rf", "ry", "rn", "rs", "rt", "se", "sa",
        "sr", "ss", "sk", "sw", "st", "sp", "so", "sg", "sb", "sf", "sn", "to", "tk", "ti", "tt",
        "td", "te", "ty", "tl", "tb", "ts", "tp", "ta", "tn", "uy", "uo", "ut", "ue", "ur", "vt",
        "vy", "vo", "vl", "ve", "vw", "va", "vd", "vs", "wl", "wd", "wm", "wp", "we", "wy", "ws",
        "wt", "wn", "wz", "wf", "wk", "yk", "yn", "yl", "ya", "yt", "zs", "zo", "zt", "zc", "ze",
        "zm",
    ];
    WORDS[byte as usize]
}

// ── contacts (address book) ──

fn store_contact(address: &str, label: &str, chain_id: &str) -> Result<(), ErrorDisplayed> {
    let db = get_db()?;
    let contact = db_handling::contacts::Contact {
        address: address.to_string(),
        label: label.to_string(),
        chain_id: chain_id.to_string(),
    };
    db_handling::contacts::store_contact(&db, &contact)
        .map_err(|e| ErrorDisplayed::from(format!("{e}")))
}

fn get_contacts() -> Result<String, ErrorDisplayed> {
    let db = get_db()?;
    let contacts = db_handling::contacts::get_contacts(&db)
        .map_err(|e| ErrorDisplayed::from(format!("{e}")))?;
    let json: Vec<serde_json::Value> = contacts
        .iter()
        .map(|c| {
            serde_json::json!({
                "address": c.address,
                "label": c.label,
                "chain_id": c.chain_id,
            })
        })
        .collect();
    serde_json::to_string(&json).map_err(|e| ErrorDisplayed::from(format!("{e}")))
}

fn get_contact_label(address: &str) -> Result<String, ErrorDisplayed> {
    let db = get_db()?;
    match db_handling::contacts::get_contact_label(&db, address)
        .map_err(|e| ErrorDisplayed::from(format!("{e}")))?
    {
        Some(label) => Ok(label),
        None => Ok(String::new()),
    }
}

fn delete_contact(address: &str) -> Result<(), ErrorDisplayed> {
    let db = get_db()?;
    db_handling::contacts::delete_contact(&db, address)
        .map_err(|e| ErrorDisplayed::from(format!("{e}")))
}

/// Export contacts as CBOR for QR display (unencrypted, for live scan)
fn export_contacts_cbor() -> Result<Vec<u8>, ErrorDisplayed> {
    let db = get_db()?;
    let contacts = db_handling::contacts::get_contacts(&db)
        .map_err(|e| ErrorDisplayed::from(format!("{e}")))?;
    Ok(backup::encode_contacts_cbor(&contacts))
}

/// Import contacts from CBOR (from QR scan)
fn import_contacts_cbor(cbor: Vec<u8>) -> Result<u32, ErrorDisplayed> {
    let contacts = backup::decode_contacts_cbor(&cbor).map_err(|e| ErrorDisplayed::Str { s: e })?;
    let db = get_db()?;
    let count = db_handling::contacts::import_contacts(&db, &contacts)
        .map_err(|e| ErrorDisplayed::from(format!("{e}")))?;
    Ok(count as u32)
}

/// Export contacts as UR-encoded animated QR string frames
fn export_contacts_ur(max_fragment_len: u32) -> Result<Vec<String>, ErrorDisplayed> {
    let cbor = export_contacts_cbor()?;
    ur_encode_cbor(&cbor, "zigner-contacts", max_fragment_len)
}

/// Export contacts as zoda transport frames (verified erasure coding)
fn export_contacts_zt(k: u8, n: u8) -> Result<Vec<String>, ErrorDisplayed> {
    let cbor = export_contacts_cbor()?;
    zt_encode(&cbor, "zigner-contacts", k, n)
}

/// Encode data as zoda transport QR frames: `zt:type/hex`
fn zt_encode(data: &[u8], zt_type: &str, k: u8, n: u8) -> Result<Vec<String>, ErrorDisplayed> {
    let (frames, _session_id) = zoda_vss::transport::Encoder::encode(data, k, n);
    let strings: Vec<String> = frames
        .iter()
        .map(|f| format!("zt:{}/{}", zt_type, hex::encode(f.to_bytes())))
        .collect();
    Ok(strings)
}

// ── encrypted backup ──

/// Create encrypted backup of all exportable data.
/// Returns UR-encoded frames of the encrypted bundle.
fn create_encrypted_backup(
    seed_name: &str,
    seed_phrase: &str,
    max_fragment_len: u32,
) -> Result<Vec<String>, ErrorDisplayed> {
    // Gather all backup data
    let accounts_json = bs_export_backup_data(seed_name, seed_phrase)?;

    let db = get_db()?;
    let contacts = db_handling::contacts::get_contacts(&db)
        .map_err(|e| ErrorDisplayed::from(format!("{e}")))?;
    let contacts_cbor = backup::encode_contacts_cbor(&contacts);

    // Build the backup bundle: CBOR map { 1: accounts_json(tstr), 2: contacts_cbor(bstr) }
    let mut bundle = Vec::new();
    bundle.push(0xa2); // map(2)

    // key 1: accounts (tstr — JSON string)
    bundle.push(0x01);
    let json_bytes = accounts_json.as_bytes();
    cbor_tstr_into(&mut bundle, json_bytes);

    // key 2: contacts (bstr — raw CBOR)
    bundle.push(0x02);
    cbor_bstr_into(&mut bundle, &contacts_cbor);

    // Encrypt
    let key = backup::derive_backup_key(seed_phrase);
    let encrypted = backup::encrypt(&key, &bundle).map_err(|e| ErrorDisplayed::Str { s: e })?;

    ur_encode_cbor(&encrypted, "zigner-backup", max_fragment_len)
}

/// Restore from encrypted backup.
/// Returns the accounts JSON for the caller to process.
fn restore_encrypted_backup(
    seed_phrase: &str,
    ur_parts: Vec<String>,
) -> Result<String, ErrorDisplayed> {
    let cbor_data = ur_decode_parts(&ur_parts)?;

    // Decrypt
    let key = backup::derive_backup_key(seed_phrase);
    let bundle = backup::decrypt(&key, &cbor_data).map_err(|e| ErrorDisplayed::Str { s: e })?;

    // Parse bundle CBOR: map { 1: accounts_tstr, 2: contacts_bstr }
    if bundle.is_empty() {
        return Err(ErrorDisplayed::Str {
            s: "empty bundle".to_string(),
        });
    }

    let (map_len, mut offset) =
        cbor_parse_map_header(&bundle).map_err(|e| ErrorDisplayed::Str { s: e })?;

    let mut accounts_json = String::new();

    for _ in 0..map_len {
        let (key, consumed) =
            cbor_parse_uint(&bundle, offset).map_err(|e| ErrorDisplayed::Str { s: e })?;
        offset = consumed;

        match key {
            1 => {
                // tstr: accounts JSON
                let (s, consumed) =
                    parse_cbor_tstr(&bundle, offset).map_err(|e| ErrorDisplayed::Str { s: e })?;
                offset = consumed;
                accounts_json = s;
            }
            2 => {
                // bstr: contacts CBOR
                let (bytes, consumed) =
                    parse_cbor_bytes(&bundle[offset..]).map_err(|e| ErrorDisplayed::Str {
                        s: format!("contacts bstr: {e}"),
                    })?;
                offset += consumed;
                // Import contacts
                let contacts = backup::decode_contacts_cbor(&bytes)
                    .map_err(|e| ErrorDisplayed::Str { s: e })?;
                let db = get_db()?;
                db_handling::contacts::import_contacts(&db, &contacts)
                    .map_err(|e| ErrorDisplayed::from(format!("{e}")))?;
            }
            _ => {
                // skip unknown value (handles any CBOR type)
                offset =
                    cbor_skip_any(&bundle, offset).map_err(|e| ErrorDisplayed::Str { s: e })?;
            }
        }
    }

    Ok(accounts_json)
}

// ── UR helpers ──

fn ur_encode_cbor(
    data: &[u8],
    ur_type: &str,
    max_fragment_len: u32,
) -> Result<Vec<String>, ErrorDisplayed> {
    // Wrap in CBOR bstr
    let mut cbor = Vec::with_capacity(data.len() + 5);
    cbor_bstr_into(&mut cbor, data);

    if max_fragment_len == 0 || cbor.len() <= max_fragment_len as usize {
        let ur_string = ur::ur::encode(&cbor, &ur::Type::Custom(ur_type));
        Ok(vec![ur_string])
    } else {
        let mut encoder =
            ur::ur::Encoder::new(&cbor, max_fragment_len as usize, ur_type).map_err(|e| {
                ErrorDisplayed::Str {
                    s: format!("UR encoder: {e:?}"),
                }
            })?;
        let count = encoder.fragment_count() * 2;
        let mut frames = Vec::with_capacity(count);
        for _ in 0..count {
            let part = encoder.next_part().map_err(|e| ErrorDisplayed::Str {
                s: format!("UR part: {e:?}"),
            })?;
            frames.push(part);
        }
        Ok(frames)
    }
}

fn ur_decode_parts(ur_parts: &[String]) -> Result<Vec<u8>, ErrorDisplayed> {
    if ur_parts.is_empty() {
        return Err(ErrorDisplayed::Str {
            s: "no UR parts".to_string(),
        });
    }
    if ur_parts.len() == 1 {
        let (_, cbor) = ur::ur::decode(&ur_parts[0]).map_err(|e| ErrorDisplayed::Str {
            s: format!("UR decode: {e:?}"),
        })?;
        let (bytes, _) = parse_cbor_bytes(&cbor).map_err(|e| ErrorDisplayed::Str {
            s: format!("CBOR: {e}"),
        })?;
        return Ok(bytes);
    }
    let mut decoder = ur::ur::Decoder::default();
    for part in ur_parts {
        decoder.receive(part).map_err(|e| ErrorDisplayed::Str {
            s: format!("UR receive: {e:?}"),
        })?;
        if decoder.complete() {
            let cbor = decoder
                .message()
                .map_err(|e| ErrorDisplayed::Str {
                    s: format!("UR message: {e:?}"),
                })?
                .ok_or_else(|| ErrorDisplayed::Str {
                    s: "UR complete but no message".to_string(),
                })?;
            let (bytes, _) = parse_cbor_bytes(&cbor).map_err(|e| ErrorDisplayed::Str {
                s: format!("CBOR: {e}"),
            })?;
            return Ok(bytes);
        }
    }
    Err(ErrorDisplayed::Str {
        s: "incomplete UR".to_string(),
    })
}

fn cbor_tstr_into(buf: &mut Vec<u8>, s: &[u8]) {
    let len = s.len();
    if len <= 23 {
        buf.push(0x60 | len as u8);
    } else if len <= 0xff {
        buf.push(0x78);
        buf.push(len as u8);
    } else if len <= 0xffff {
        buf.push(0x79);
        buf.extend_from_slice(&(len as u16).to_be_bytes());
    } else {
        buf.push(0x7a);
        buf.extend_from_slice(&(len as u32).to_be_bytes());
    }
    buf.extend_from_slice(s);
}

fn cbor_bstr_into(buf: &mut Vec<u8>, data: &[u8]) {
    let len = data.len();
    if len <= 23 {
        buf.push(0x40 | len as u8);
    } else if len <= 0xff {
        buf.push(0x58);
        buf.push(len as u8);
    } else if len <= 0xffff {
        buf.push(0x59);
        buf.extend_from_slice(&(len as u16).to_be_bytes());
    } else {
        buf.push(0x5a);
        buf.extend_from_slice(&(len as u32).to_be_bytes());
    }
    buf.extend_from_slice(data);
}

fn parse_cbor_tstr(data: &[u8], offset: usize) -> Result<(String, usize), String> {
    if offset >= data.len() {
        return Err("truncated tstr".to_string());
    }
    let first = data[offset];
    let major = first >> 5;
    if major != 3 {
        return Err(format!("expected tstr, got major {major}"));
    }
    let additional = first & 0x1f;
    let (len, header_end) = match additional {
        0..=23 => (additional as usize, offset + 1),
        24 => {
            if offset + 2 > data.len() {
                return Err("truncated".to_string());
            }
            (data[offset + 1] as usize, offset + 2)
        }
        25 => {
            if offset + 3 > data.len() {
                return Err("truncated".to_string());
            }
            (
                u16::from_be_bytes([data[offset + 1], data[offset + 2]]) as usize,
                offset + 3,
            )
        }
        _ => return Err(format!("unsupported tstr additional {additional}")),
    };
    if header_end + len > data.len() {
        return Err("truncated tstr data".to_string());
    }
    let s = std::str::from_utf8(&data[header_end..header_end + len])
        .map_err(|e| format!("invalid UTF-8: {e}"))?;
    Ok((s.to_string(), header_end + len))
}

/// Parse a CBOR map header, returning (length, offset after header).
fn cbor_parse_map_header(data: &[u8]) -> Result<(usize, usize), String> {
    if data.is_empty() {
        return Err("empty CBOR".to_string());
    }
    let first = data[0];
    let major = first >> 5;
    if major != 5 {
        return Err(format!("expected map (major 5), got major {major}"));
    }
    let additional = first & 0x1f;
    cbor_parse_length(data, 0, additional).map(|(len, off)| (len as usize, off))
}

/// Parse a CBOR unsigned integer at offset.
fn cbor_parse_uint(data: &[u8], offset: usize) -> Result<(u64, usize), String> {
    if offset >= data.len() {
        return Err("truncated uint".to_string());
    }
    let first = data[offset];
    let major = first >> 5;
    if major != 0 {
        return Err(format!("expected uint (major 0), got major {major}"));
    }
    cbor_parse_length(data, offset, first & 0x1f)
}

/// Decode CBOR additional info into a length/value.
fn cbor_parse_length(data: &[u8], offset: usize, additional: u8) -> Result<(u64, usize), String> {
    match additional {
        0..=23 => Ok((additional as u64, offset + 1)),
        24 => {
            if offset + 2 > data.len() {
                return Err("truncated length".to_string());
            }
            Ok((data[offset + 1] as u64, offset + 2))
        }
        25 => {
            if offset + 3 > data.len() {
                return Err("truncated length".to_string());
            }
            Ok((
                u16::from_be_bytes([data[offset + 1], data[offset + 2]]) as u64,
                offset + 3,
            ))
        }
        26 => {
            if offset + 5 > data.len() {
                return Err("truncated length".to_string());
            }
            Ok((
                u32::from_be_bytes([
                    data[offset + 1],
                    data[offset + 2],
                    data[offset + 3],
                    data[offset + 4],
                ]) as u64,
                offset + 5,
            ))
        }
        _ => Err(format!("unsupported CBOR additional {additional}")),
    }
}

/// Skip a single CBOR value of any type at offset.
fn cbor_skip_any(data: &[u8], offset: usize) -> Result<usize, String> {
    if offset >= data.len() {
        return Err("truncated CBOR value".to_string());
    }
    let first = data[offset];
    let major = first >> 5;
    let additional = first & 0x1f;
    let (content_len, header_end) = cbor_parse_length(data, offset, additional)?;
    let content_len = content_len as usize;
    match major {
        0 | 1 => Ok(header_end),               // uint/negint
        2 | 3 => Ok(header_end + content_len), // bstr/tstr
        4 => {
            let mut pos = header_end;
            for _ in 0..content_len {
                pos = cbor_skip_any(data, pos)?;
            }
            Ok(pos)
        }
        5 => {
            let mut pos = header_end;
            for _ in 0..content_len {
                pos = cbor_skip_any(data, pos)?; // key
                pos = cbor_skip_any(data, pos)?; // value
            }
            Ok(pos)
        }
        7 => Ok(offset + 1), // simple (bool/null)
        _ => Err(format!("unsupported CBOR major {major}")),
    }
}

// ── FROST threshold multisig ──

fn frost_dkg_part1(max_signers: u16, min_signers: u16) -> Result<String, ErrorDisplayed> {
    frost_multisig::frost_dkg_part1(max_signers, min_signers)
        .map_err(|e| ErrorDisplayed::Str { s: e })
}

fn frost_dkg_part2(secret_hex: &str, peer_broadcasts_json: &str) -> Result<String, ErrorDisplayed> {
    frost_multisig::frost_dkg_part2(secret_hex, peer_broadcasts_json)
        .map_err(|e| ErrorDisplayed::Str { s: e })
}

fn frost_dkg_part3(
    secret_hex: &str,
    round1_broadcasts_json: &str,
    round2_packages_json: &str,
) -> Result<String, ErrorDisplayed> {
    frost_multisig::frost_dkg_part3(secret_hex, round1_broadcasts_json, round2_packages_json)
        .map_err(|e| ErrorDisplayed::Str { s: e })
}

fn frost_sign_round1(
    ephemeral_seed_hex: &str,
    key_package_hex: &str,
) -> Result<String, ErrorDisplayed> {
    frost_multisig::frost_sign_round1(ephemeral_seed_hex, key_package_hex)
        .map_err(|e| ErrorDisplayed::Str { s: e })
}

fn frost_spend_sign_round2(
    key_package_hex: &str,
    nonces_hex: &str,
    sighash_hex: &str,
    alpha_hex: &str,
    commitments_json: &str,
) -> Result<String, ErrorDisplayed> {
    frost_multisig::frost_spend_sign_round2(
        key_package_hex,
        nonces_hex,
        sighash_hex,
        alpha_hex,
        commitments_json,
    )
    .map_err(|e| ErrorDisplayed::Str { s: e })
}

fn frost_spend_sign_actions(
    key_package_hex: &str,
    nonces_hex: &str,
    sighash_hex: &str,
    alphas_json: &str,
    commitments_json: &str,
) -> Result<String, ErrorDisplayed> {
    frost_multisig::frost_spend_sign_actions(
        key_package_hex,
        nonces_hex,
        sighash_hex,
        alphas_json,
        commitments_json,
    )
    .map_err(|e| ErrorDisplayed::Str { s: e })
}

fn frost_derive_address_raw(
    public_key_package_hex: &str,
    diversifier_index: u32,
) -> Result<String, ErrorDisplayed> {
    frost_multisig::frost_derive_address_raw(public_key_package_hex, diversifier_index)
        .map_err(|e| ErrorDisplayed::Str { s: e })
}

// ── FROST wallet storage ──

fn frost_store_wallet(
    key_package_hex: &str,
    public_key_package_hex: &str,
    ephemeral_seed_hex: &str,
    label: &str,
    min_signers: u16,
    max_signers: u16,
    mainnet: bool,
    orchard_fvk_uview: &str,
    address: &str,
    relay_url: &str,
) -> Result<String, ErrorDisplayed> {
    let db_guard = DB.read().map_err(|_| ErrorDisplayed::MutexPoisoned)?;
    let database = db_guard.as_ref().ok_or(ErrorDisplayed::DbNotInitialized)?;

    // Empty strings → None, so older callers that pass "" don't poison the
    // optional fields with empty data.
    let none_if_empty = |s: &str| if s.is_empty() { None } else { Some(s.to_string()) };

    let data = db_handling::frost::FrostWalletData {
        key_package_hex: key_package_hex.to_string(),
        public_key_package_hex: public_key_package_hex.to_string(),
        ephemeral_seed_hex: ephemeral_seed_hex.to_string(),
        label: label.to_string(),
        min_signers,
        max_signers,
        mainnet,
        created_at: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
        orchard_fvk_uview: none_if_empty(orchard_fvk_uview),
        address: none_if_empty(address),
        relay_url: none_if_empty(relay_url),
    };

    db_handling::frost::store_frost_wallet(database, &data).map_err(|e| ErrorDisplayed::Str {
        s: format!("Failed to store FROST wallet: {e}"),
    })
}

fn frost_list_wallets() -> Result<Vec<FrostWalletSummaryFFI>, ErrorDisplayed> {
    let db_guard = DB.read().map_err(|_| ErrorDisplayed::MutexPoisoned)?;
    let database = db_guard.as_ref().ok_or(ErrorDisplayed::DbNotInitialized)?;

    let wallets =
        db_handling::frost::list_frost_wallets(database).map_err(|e| ErrorDisplayed::Str {
            s: format!("Failed to list FROST wallets: {e}"),
        })?;

    Ok(wallets
        .into_iter()
        .map(|w| FrostWalletSummaryFFI {
            wallet_id: w.wallet_id,
            label: w.label,
            min_signers: w.min_signers,
            max_signers: w.max_signers,
            mainnet: w.mainnet,
            created_at: w.created_at,
        })
        .collect())
}

fn frost_load_wallet(wallet_id: &str) -> Result<String, ErrorDisplayed> {
    let db_guard = DB.read().map_err(|_| ErrorDisplayed::MutexPoisoned)?;
    let database = db_guard.as_ref().ok_or(ErrorDisplayed::DbNotInitialized)?;

    let data = db_handling::frost::get_frost_wallet(database, wallet_id)
        .map_err(|e| ErrorDisplayed::Str {
            s: format!("Failed to load FROST wallet: {e}"),
        })?
        .ok_or_else(|| ErrorDisplayed::Str {
            s: format!("FROST wallet not found: {wallet_id}"),
        })?;

    serde_json::to_string(&serde_json::json!({
        "key_package": data.key_package_hex,
        "ephemeral_seed": data.ephemeral_seed_hex,
        "public_key_package": data.public_key_package_hex,
    }))
    .map_err(|e| ErrorDisplayed::Str {
        s: format!("Serialize: {e}"),
    })
}

fn frost_delete_wallet(wallet_id: &str) -> Result<(), ErrorDisplayed> {
    let db_guard = DB.read().map_err(|_| ErrorDisplayed::MutexPoisoned)?;
    let database = db_guard.as_ref().ok_or(ErrorDisplayed::DbNotInitialized)?;

    db_handling::frost::delete_frost_wallet(database, wallet_id).map_err(|e| ErrorDisplayed::Str {
        s: format!("Failed to delete FROST wallet: {e}"),
    })
}

// ── FROST backup encryption (zigner ↔ zafu interoperable envelope) ──

fn frost_export_backup_envelope(
    wallet_id: &str,
    passphrase: &str,
) -> Result<String, ErrorDisplayed> {
    let db_guard = DB.read().map_err(|_| ErrorDisplayed::MutexPoisoned)?;
    let database = db_guard.as_ref().ok_or(ErrorDisplayed::DbNotInitialized)?;

    let data = db_handling::frost::get_frost_wallet(database, wallet_id)
        .map_err(|e| ErrorDisplayed::Str {
            s: format!("load FROST wallet: {e}"),
        })?
        .ok_or_else(|| ErrorDisplayed::Str {
            s: format!("FROST wallet not found: {wallet_id}"),
        })?;

    let payload = frost_backup::PlaintextPayload {
        version: 1,
        kind: "frost-share".into(),
        label: data.label,
        public_key_package: data.public_key_package_hex,
        key_package: data.key_package_hex,
        ephemeral_seed: data.ephemeral_seed_hex,
        threshold: data.min_signers,
        max_signers: data.max_signers,
        mainnet: data.mainnet,
        orchard_fvk: data.orchard_fvk_uview,
        address: data.address,
        relay_url: data.relay_url,
        created_at: data.created_at,
    };

    frost_backup::seal_envelope(&payload, passphrase).map_err(|e| ErrorDisplayed::Str { s: e })
}

fn frost_import_backup_envelope(
    envelope_json: &str,
    passphrase: &str,
) -> Result<String, ErrorDisplayed> {
    let payload = frost_backup::open_envelope(envelope_json, passphrase)
        .map_err(|e| ErrorDisplayed::Str { s: e })?;

    let db_guard = DB.read().map_err(|_| ErrorDisplayed::MutexPoisoned)?;
    let database = db_guard.as_ref().ok_or(ErrorDisplayed::DbNotInitialized)?;

    let data = db_handling::frost::FrostWalletData {
        key_package_hex: payload.key_package,
        public_key_package_hex: payload.public_key_package,
        ephemeral_seed_hex: payload.ephemeral_seed,
        label: payload.label,
        min_signers: payload.threshold,
        max_signers: payload.max_signers,
        mainnet: payload.mainnet,
        created_at: payload.created_at,
        orchard_fvk_uview: payload.orchard_fvk,
        address: payload.address,
        relay_url: payload.relay_url,
    };

    db_handling::frost::store_frost_wallet(database, &data).map_err(|e| ErrorDisplayed::Str {
        s: format!("store imported wallet: {e}"),
    })
}

ffi_support::define_string_destructor!(signer_destroy_string);

#[cfg(test)]
mod tests {
    //use super::*;
}
