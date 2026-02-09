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

// These crates are used by pczt but need to be declared here
// to satisfy the unused_crate_dependencies lint
use zcash_transparent as _;

mod ffi_types;

use crate::ffi_types::*;
use db_handling::identities::{import_all_addrs, inject_derivations_has_pwd};
use db_handling::{Error as DbHandlingError, Error};
use definitions::keyring::AddressKey;
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
    let genesis_hash_bytes = hex::decode(genesis_hash_hex)
        .map_err(|e| ErrorDisplayed::Str { s: format!("Invalid genesis hash hex: {e}") })?;
    if genesis_hash_bytes.len() != 32 {
        return Err(ErrorDisplayed::Str { s: "Genesis hash must be 32 bytes".to_string() });
    }
    let genesis_hash = H256::from_slice(&genesis_hash_bytes);

    let specs_invariants = genesis_hash_in_specs(&db, genesis_hash)
        .map_err(|e| ErrorDisplayed::Str { s: format!("{e}") })?
        .ok_or_else(|| ErrorDisplayed::Str { s: format!("Network with genesis hash {} not found", genesis_hash_hex) })?;

    db_handling::identities::try_create_address(&db, seed_name, seed_phrase, path, &specs_invariants.first_network_specs_key)
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
    use db_handling::identities::get_addresses_by_seed_name;
    use db_handling::helpers::try_get_network_specs;
    use serde_json::{json, Value};

    let db = get_db()?;
    let addresses = get_addresses_by_seed_name(&db, seed_name)
        .map_err(|e| ErrorDisplayed::from(format!("{e}")))?;

    let accounts: Vec<Value> = addresses
        .into_iter()
        .filter(|(_, details)| !details.is_root()) // skip root key, only derived accounts
        .map(|(_, details)| {
            // Look up network specs to get genesis_hash, network name, and base58prefix
            let (genesis_hash, network_name, base58prefix) = if let Some(ref network_id) = details.network_id {
                if let Ok(Some(specs)) = try_get_network_specs(&db, network_id) {
                    // Only include base58prefix for Substrate networks (sr25519/ed25519/ecdsa)
                    // Zcash and Penumbra don't use SS58 addresses
                    let prefix: Option<u16> = match details.encryption {
                        definitions::crypto::Encryption::Sr25519 |
                        definitions::crypto::Encryption::Ed25519 |
                        definitions::crypto::Encryption::Ecdsa => Some(specs.specs.base58prefix),
                        _ => None,
                    };
                    (Some(hex::encode(specs.specs.genesis_hash)), Some(specs.specs.name), prefix)
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
fn export_backup_qr(seed_name: &str, seed_phrase: &str, max_fragment_len: u32) -> Result<Vec<QrData>, ErrorDisplayed> {
    let ur_strings = export_backup_ur(seed_name, seed_phrase, max_fragment_len)?;

    // Convert each UR string to a QR image
    let qr_images: Result<Vec<QrData>, ErrorDisplayed> = ur_strings
        .into_iter()
        .map(|ur_string| {
            qrcode_static::png_qr_from_string(&ur_string, qrcode_static::DataType::Sensitive)
                .map(|data| QrData::Sensitive { data })
                .map_err(|e| ErrorDisplayed::Str { s: format!("QR encoding error: {e}") })
        })
        .collect();

    qr_images
}

/// Export seed backup as UR-encoded multipart string frames for device-to-device migration
/// Uses fountain codes for reliable animated QR scanning
/// max_fragment_len: max bytes per QR frame (0 = single QR, 200-500 typical for animated)
fn export_backup_ur(seed_name: &str, seed_phrase: &str, max_fragment_len: u32) -> Result<Vec<String>, ErrorDisplayed> {
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
        let mut encoder = ur::ur::Encoder::new(
            &cbor_data,
            max_fragment_len as usize,
            "zigner-backup",
        ).map_err(|e| ErrorDisplayed::Str {
            s: format!("Failed to create UR encoder: {:?}", e),
        })?;

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
        return Err(ErrorDisplayed::Str { s: "No UR parts provided".to_string() });
    }

    // Try single-part decode first
    if ur_parts.len() == 1 {
        let (_, cbor_data) = ur::ur::decode(&ur_parts[0])
            .map_err(|e| ErrorDisplayed::Str { s: format!("UR decode error: {:?}", e) })?;
        return extract_backup_json_from_cbor(&cbor_data);
    }

    // Multi-part decode using fountain codes
    let mut decoder = ur::ur::Decoder::default();

    for part in &ur_parts {
        decoder.receive(part)
            .map_err(|e| ErrorDisplayed::Str { s: format!("UR receive error: {:?}", e) })?;

        if decoder.complete() {
            match decoder.message() {
                Ok(Some(cbor_data)) => return extract_backup_json_from_cbor(&cbor_data),
                Ok(None) => return Err(ErrorDisplayed::Str { s: "UR decoder complete but no message".to_string() }),
                Err(e) => return Err(ErrorDisplayed::Str { s: format!("UR message error: {:?}", e) }),
            }
        }
    }

    Err(ErrorDisplayed::Str { s: "Incomplete UR data - need more frames".to_string() })
}

fn extract_backup_json_from_cbor(cbor_data: &[u8]) -> Result<String, ErrorDisplayed> {
    // Parse CBOR bytes using existing helper
    let (json_bytes, _) = parse_cbor_bytes(cbor_data).map_err(|e| ErrorDisplayed::Str {
        s: format!("Failed to parse CBOR: {}", e),
    })?;

    String::from_utf8(json_bytes)
        .map_err(|e| ErrorDisplayed::Str { s: format!("Invalid UTF-8 in backup: {e}") })
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
fn export_penumbra_fvk(
    seed_phrase: &str,
    account_index: u32,
    label: &str,
) -> Result<PenumbraFvkExport, ErrorDisplayed> {
    use transaction_signing::penumbra::{FvkExportData, FullViewingKey, SpendKeyBytes};

    // Derive spend key from seed phrase
    let spend_key_bytes = SpendKeyBytes::from_seed_phrase(seed_phrase, account_index)
        .map_err(|e| ErrorDisplayed::Str {
            s: format!("Failed to derive spend key: {e}"),
        })?;

    // Create FVK export data
    let label_opt = if label.is_empty() {
        None
    } else {
        Some(label.to_string())
    };
    let export_data =
        FvkExportData::from_spend_key(&spend_key_bytes, account_index, label_opt.clone())
            .map_err(|e| ErrorDisplayed::Str {
                s: format!("Failed to create FVK export: {e}"),
            })?;

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

        // PenumbraFullViewingKey: map with 2 or 3 entries
        let has_name = !label.is_empty();
        if has_name {
            cbor_data.push(0xa3); // map(3)
        } else {
            cbor_data.push(0xa2); // map(2)
        }

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
// Penumbra cold signing functions
// ============================================================================

/// Parse a Penumbra sign request from QR hex data
fn parse_penumbra_sign_request(qr_hex: &str) -> Result<PenumbraSignRequest, ErrorDisplayed> {
    use transaction_parsing::penumbra::parse_penumbra_transaction;

    let plan = parse_penumbra_transaction(qr_hex)
        .map_err(|e| ErrorDisplayed::Str { s: format!("Failed to parse Penumbra QR: {e}") })?;

    let effect_hash_hex = plan.effect_hash
        .map(|h| hex::encode(h))
        .unwrap_or_default();

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
    use transaction_parsing::penumbra::{parse_penumbra_transaction, SpendKeyBytes, sign_transaction};

    // Re-parse to get the full plan data
    let plan = parse_penumbra_transaction(&request.raw_qr_hex)
        .map_err(|e| ErrorDisplayed::Str { s: format!("Failed to parse Penumbra QR: {e}") })?;

    let effect_hash = plan.effect_hash
        .ok_or_else(|| ErrorDisplayed::Str { s: "No effect hash in QR".to_string() })?;

    // Derive spend key from seed phrase (account 0)
    let spend_key = SpendKeyBytes::from_seed_phrase(seed_phrase, 0)
        .map_err(|e| ErrorDisplayed::Str { s: format!("Key derivation failed: {e}") })?;

    // Sign the transaction
    let auth_data = sign_transaction(
        effect_hash,
        &plan.spend_randomizers,
        &plan.delegator_vote_randomizers,
        &plan.lqt_vote_randomizers,
        &spend_key,
    ).map_err(|e| ErrorDisplayed::Str { s: format!("Signing failed: {e}") })?;

    // Encode as QR response bytes
    Ok(auth_data.encode())
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
fn export_zcash_fvk(
    seed_phrase: &str,
    account_index: u32,
    label: &str,
    mainnet: bool,
) -> Result<ZcashFvkExport, ErrorDisplayed> {
    use transaction_signing::zcash::{OrchardSpendingKey, QR_TYPE_ZCASH_FVK_EXPORT};

    // Derive Orchard spending key from seed phrase using ZIP-32 derivation
    let osk = OrchardSpendingKey::from_seed_phrase(seed_phrase, account_index)
        .map_err(|e| ErrorDisplayed::Str {
            s: format!("Failed to derive Orchard key: {e}"),
        })?;

    // Get FVK bytes (96 bytes raw orchard full viewing key)
    let fvk_bytes = osk.fvk_bytes();

    // Get receiving address (unified address with orchard receiver)
    let address = osk.get_address(mainnet);

    // Get UFVK string (standard Zcash unified full viewing key format per ZIP-316)
    // Format: "uview1..." for mainnet, "uviewtest1..." for testnet
    let ufvk = osk.get_ufvk(mainnet);

    // Generate seed fingerprint: first 16 bytes of SHA256(seed_phrase)
    // This allows Zashi to match accounts to the same seed without revealing the seed
    let seed_fingerprint = {
        use sha2::{Sha256, Digest};
        let hash = Sha256::digest(seed_phrase.as_bytes());
        hash[..16].to_vec()
    };

    // ========================================================================
    // Build UR-encoded "zcash-accounts" for Zashi/Keystone QR code compatibility
    //
    // The UR string format is: ur:zcash-accounts/<bytewords-encoded-cbor>
    // where the CBOR payload matches the Keystone SDK zcash_accounts.rs structure
    // ========================================================================
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

        // ZcashUnifiedFullViewingKey: map with 2 or 3 entries
        let has_name = !label.is_empty();
        if has_name {
            cbor_data.push(0xa3); // map(3)
        } else {
            cbor_data.push(0xa2); // map(2)
        }

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

    // flags: bit 0 = mainnet, bit 1 = has orchard, bit 2 = has transparent, bit 3 = has address
    let flags: u8 = (if mainnet { 0x01 } else { 0x00 }) | 0x02 | 0x08; // has orchard + has address

    let mut qr_data = Vec::with_capacity(3 + 1 + 4 + 1 + label_bytes.len() + 96 + 2 + address_bytes.len());
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

    Ok(ZcashFvkExport {
        account_index,
        label: label.to_string(),
        mainnet,
        address,
        fvk_hex: hex::encode(&fvk_bytes),
        ufvk,
        qr_data,
        ur_string,
    })
}

/// Parse Zcash sign request from QR hex data
fn parse_zcash_sign_request(qr_hex: &str) -> Result<ZcashSignRequest, ErrorDisplayed> {
    use transaction_signing::zcash::ZcashSignRequest as RustSignRequest;

    let request = RustSignRequest::from_qr_hex(qr_hex).map_err(|e| ErrorDisplayed::Str {
        s: format!("Failed to parse sign request: {e}"),
    })?;

    Ok(ZcashSignRequest {
        account_index: request.account_index,
        sighash: hex::encode(&request.sighash),
        alphas: request.orchard_alphas.iter().map(hex::encode).collect(),
        summary: request.summary,
        mainnet: request.mainnet,
    })
}

/// Sign Zcash transaction and return signature response
fn sign_zcash_transaction(
    seed_phrase: &str,
    request: ZcashSignRequest,
) -> Result<ZcashSignatureResponse, ErrorDisplayed> {
    use transaction_signing::zcash::ZcashSignRequest as RustSignRequest;

    // Convert back to Rust type
    let sighash: [u8; 32] = hex::decode(&request.sighash)
        .map_err(|e| ErrorDisplayed::Str {
            s: format!("Invalid sighash hex: {e}"),
        })?
        .try_into()
        .map_err(|_| ErrorDisplayed::Str {
            s: "Sighash must be 32 bytes".to_string(),
        })?;

    let orchard_alphas: Vec<[u8; 32]> = request
        .alphas
        .iter()
        .map(|a| {
            hex::decode(a)
                .map_err(|e| ErrorDisplayed::Str {
                    s: format!("Invalid alpha hex: {e}"),
                })?
                .try_into()
                .map_err(|_| ErrorDisplayed::Str {
                    s: "Alpha must be 32 bytes".to_string(),
                })
        })
        .collect::<Result<Vec<_>, _>>()?;

    let rust_request = RustSignRequest {
        account_index: request.account_index,
        sighash,
        orchard_alphas,
        summary: request.summary,
        mainnet: request.mainnet,
    };

    // Sign the transaction
    let response = rust_request
        .sign(seed_phrase)
        .map_err(|e| ErrorDisplayed::Str {
            s: format!("Signing failed: {e}"),
        })?;

    Ok(ZcashSignatureResponse {
        sighash: hex::encode(&response.sighash),
        orchard_sigs: response.orchard_sigs.iter().map(hex::encode).collect(),
    })
}

/// Encode Zcash signature response as QR bytes
fn encode_zcash_signature_qr(response: ZcashSignatureResponse) -> Result<Vec<u8>, ErrorDisplayed> {
    use transaction_signing::zcash::ZcashSignatureResponse as RustResponse;

    let sighash: [u8; 32] = hex::decode(&response.sighash)
        .map_err(|e| ErrorDisplayed::Str {
            s: format!("Invalid sighash hex: {e}"),
        })?
        .try_into()
        .map_err(|_| ErrorDisplayed::Str {
            s: "Sighash must be 32 bytes".to_string(),
        })?;

    let orchard_sigs: Vec<[u8; 64]> = response
        .orchard_sigs
        .iter()
        .map(|s| {
            hex::decode(s)
                .map_err(|e| ErrorDisplayed::Str {
                    s: format!("Invalid signature hex: {e}"),
                })?
                .try_into()
                .map_err(|_| ErrorDisplayed::Str {
                    s: "Signature must be 64 bytes".to_string(),
                })
        })
        .collect::<Result<Vec<_>, _>>()?;

    let rust_response = RustResponse {
        sighash,
        transparent_sigs: vec![], // No transparent for now
        orchard_sigs,
    };

    Ok(rust_response.to_qr_bytes())
}

/// Generate a test Zcash sign request QR (for development/testing only)
/// Returns hex-encoded QR payload
fn generate_test_zcash_sign_request(
    account_index: u32,
    action_count: u32,
    mainnet: bool,
    summary: &str,
) -> String {
    let mut data = Vec::new();

    // prelude: [0x53][0x04][0x02]
    data.push(0x53);
    data.push(0x04);
    data.push(0x02);

    // flags: bit 0 = mainnet
    data.push(if mainnet { 0x01 } else { 0x00 });

    // account index (4 bytes LE)
    data.extend_from_slice(&account_index.to_le_bytes());

    // sighash (32 bytes) - use deterministic test value
    let test_sighash: [u8; 32] = [
        0xde, 0xad, 0xbe, 0xef, 0x12, 0x34, 0x56, 0x78,
        0x9a, 0xbc, 0xde, 0xf0, 0x11, 0x22, 0x33, 0x44,
        0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc,
        0xdd, 0xee, 0xff, 0x00, 0x01, 0x02, 0x03, 0x04,
    ];
    data.extend_from_slice(&test_sighash);

    // action count (2 bytes LE)
    data.extend_from_slice(&(action_count as u16).to_le_bytes());

    // alphas (32 bytes each) - use deterministic test values
    for i in 0..action_count {
        let mut alpha = [0u8; 32];
        // fill with pattern based on index
        for j in 0..32 {
            alpha[j] = (i as u8).wrapping_mul(17).wrapping_add(j as u8);
        }
        data.extend_from_slice(&alpha);
    }

    // summary (length-prefixed)
    let summary_bytes = summary.as_bytes();
    data.extend_from_slice(&(summary_bytes.len() as u16).to_le_bytes());
    data.extend_from_slice(summary_bytes);

    hex::encode(data)
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
                s: format!("Expected ur:zcash-pczt/... got: {}", ur_string.chars().take(30).collect::<String>()),
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

        let cbor_data = decoder.message().map_err(|e| ErrorDisplayed::Str {
            s: format!("Failed to get UR message: {:?}", e),
        })?.ok_or_else(|| ErrorDisplayed::Str {
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
        return Err(format!("Expected bytes (major type 2), got: {}", major_type));
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
            (u32::from_be_bytes([data[1], data[2], data[3], data[4]]) as usize, 5)
        }
        _ => return Err(format!("Unsupported CBOR additional info: {}", additional)),
    };

    if data.len() < header_len + len {
        return Err("Truncated CBOR bytes".to_string());
    }

    Ok((data[header_len..header_len + len].to_vec(), header_len + len))
}

/// Sign a PCZT and return the signed PCZT bytes
///
/// This function:
/// 1. Parses the PCZT to extract orchard actions
/// 2. Signs each action with the spending key derived from seed
/// 3. Injects signatures back into the PCZT
fn sign_zcash_pczt(
    seed_phrase: &str,
    account_index: u32,
    pczt_bytes: Vec<u8>,
) -> Result<Vec<u8>, ErrorDisplayed> {
    use pczt::Pczt;
    use pczt::roles::signer::Signer;
    use transaction_signing::zcash::OrchardSpendingKey;

    // Parse the PCZT to get action count first
    let pczt = Pczt::parse(&pczt_bytes).map_err(|e| ErrorDisplayed::Str {
        s: format!("Failed to parse PCZT: {:?}", e),
    })?;

    // Get number of orchard actions before creating signer
    let action_count = pczt.orchard().actions().len();

    // Derive the orchard spending key from seed
    let spending_key = OrchardSpendingKey::from_seed_phrase(seed_phrase, account_index)
        .map_err(|e| ErrorDisplayed::Str {
            s: format!("Failed to derive spending key: {}", e),
        })?;

    // Get the actual orchard spending key for signing
    let orchard_sk = spending_key.to_spending_key().map_err(|e| ErrorDisplayed::Str {
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
        signer.sign_orchard(action_index, &ask).map_err(|e| ErrorDisplayed::Str {
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
fn encode_signed_pczt_ur(pczt_bytes: Vec<u8>, max_fragment_len: u32) -> Result<Vec<String>, ErrorDisplayed> {
    // Wrap PCZT bytes in CBOR: { 1: bytes }
    let cbor_data = encode_pczt_to_cbor(&pczt_bytes);

    if max_fragment_len == 0 || cbor_data.len() <= max_fragment_len as usize {
        // Single part UR
        let ur_string = ur::ur::encode(&cbor_data, &ur::Type::Custom("zcash-pczt"));
        Ok(vec![ur_string])
    } else {
        // Multi-part (animated) UR using fountain codes
        let mut encoder = ur::ur::Encoder::new(
            &cbor_data,
            max_fragment_len as usize,
            "zcash-pczt",
        ).map_err(|e| ErrorDisplayed::Str {
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

    let _ = oslog::OsLogger::new("io.parity.signer")
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

ffi_support::define_string_destructor!(signer_destroy_string);

#[cfg(test)]
mod tests {
    //use super::*;
}
