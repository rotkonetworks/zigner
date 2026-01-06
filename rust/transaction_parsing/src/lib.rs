#![deny(unused_crate_dependencies)]
#![deny(rustdoc::broken_intra_doc_links)]

use db_handling::identities::TransactionBulk;
use definitions::helpers::unhex;
use parity_scale_codec::Decode;

pub use definitions::navigation::{StubNav, TransactionAction};
mod add_specs;
use add_specs::add_specs;

use definitions::navigation::DecodeSequenceResult;

pub mod cards;
pub mod check_signature;
mod derivations;
pub use derivations::prepare_derivations_preview;
use derivations::process_derivations;
mod helpers;
mod holds;
mod load_metadata;
use load_metadata::load_metadata;
mod load_types;
use load_types::load_types;
mod message;
use message::{process_any_chain_message, process_concrete_chain_message};
pub mod parse_transaction;
pub use parse_transaction::entry_to_transactions_with_decoding;
use parse_transaction::{parse_transaction, parse_transaction_with_proof};
pub mod dynamic_derivations;
mod error;

// penumbra support
#[cfg(feature = "penumbra")]
pub mod penumbra;
#[cfg(feature = "penumbra")]
use penumbra::process_penumbra_transaction;

// zcash support
pub mod zcash;
use zcash::process_zcash_sign_request;

// penumbra schema support (always available)
pub mod penumbra_protobuf;
pub mod penumbra_schema_parser;
use penumbra_schema_parser::{
    process_penumbra_schema_update,
    process_penumbra_schema_digest,
    process_penumbra_registry,
};

#[cfg(test)]
mod tests;
use crate::dynamic_derivations::decode_dynamic_derivations;

pub use crate::error::{Error, Result};

/// Payload in hex format as it arrives into handling contains following elements:
/// - prelude, length 6 symbols ("53" stands for substrate, ** - crypto type, ** - transaction type),
///   see the standard for details,
/// - actual content (differs between transaction types, could be even empty)
///   actual content is handled individually depending on prelude
fn handle_scanner_input(database: &sled::Db, payload: &str) -> Result<TransactionAction> {
    let data_hex = {
        if let Some(a) = payload.strip_prefix("0x") {
            a
        } else {
            payload
        }
    };

    if data_hex.len() < 6 {
        return Err(Error::TooShort);
    }

    if &data_hex[..2] != "53" {
        return Err(Error::NotSubstrate(data_hex[..2].to_string()));
    }

    // check for zcash transactions first (crypto type 0x04)
    // format: [0x53][crypto_type][tx_type]
    // zcash uses crypto_type=0x04, tx_type=0x02 for sign requests
    if &data_hex[2..4] == "04" {
        return match &data_hex[4..6] {
            "02" => process_zcash_sign_request(database, data_hex),
            _ => Err(Error::PayloadNotSupported(format!("zcash tx type {}", &data_hex[4..6]))),
        };
    }

    match &data_hex[4..6] {
        "00" | "02" => parse_transaction(database, data_hex),
        "03" => process_concrete_chain_message(database, data_hex),
        "04" => parse_transaction_bulk(database, data_hex),
        "06" => parse_transaction_with_proof(database, data_hex),
        "08" => process_any_chain_message(database, data_hex),
        #[cfg(feature = "penumbra")]
        "10" => process_penumbra_transaction(database, data_hex),
        "12" => process_penumbra_schema_update(database, data_hex),
        "13" => process_penumbra_schema_digest(database, data_hex),
        "14" => process_penumbra_registry(database, data_hex),
        "80" => load_metadata(database, data_hex),
        "81" => load_types(database, data_hex),
        "c1" => add_specs(database, data_hex),
        "de" => process_derivations(database, data_hex),
        _ => Err(Error::PayloadNotSupported(data_hex[4..6].to_string())),
    }
}

/// Decode content of payload
/// `enable_dynamic_derivations` is a feature flag
pub fn decode_payload(
    payload: &str,
    enable_dynamic_derivations: bool,
) -> Result<DecodeSequenceResult> {
    let data_hex = {
        if let Some(a) = payload.strip_prefix("0x") {
            a
        } else {
            payload
        }
    };

    if data_hex.len() < 6 {
        return Err(Error::TooShort);
    }

    if &data_hex[..2] != "53" {
        return Err(Error::NotSubstrate(data_hex[..2].to_string()));
    }

    if !enable_dynamic_derivations {
        return Ok(DecodeSequenceResult::Other {
            s: payload.to_string(),
        });
    }

    match &data_hex[4..6] {
        "04" => decode_transaction_bulk(data_hex, enable_dynamic_derivations),
        "05" => Ok(DecodeSequenceResult::DynamicDerivationTransaction {
            s: vec![data_hex.to_string()],
        }),
        "07" => Ok(DecodeSequenceResult::DynamicDerivationTransaction {
            s: vec![data_hex.to_string()],
        }),
        "df" => decode_dynamic_derivations(data_hex),
        _ => Ok(DecodeSequenceResult::Other {
            s: payload.to_string(),
        }),
    }
}

fn parse_transaction_bulk(database: &sled::Db, payload: &str) -> Result<TransactionAction> {
    let decoded_data = unhex(payload)?;

    let bulk = TransactionBulk::decode(&mut &decoded_data[3..])?;

    match bulk {
        TransactionBulk::V1(b) => {
            let mut actions = vec![];

            let mut checksum = 0;
            for t in &b.encoded_transactions {
                let encoded = hex::encode(t);
                let encoded = "53".to_string() + &encoded;
                let action = if &encoded[4..6] == "06" {
                    parse_transaction_with_proof(database, &encoded)?
                } else {
                    parse_transaction(database, &encoded)?
                };
                match action {
                    TransactionAction::Sign {
                        actions: a,
                        checksum: c,
                    } => {
                        checksum = c;
                        actions.push(a[0].clone());
                    }
                    _ => return Ok(action),
                }
            }

            Ok(TransactionAction::Sign { actions, checksum })
        }
    }
}

fn decode_transaction_bulk(
    payload: &str,
    enable_dynamic_derivations: bool,
) -> Result<DecodeSequenceResult> {
    let decoded_data = unhex(payload)?;

    let bulk = TransactionBulk::decode(&mut &decoded_data[3..])?;

    match bulk {
        TransactionBulk::V1(b) => {
            let mut transactions = vec![];
            for t in &b.encoded_transactions {
                let encoded = hex::encode(t);
                let encoded = "53".to_string() + &encoded;
                match decode_payload(&encoded, enable_dynamic_derivations)? {
                    DecodeSequenceResult::DynamicDerivationTransaction { s } => {
                        transactions.extend(s);
                    }
                    // Do not attempt to handle non-dynamic derivation transactions here. Should be handled by handle_scanner_input
                    _ => {
                        return Ok(DecodeSequenceResult::Other {
                            s: payload.to_string(),
                        })
                    }
                }
            }
            Ok(DecodeSequenceResult::DynamicDerivationTransaction { s: transactions })
        }
    }
}

pub fn produce_output(database: &sled::Db, payload: &str) -> Result<TransactionAction> {
    handle_scanner_input(database, payload)
}
