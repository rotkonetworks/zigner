//! Penumbra schema and registry QR parser
//!
//! Parses schema update QR codes and validates them.
//!
//! QR Types:
//! - 0x12: Full schema [0x53][0x03][0x12][version:4LE][checksum:32][schema_json]
//! - 0x13: Merkle schema digest (compact)
//! - 0x14: Asset registry digest (compact)

use definitions::helpers::unhex;
use definitions::navigation::{
    Card, PenumbraSchemaInfo, TransactionAction, TransactionCard, TransactionCardSet,
};
use definitions::penumbra_schema::{
    decode_registry_qr, decode_schema_digest_qr, PenumbraActionSchema, RegistryDigest,
    SchemaDigest, PENUMBRA_SCHEMA_QR_TYPE,
};

use crate::{Error, Result};

/// Process a Penumbra schema update QR - entry point for router
pub fn process_penumbra_schema_update(
    database: &sled::Db,
    data_hex: &str,
) -> Result<TransactionAction> {
    let (schema, action) = parse_penumbra_schema_update(data_hex)?;

    // Store schema in database
    db_handling::penumbra::store_schema(database, &schema)
        .map_err(|e| Error::PenumbraParseError(format!("failed to store schema: {}", e)))?;

    Ok(action)
}

/// Parse a Penumbra schema update QR
pub fn parse_penumbra_schema_update(
    data_hex: &str,
) -> Result<(PenumbraActionSchema, TransactionAction)> {
    let data = unhex(data_hex)?;

    // Verify prelude: [0x53][crypto_type][tx_type]
    if data.len() < 3 {
        return Err(Error::TooShort);
    }

    if data[0] != 0x53 {
        return Err(Error::NotSubstrate(data[0].to_string()));
    }

    // Crypto type 0x03 = Penumbra
    if data[1] != 0x03 {
        return Err(Error::PenumbraParseError(format!(
            "expected crypto type 0x03, got 0x{:02x}",
            data[1]
        )));
    }

    // TX type 0x12 = schema update
    if data[2] != PENUMBRA_SCHEMA_QR_TYPE {
        return Err(Error::PenumbraParseError(format!(
            "expected tx type 0x12, got 0x{:02x}",
            data[2]
        )));
    }

    if data.len() < 39 {
        // 3 (prelude) + 4 (version) + 32 (checksum) = 39 minimum
        return Err(Error::PenumbraParseError("schema QR too short".to_string()));
    }

    // Parse version (4 bytes little-endian)
    let version = u32::from_le_bytes([data[3], data[4], data[5], data[6]]);

    // Parse checksum (32 bytes) - for now just skip
    let _checksum = &data[7..39];

    // Parse schema JSON
    let schema_bytes = &data[39..];
    let schema: PenumbraActionSchema = serde_json::from_slice(schema_bytes)
        .map_err(|e| Error::PenumbraParseError(format!("failed to parse schema JSON: {}", e)))?;

    // Verify version matches
    if schema.version != version {
        return Err(Error::PenumbraParseError(format!(
            "version mismatch: header says {}, schema says {}",
            version, schema.version
        )));
    }

    // Create display cards
    let cards = create_schema_cards(&schema);
    // Use Read action to display schema info before storing
    let action = TransactionAction::Read { r: Box::new(cards) };

    Ok((schema, action))
}

/// Create display cards for schema info
fn create_schema_cards(schema: &PenumbraActionSchema) -> TransactionCardSet {
    let mut method_cards = Vec::new();

    // Schema info card
    method_cards.push(TransactionCard {
        index: 0,
        indent: 0,
        card: Card::PenumbraSchemaCard {
            f: PenumbraSchemaInfo {
                chain_id: schema.chain_id.clone(),
                protocol_version: schema.protocol_version.clone(),
                action_count: schema.actions.len() as u32,
                schema_version: schema.version,
            },
        },
    });

    // List some key actions
    method_cards.push(TransactionCard {
        index: 1,
        indent: 0,
        card: Card::TextCard {
            f: format!("Actions defined: {}", schema.actions.len()),
        },
    });

    // Show a few example actions
    let mut action_list: Vec<_> = schema.actions.iter().collect();
    action_list.sort_by_key(|(k, _)| *k);

    for (i, (field_num, action)) in action_list.iter().take(10).enumerate() {
        method_cards.push(TransactionCard {
            index: (i + 2) as u32,
            indent: 1,
            card: Card::TextCard {
                f: format!("  {} ({}): {}", field_num, action.name, action.display_name),
            },
        });
    }

    if schema.actions.len() > 10 {
        method_cards.push(TransactionCard {
            index: 12,
            indent: 1,
            card: Card::TextCard {
                f: format!("  ... and {} more", schema.actions.len() - 10),
            },
        });
    }

    TransactionCardSet {
        method: Some(method_cards),
        ..Default::default()
    }
}

/// Encode a schema to QR format
pub fn encode_schema_to_qr(schema: &PenumbraActionSchema) -> Result<Vec<u8>> {
    let schema_json = serde_json::to_vec(schema)
        .map_err(|e| Error::PenumbraParseError(format!("failed to encode schema: {}", e)))?;

    // Calculate checksum (simple hash for now - should use blake2)
    let checksum = simple_checksum(&schema_json);

    let mut result = Vec::with_capacity(39 + schema_json.len());

    // Prelude
    result.push(0x53);
    result.push(0x03); // Penumbra crypto type
    result.push(PENUMBRA_SCHEMA_QR_TYPE);

    // Version (4 bytes LE)
    result.extend_from_slice(&schema.version.to_le_bytes());

    // Checksum (32 bytes)
    result.extend_from_slice(&checksum);

    // Schema JSON
    result.extend_from_slice(&schema_json);

    Ok(result)
}

/// Simple checksum (replace with proper blake2 in production)
fn simple_checksum(data: &[u8]) -> [u8; 32] {
    let mut hash = [0u8; 32];
    for (i, byte) in data.iter().enumerate() {
        hash[i % 32] ^= byte;
    }
    hash
}

// =============================================================================
// Schema Digest (Merkleized) - 0x13
// =============================================================================

/// Process a Penumbra schema digest QR (compact merkleized format)
pub fn process_penumbra_schema_digest(
    database: &sled::Db,
    data_hex: &str,
) -> Result<TransactionAction> {
    let data = unhex(data_hex)?;

    // Decode using the binary format decoder
    let digest = decode_schema_digest_qr(&data).map_err(Error::PenumbraParseError)?;

    // Store in database
    db_handling::penumbra::store_schema_digest(database, &digest)
        .map_err(|e| Error::PenumbraParseError(format!("failed to store schema digest: {}", e)))?;

    // Create display cards
    let cards = create_schema_digest_cards(&digest);
    Ok(TransactionAction::Read { r: Box::new(cards) })
}

/// Create display cards for schema digest
fn create_schema_digest_cards(digest: &SchemaDigest) -> TransactionCardSet {
    let mut method_cards = Vec::new();

    method_cards.push(TransactionCard {
        index: 0,
        indent: 0,
        card: Card::TextCard {
            f: "Penumbra Schema Digest (Merkleized)".to_string(),
        },
    });

    method_cards.push(TransactionCard {
        index: 1,
        indent: 0,
        card: Card::TextCard {
            f: format!("Chain: {}", digest.chain_id),
        },
    });

    method_cards.push(TransactionCard {
        index: 2,
        indent: 0,
        card: Card::TextCard {
            f: format!("Protocol: {}", digest.protocol_version),
        },
    });

    method_cards.push(TransactionCard {
        index: 3,
        indent: 0,
        card: Card::TextCard {
            f: format!("Actions: {}", digest.action_count),
        },
    });

    method_cards.push(TransactionCard {
        index: 4,
        indent: 0,
        card: Card::TextCard {
            f: format!(
                "Merkle Root: {}...",
                &digest.root_hex()[..32.min(digest.root_hex().len())]
            ),
        },
    });

    TransactionCardSet {
        method: Some(method_cards),
        ..Default::default()
    }
}

// =============================================================================
// Asset Registry Digest - 0x14
// =============================================================================

/// Process a Penumbra asset registry QR
pub fn process_penumbra_registry(database: &sled::Db, data_hex: &str) -> Result<TransactionAction> {
    let data = unhex(data_hex)?;

    // Decode using the binary format decoder
    let digest = decode_registry_qr(&data).map_err(Error::PenumbraParseError)?;

    // Store in database (both as current and by chain_id)
    db_handling::penumbra::store_registry_digest(database, &digest)
        .map_err(|e| Error::PenumbraParseError(format!("failed to store registry: {}", e)))?;

    db_handling::penumbra::store_registry_for_chain(database, &digest.chain_id, &digest).map_err(
        |e| Error::PenumbraParseError(format!("failed to store registry for chain: {}", e)),
    )?;

    // Create display cards
    let cards = create_registry_cards(&digest);
    Ok(TransactionAction::Read { r: Box::new(cards) })
}

/// Create display cards for registry digest
fn create_registry_cards(digest: &RegistryDigest) -> TransactionCardSet {
    let mut method_cards = Vec::new();

    method_cards.push(TransactionCard {
        index: 0,
        indent: 0,
        card: Card::TextCard {
            f: "Penumbra Asset Registry Update".to_string(),
        },
    });

    method_cards.push(TransactionCard {
        index: 1,
        indent: 0,
        card: Card::TextCard {
            f: format!("Chain: {}", digest.chain_id),
        },
    });

    method_cards.push(TransactionCard {
        index: 2,
        indent: 0,
        card: Card::TextCard {
            f: format!("Assets: {}", digest.asset_count),
        },
    });

    method_cards.push(TransactionCard {
        index: 3,
        indent: 0,
        card: Card::TextCard {
            f: format!("Merkle Root: {}...", digest.root_hex()),
        },
    });

    // Convert timestamp to human-readable if it looks valid
    if digest.timestamp > 0 {
        method_cards.push(TransactionCard {
            index: 4,
            indent: 0,
            card: Card::TextCard {
                f: format!("Timestamp: {}", digest.timestamp),
            },
        });
    }

    method_cards.push(TransactionCard {
        index: 5,
        indent: 0,
        card: Card::TextCard {
            f: "Registry digest stored successfully!".to_string(),
        },
    });

    TransactionCardSet {
        method: Some(method_cards),
        ..Default::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use definitions::penumbra_schema::default_penumbra_schema;

    #[test]
    fn test_encode_decode_roundtrip() {
        let schema = default_penumbra_schema();
        let encoded = encode_schema_to_qr(&schema).unwrap();
        let hex = encoded
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<String>();

        let (decoded, _) = parse_penumbra_schema_update(&hex).unwrap();
        assert_eq!(schema, decoded);
    }

    #[test]
    fn test_schema_contains_token_factory() {
        let schema = default_penumbra_schema();
        assert!(schema.actions.contains_key(&61)); // TokenFactoryCreate
        assert!(schema.actions.contains_key(&62)); // TokenFactoryMint
    }
}
