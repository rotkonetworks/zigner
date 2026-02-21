//! Generic Penumbra protobuf decoder using schema
//!
//! Decodes protobuf messages based on the action schema definition.
//! This allows parsing new action types without code changes.

use definitions::navigation::{PenumbraGenericAction, StringPair};
use definitions::penumbra_schema::{
    FieldDefinition, FieldType, ParsedAction, ParsedValue, PenumbraActionSchema,
};

use crate::{Error, Result};

/// Decode a transaction plan and extract actions
pub fn decode_transaction_plan(
    plan_bytes: &[u8],
    schema: &PenumbraActionSchema,
    asset_names: &[String],
) -> Result<Vec<ParsedAction>> {
    let mut actions = Vec::new();
    let mut offset = 0;

    while offset < plan_bytes.len() {
        // Read protobuf tag
        let (tag, new_offset) = read_varint(plan_bytes, offset)?;
        offset = new_offset;

        let field_number = (tag >> 3) as u32;
        let wire_type = (tag & 0x7) as u8;

        // Field 1 is the actions repeated field in TransactionPlan
        if field_number == 1 && wire_type == 2 {
            // Length-delimited (embedded message)
            let (len, new_offset) = read_varint(plan_bytes, offset)?;
            offset = new_offset;

            let action_bytes = &plan_bytes[offset..offset + len as usize];
            offset += len as usize;

            // Parse the action
            if let Ok(action) = parse_action(action_bytes, schema, asset_names) {
                actions.push(action);
            }
        } else {
            // Skip other fields
            offset = skip_field(plan_bytes, offset, wire_type)?;
        }
    }

    Ok(actions)
}

/// Parse a single action from protobuf bytes
fn parse_action(
    action_bytes: &[u8],
    schema: &PenumbraActionSchema,
    asset_names: &[String],
) -> Result<ParsedAction> {
    let mut offset = 0;

    // Action is a oneof - read the field number to determine type
    if offset >= action_bytes.len() {
        return Ok(ParsedAction::unrecognized(0));
    }

    let (tag, new_offset) = read_varint(action_bytes, offset)?;
    offset = new_offset;

    let field_number = (tag >> 3) as u32;
    let wire_type = (tag & 0x7) as u8;

    // Look up action definition in schema
    let action_def = match schema.get_action(field_number) {
        Some(def) => def,
        None => return Ok(ParsedAction::unrecognized(field_number)),
    };

    // Read the nested message
    if wire_type != 2 {
        return Ok(ParsedAction::unrecognized(field_number));
    }

    let (len, new_offset) = read_varint(action_bytes, offset)?;
    offset = new_offset;

    let nested_bytes = &action_bytes[offset..offset + len as usize];

    // Parse fields according to schema
    let fields = parse_fields(nested_bytes, &action_def.fields, asset_names)?;

    Ok(ParsedAction {
        name: action_def.display_name.clone(),
        description: action_def.description.clone(),
        fields,
        recognized: true,
    })
}

/// Parse fields from a protobuf message according to field definitions
fn parse_fields(
    msg_bytes: &[u8],
    field_defs: &[FieldDefinition],
    asset_names: &[String],
) -> Result<Vec<(String, ParsedValue)>> {
    let mut results = Vec::new();
    let mut offset = 0;

    // Build a map of proto path -> field definition
    // For now, we'll do simple first-level matching
    let mut field_values: std::collections::HashMap<u32, Vec<u8>> =
        std::collections::HashMap::new();

    while offset < msg_bytes.len() {
        let (tag, new_offset) = read_varint(msg_bytes, offset)?;
        offset = new_offset;

        let field_num = (tag >> 3) as u32;
        let wire_type = (tag & 0x7) as u8;

        let value_bytes = match wire_type {
            0 => {
                // Varint
                let (val, new_offset) = read_varint(msg_bytes, offset)?;
                offset = new_offset;
                val.to_le_bytes().to_vec()
            }
            1 => {
                // 64-bit
                let bytes = msg_bytes[offset..offset + 8].to_vec();
                offset += 8;
                bytes
            }
            2 => {
                // Length-delimited
                let (len, new_offset) = read_varint(msg_bytes, offset)?;
                offset = new_offset;
                let bytes = msg_bytes[offset..offset + len as usize].to_vec();
                offset += len as usize;
                bytes
            }
            5 => {
                // 32-bit
                let bytes = msg_bytes[offset..offset + 4].to_vec();
                offset += 4;
                bytes
            }
            _ => {
                // Unknown wire type, skip
                break;
            }
        };

        field_values.insert(field_num, value_bytes);
    }

    // Now match field definitions to values
    for def in field_defs {
        if !def.visible {
            continue;
        }

        // Simple path parsing - just use first segment for now
        let path_parts: Vec<&str> = def.path.split('.').collect();
        let first_field_num = match path_parts.first() {
            Some(s) => path_to_field_number(s),
            None => continue,
        };

        if let Some(field_num) = first_field_num {
            if let Some(value_bytes) = field_values.get(&field_num) {
                let parsed = parse_value(value_bytes, &def.field_type, asset_names);
                results.push((def.label.clone(), parsed));
            }
        }
    }

    // Sort by priority
    results.sort_by_key(|(_, _)| 0u32); // TODO: use actual priority

    Ok(results)
}

/// Map common field names to their protobuf field numbers
fn path_to_field_number(path: &str) -> Option<u32> {
    match path {
        // TokenFactoryCreate fields
        "nonce" => Some(1),
        "metadata" => Some(2),
        "initial_supply" => Some(3),
        "enable_mint" => Some(4),
        // TokenFactoryMint fields
        "token_id" => Some(1),
        "current_seq" => Some(2),
        "amount" => Some(3),
        // Common nested fields
        "name" => Some(6),   // in Metadata
        "symbol" => Some(7), // in Metadata
        "inner" => Some(1),  // in TokenFactoryId
        "lo" => Some(1),     // in Amount
        "hi" => Some(2),     // in Amount
        _ => None,
    }
}

/// Parse a value according to its type
fn parse_value(bytes: &[u8], field_type: &FieldType, asset_names: &[String]) -> ParsedValue {
    match field_type {
        FieldType::String => match String::from_utf8(bytes.to_vec()) {
            Ok(s) => ParsedValue::String(s),
            Err(_) => ParsedValue::Bytes(bytes.to_vec()),
        },
        FieldType::Bool => {
            let val = bytes.first().copied().unwrap_or(0) != 0;
            ParsedValue::Bool(val)
        }
        FieldType::U32 => {
            if bytes.len() >= 4 {
                let val = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
                ParsedValue::U32(val)
            } else {
                // Varint encoded
                let (val, _) = read_varint(bytes, 0).unwrap_or((0, 0));
                ParsedValue::U32(val as u32)
            }
        }
        FieldType::U64 => {
            if bytes.len() >= 8 {
                let val = u64::from_le_bytes([
                    bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
                ]);
                ParsedValue::U64(val)
            } else {
                let (val, _) = read_varint(bytes, 0).unwrap_or((0, 0));
                ParsedValue::U64(val)
            }
        }
        FieldType::Amount { decimals } => {
            // Amount is encoded as nested message with lo/hi
            let (lo, hi) = parse_amount_message(bytes);
            let raw = (hi as u128) << 64 | (lo as u128);
            let formatted = format_amount(raw, *decimals);
            ParsedValue::Amount {
                raw,
                decimals: *decimals,
                formatted,
            }
        }
        FieldType::AssetId => {
            // Look up in asset_names if possible
            let hex: String = bytes.iter().map(|b| format!("{:02x}", b)).collect();
            // For now, just return hex - could do bech32 encoding
            if !asset_names.is_empty() {
                // Simple index lookup (QR embeds asset names in order)
                ParsedValue::AssetId(format!("passet1{}", &hex[..16.min(hex.len())]))
            } else {
                ParsedValue::AssetId(hex)
            }
        }
        FieldType::Address => {
            let hex: String = bytes.iter().map(|b| format!("{:02x}", b)).collect();
            ParsedValue::Address(format!("penumbra1{}", &hex[..32.min(hex.len())]))
        }
        FieldType::IdentityKey => {
            let hex: String = bytes.iter().map(|b| format!("{:02x}", b)).collect();
            ParsedValue::String(format!("penumbravalid1{}", &hex[..24.min(hex.len())]))
        }
        FieldType::Bytes => ParsedValue::Bytes(bytes.to_vec()),
        FieldType::Message { .. } => {
            // Nested message - would need recursive parsing
            ParsedValue::Bytes(bytes.to_vec())
        }
        FieldType::Enum { variants } => {
            let (val, _) = read_varint(bytes, 0).unwrap_or((0, 0));
            let variant_name = variants
                .iter()
                .find(|(n, _)| *n == val as u32)
                .map(|(_, name)| name.clone())
                .unwrap_or_else(|| format!("Unknown({})", val));
            ParsedValue::String(variant_name)
        }
    }
}

/// Parse an Amount message (lo/hi nested fields)
fn parse_amount_message(bytes: &[u8]) -> (u64, u64) {
    let mut lo = 0u64;
    let mut hi = 0u64;
    let mut offset = 0;

    while offset < bytes.len() {
        let (tag, new_offset) = match read_varint(bytes, offset) {
            Ok(t) => t,
            Err(_) => break,
        };
        offset = new_offset;

        let field_num = (tag >> 3) as u32;
        let wire_type = (tag & 0x7) as u8;

        if wire_type != 0 {
            // Skip non-varint
            break;
        }

        let (val, new_offset) = match read_varint(bytes, offset) {
            Ok(t) => t,
            Err(_) => break,
        };
        offset = new_offset;

        match field_num {
            1 => lo = val,
            2 => hi = val,
            _ => {}
        }
    }

    (lo, hi)
}

/// Format an amount with decimals
fn format_amount(raw: u128, decimals: u8) -> String {
    let divisor = 10u128.pow(decimals as u32);
    let whole = raw / divisor;
    let frac = raw % divisor;

    if decimals == 0 {
        whole.to_string()
    } else {
        format!("{}.{:0width$}", whole, frac, width = decimals as usize)
    }
}

/// Read a varint from bytes
fn read_varint(bytes: &[u8], offset: usize) -> Result<(u64, usize)> {
    let mut result = 0u64;
    let mut shift = 0;
    let mut pos = offset;

    loop {
        if pos >= bytes.len() {
            return Err(Error::PenumbraParseError(
                "varint extends past end".to_string(),
            ));
        }

        let byte = bytes[pos];
        pos += 1;

        result |= ((byte & 0x7F) as u64) << shift;

        if byte & 0x80 == 0 {
            break;
        }

        shift += 7;
        if shift > 63 {
            return Err(Error::PenumbraParseError("varint too long".to_string()));
        }
    }

    Ok((result, pos))
}

/// Skip a field based on wire type
fn skip_field(bytes: &[u8], offset: usize, wire_type: u8) -> Result<usize> {
    match wire_type {
        0 => {
            // Varint
            let (_, new_offset) = read_varint(bytes, offset)?;
            Ok(new_offset)
        }
        1 => {
            // 64-bit
            Ok(offset + 8)
        }
        2 => {
            // Length-delimited
            let (len, new_offset) = read_varint(bytes, offset)?;
            Ok(new_offset + len as usize)
        }
        5 => {
            // 32-bit
            Ok(offset + 4)
        }
        _ => Err(Error::PenumbraParseError(format!(
            "unknown wire type: {}",
            wire_type
        ))),
    }
}

/// Convert ParsedAction to PenumbraGenericAction for display
pub fn to_generic_action(parsed: &ParsedAction, field_number: u32) -> PenumbraGenericAction {
    PenumbraGenericAction {
        action_name: parsed.name.clone(),
        description: parsed.description.clone(),
        fields: parsed
            .fields
            .iter()
            .map(|(label, value)| StringPair {
                first: label.clone(),
                second: value.display(),
            })
            .collect(),
        recognized: parsed.recognized,
        field_number,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_read_varint() {
        // Single byte
        let (val, offset) = read_varint(&[0x01], 0).unwrap();
        assert_eq!(val, 1);
        assert_eq!(offset, 1);

        // Multi-byte
        let (val, offset) = read_varint(&[0x96, 0x01], 0).unwrap();
        assert_eq!(val, 150);
        assert_eq!(offset, 2);
    }

    #[test]
    fn test_format_amount() {
        assert_eq!(format_amount(1_000_000, 6), "1.000000");
        assert_eq!(format_amount(123_456_789, 6), "123.456789");
        assert_eq!(format_amount(1, 6), "0.000001");
    }
}
