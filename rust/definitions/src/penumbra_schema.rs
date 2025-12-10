//! Penumbra Action Schema
//!
//! Dynamic schema system for parsing and displaying Penumbra transaction actions.
//! Allows updating action type definitions via QR codes without app updates.
//!
//! Similar to Polkadot's metadata update system, but designed for protobuf-based
//! Penumbra transactions.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Schema version - increment when format changes
pub const PENUMBRA_SCHEMA_VERSION: u32 = 1;

/// QR type for schema updates (0x12 in the tx_type field)
pub const PENUMBRA_SCHEMA_QR_TYPE: u8 = 0x12;

/// QR type for merkleized schema digest (0x13)
pub const PENUMBRA_MERKLE_SCHEMA_QR_TYPE: u8 = 0x13;

/// QR type for asset registry digest (0x14)
pub const PENUMBRA_REGISTRY_QR_TYPE: u8 = 0x14;

/// Complete schema for Penumbra transaction parsing
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PenumbraActionSchema {
    /// Schema format version
    pub version: u32,
    /// Chain ID this schema applies to (e.g., "penumbra-1")
    pub chain_id: String,
    /// Protocol version (e.g., "2.1.0")
    pub protocol_version: String,
    /// Action definitions keyed by protobuf field number in Action oneof
    pub actions: HashMap<u32, ActionDefinition>,
    /// Common type definitions (Amount, Address, etc.)
    pub types: HashMap<String, TypeDefinition>,
}

impl PenumbraActionSchema {
    /// Create a new empty schema
    pub fn new(chain_id: String, protocol_version: String) -> Self {
        Self {
            version: PENUMBRA_SCHEMA_VERSION,
            chain_id,
            protocol_version,
            actions: HashMap::new(),
            types: default_types(),
        }
    }

    /// Get action definition by field number
    pub fn get_action(&self, field_number: u32) -> Option<&ActionDefinition> {
        self.actions.get(&field_number)
    }

    /// Add or update an action definition
    pub fn add_action(&mut self, field_number: u32, action: ActionDefinition) {
        self.actions.insert(field_number, action);
    }
}

/// Definition of a single action type
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ActionDefinition {
    /// Internal action name (e.g., "ActionTokenFactoryCreate")
    pub name: String,
    /// Human-readable display name (e.g., "Create Token")
    pub display_name: String,
    /// Description of what this action does
    pub description: String,
    /// Whether this action requires a signature (has randomizer)
    pub requires_signature: bool,
    /// Fields to extract and display
    pub fields: Vec<FieldDefinition>,
    /// Display template (optional, for custom formatting)
    pub template: Option<String>,
}

impl ActionDefinition {
    pub fn new(name: &str, display_name: &str) -> Self {
        Self {
            name: name.to_string(),
            display_name: display_name.to_string(),
            description: String::new(),
            requires_signature: false,
            fields: Vec::new(),
            template: None,
        }
    }

    pub fn with_description(mut self, desc: &str) -> Self {
        self.description = desc.to_string();
        self
    }

    pub fn with_signature(mut self) -> Self {
        self.requires_signature = true;
        self
    }

    pub fn with_field(mut self, field: FieldDefinition) -> Self {
        self.fields.push(field);
        self
    }
}

/// Definition of a field within an action
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FieldDefinition {
    /// Protobuf field path (e.g., "metadata.symbol" or "initial_supply")
    pub path: String,
    /// Human-readable label (e.g., "Symbol")
    pub label: String,
    /// Field type for parsing/display
    pub field_type: FieldType,
    /// Whether to show this field (some fields are for internal use)
    pub visible: bool,
    /// Display priority (lower = shown first)
    pub priority: u32,
}

impl FieldDefinition {
    pub fn new(path: &str, label: &str, field_type: FieldType) -> Self {
        Self {
            path: path.to_string(),
            label: label.to_string(),
            field_type,
            visible: true,
            priority: 100,
        }
    }

    pub fn hidden(mut self) -> Self {
        self.visible = false;
        self
    }

    pub fn with_priority(mut self, priority: u32) -> Self {
        self.priority = priority;
        self
    }
}

/// Type of a field for parsing and display
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum FieldType {
    /// UTF-8 string
    String,
    /// Boolean
    Bool,
    /// Unsigned 32-bit integer
    U32,
    /// Unsigned 64-bit integer
    U64,
    /// Amount (lo/hi u64 pair, displayed with decimals)
    Amount { decimals: u8 },
    /// Asset ID (32 bytes, displayed as bech32)
    AssetId,
    /// Address (80 bytes, displayed as bech32)
    Address,
    /// Identity key (32 bytes, for validators)
    IdentityKey,
    /// Bytes (displayed as hex)
    Bytes,
    /// Nested message - reference to type definition
    Message { type_name: String },
    /// Enum variant
    Enum { variants: Vec<(u32, String)> },
}

/// Common type definitions
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TypeDefinition {
    /// Type name
    pub name: String,
    /// Fields in this type
    pub fields: Vec<FieldDefinition>,
}

/// Create default type definitions for common Penumbra types
fn default_types() -> HashMap<String, TypeDefinition> {
    let mut types = HashMap::new();

    // Amount type
    types.insert(
        "Amount".to_string(),
        TypeDefinition {
            name: "Amount".to_string(),
            fields: vec![
                FieldDefinition::new("lo", "Low", FieldType::U64),
                FieldDefinition::new("hi", "High", FieldType::U64),
            ],
        },
    );

    // TokenFactoryId type
    types.insert(
        "TokenFactoryId".to_string(),
        TypeDefinition {
            name: "TokenFactoryId".to_string(),
            fields: vec![FieldDefinition::new("inner", "ID", FieldType::Bytes)],
        },
    );

    // Metadata type (simplified)
    types.insert(
        "Metadata".to_string(),
        TypeDefinition {
            name: "Metadata".to_string(),
            fields: vec![
                FieldDefinition::new("name", "Name", FieldType::String),
                FieldDefinition::new("symbol", "Symbol", FieldType::String),
                FieldDefinition::new("base", "Base Denom", FieldType::String),
                FieldDefinition::new("description", "Description", FieldType::String),
            ],
        },
    );

    types
}

/// Create the default schema with all known Penumbra actions
pub fn default_penumbra_schema() -> PenumbraActionSchema {
    let mut schema = PenumbraActionSchema::new(
        "penumbra-1".to_string(),
        "2.1.0".to_string(),
    );

    // Field 1: Spend
    schema.add_action(
        1,
        ActionDefinition::new("ActionSpend", "Spend")
            .with_description("Spend a note from your wallet")
            .with_signature()
            .with_field(FieldDefinition::new("note.value.amount", "Amount", FieldType::Amount { decimals: 6 }))
            .with_field(FieldDefinition::new("note.value.asset_id", "Asset", FieldType::AssetId)),
    );

    // Field 2: Output
    schema.add_action(
        2,
        ActionDefinition::new("ActionOutput", "Output")
            .with_description("Create an output note")
            .with_field(FieldDefinition::new("value.amount", "Amount", FieldType::Amount { decimals: 6 }))
            .with_field(FieldDefinition::new("value.asset_id", "Asset", FieldType::AssetId))
            .with_field(FieldDefinition::new("dest_address", "To", FieldType::Address)),
    );

    // Field 3: Swap
    schema.add_action(
        3,
        ActionDefinition::new("ActionSwap", "Swap")
            .with_description("Swap assets via DEX")
            .with_field(FieldDefinition::new("swap_plaintext.delta_1_i", "Input Amount", FieldType::Amount { decimals: 6 }))
            .with_field(FieldDefinition::new("swap_plaintext.trading_pair.asset_1", "From Asset", FieldType::AssetId))
            .with_field(FieldDefinition::new("swap_plaintext.trading_pair.asset_2", "To Asset", FieldType::AssetId)),
    );

    // Field 4: SwapClaim
    schema.add_action(
        4,
        ActionDefinition::new("ActionSwapClaim", "Claim Swap")
            .with_description("Claim outputs from a completed swap"),
    );

    // Field 16: Delegate
    schema.add_action(
        16,
        ActionDefinition::new("ActionDelegate", "Delegate")
            .with_description("Delegate stake to a validator")
            .with_field(FieldDefinition::new("unbonded_amount", "Amount", FieldType::Amount { decimals: 6 }))
            .with_field(FieldDefinition::new("validator_identity", "Validator", FieldType::IdentityKey)),
    );

    // Field 17: Undelegate
    schema.add_action(
        17,
        ActionDefinition::new("ActionUndelegate", "Undelegate")
            .with_description("Undelegate stake from a validator")
            .with_field(FieldDefinition::new("delegation_amount", "Amount", FieldType::Amount { decimals: 6 }))
            .with_field(FieldDefinition::new("validator_identity", "Validator", FieldType::IdentityKey)),
    );

    // Field 18: UndelegateClaim
    schema.add_action(
        18,
        ActionDefinition::new("ActionUndelegateClaim", "Claim Undelegation")
            .with_description("Claim unbonded stake"),
    );

    // Field 20: DelegatorVote
    schema.add_action(
        20,
        ActionDefinition::new("ActionDelegatorVote", "Vote")
            .with_description("Vote on a governance proposal")
            .with_signature()
            .with_field(FieldDefinition::new("proposal", "Proposal", FieldType::U64))
            .with_field(FieldDefinition::new("vote.vote", "Vote", FieldType::Enum {
                variants: vec![
                    (0, "Abstain".to_string()),
                    (1, "Yes".to_string()),
                    (2, "No".to_string()),
                ],
            })),
    );

    // Field 30: PositionOpen
    schema.add_action(
        30,
        ActionDefinition::new("ActionPositionOpen", "Open LP Position")
            .with_description("Open a liquidity position"),
    );

    // Field 31: PositionClose
    schema.add_action(
        31,
        ActionDefinition::new("ActionPositionClose", "Close LP Position")
            .with_description("Close a liquidity position"),
    );

    // Field 32: PositionWithdraw
    schema.add_action(
        32,
        ActionDefinition::new("ActionPositionWithdraw", "Withdraw LP")
            .with_description("Withdraw from a closed position"),
    );

    // Field 53: DutchAuctionSchedule
    schema.add_action(
        53,
        ActionDefinition::new("ActionDutchAuctionSchedule", "Schedule Auction")
            .with_description("Schedule a Dutch auction")
            .with_field(FieldDefinition::new("description.input.amount", "Input Amount", FieldType::Amount { decimals: 6 }))
            .with_field(FieldDefinition::new("description.input.asset_id", "Selling", FieldType::AssetId))
            .with_field(FieldDefinition::new("description.output_id", "For Asset", FieldType::AssetId))
            .with_field(FieldDefinition::new("description.max_output", "Min Price", FieldType::Amount { decimals: 6 }))
            .with_field(FieldDefinition::new("description.min_output", "Max Price", FieldType::Amount { decimals: 6 })),
    );

    // Field 54: DutchAuctionEnd
    schema.add_action(
        54,
        ActionDefinition::new("ActionDutchAuctionEnd", "End Auction")
            .with_description("End a Dutch auction early"),
    );

    // Field 55: DutchAuctionWithdraw
    schema.add_action(
        55,
        ActionDefinition::new("ActionDutchAuctionWithdraw", "Withdraw Auction")
            .with_description("Withdraw from ended auction"),
    );

    // Field 61: TokenFactoryCreate (NEW!)
    schema.add_action(
        61,
        ActionDefinition::new("ActionTokenFactoryCreate", "Create Token")
            .with_description("Create a new token via Token Factory")
            .with_field(FieldDefinition::new("nonce.inner", "Token ID", FieldType::Bytes).with_priority(10))
            .with_field(FieldDefinition::new("metadata.name", "Name", FieldType::String).with_priority(1))
            .with_field(FieldDefinition::new("metadata.symbol", "Symbol", FieldType::String).with_priority(2))
            .with_field(FieldDefinition::new("metadata.description", "Description", FieldType::String).with_priority(5))
            .with_field(FieldDefinition::new("initial_supply", "Initial Supply", FieldType::Amount { decimals: 6 }).with_priority(3))
            .with_field(FieldDefinition::new("enable_mint", "Minting Enabled", FieldType::Bool).with_priority(4)),
    );

    // Field 62: TokenFactoryMint (NEW!)
    schema.add_action(
        62,
        ActionDefinition::new("ActionTokenFactoryMint", "Mint Tokens")
            .with_description("Mint additional tokens using mint capability")
            .with_field(FieldDefinition::new("token_id.inner", "Token ID", FieldType::Bytes).with_priority(1))
            .with_field(FieldDefinition::new("current_seq", "Sequence", FieldType::U64).with_priority(3))
            .with_field(FieldDefinition::new("amount", "Amount to Mint", FieldType::Amount { decimals: 6 }).with_priority(2)),
    );

    // Field 63: LiquidityTournamentVote
    schema.add_action(
        63,
        ActionDefinition::new("ActionLiquidityTournamentVote", "LQT Vote")
            .with_description("Vote in liquidity tournament")
            .with_signature()
            .with_field(FieldDefinition::new("body.incentivized_asset", "Vote For", FieldType::AssetId)),
    );

    // IBC actions (field 17 for Ics20Withdrawal in some versions)
    schema.add_action(
        200,
        ActionDefinition::new("ActionIcs20Withdrawal", "IBC Transfer Out")
            .with_description("Transfer assets via IBC")
            .with_field(FieldDefinition::new("amount", "Amount", FieldType::Amount { decimals: 6 }))
            .with_field(FieldDefinition::new("denom", "Asset", FieldType::String))
            .with_field(FieldDefinition::new("destination_chain_address", "To", FieldType::String)),
    );

    schema
}

/// Parsed field value for display
#[derive(Debug, Clone)]
pub enum ParsedValue {
    String(String),
    Bool(bool),
    U32(u32),
    U64(u64),
    Amount { raw: u128, decimals: u8, formatted: String },
    Address(String),
    AssetId(String),
    Bytes(Vec<u8>),
    Unknown,
}

impl ParsedValue {
    /// Format for display
    pub fn display(&self) -> String {
        match self {
            ParsedValue::String(s) => s.clone(),
            ParsedValue::Bool(b) => if *b { "Yes".to_string() } else { "No".to_string() },
            ParsedValue::U32(n) => n.to_string(),
            ParsedValue::U64(n) => n.to_string(),
            ParsedValue::Amount { formatted, .. } => formatted.clone(),
            ParsedValue::Address(a) => truncate_middle(a, 20),
            ParsedValue::AssetId(a) => truncate_middle(a, 16),
            ParsedValue::Bytes(b) => {
                let hex: String = b.iter().map(|b| format!("{:02x}", b)).collect();
                truncate_middle(&hex, 16)
            }
            ParsedValue::Unknown => "???".to_string(),
        }
    }
}

/// Truncate string in the middle for display
fn truncate_middle(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        let half = (max_len - 3) / 2;
        format!("{}...{}", &s[..half], &s[s.len() - half..])
    }
}

/// Parsed action ready for display
#[derive(Debug, Clone)]
pub struct ParsedAction {
    /// Action display name
    pub name: String,
    /// Action description
    pub description: String,
    /// Parsed fields
    pub fields: Vec<(String, ParsedValue)>,
    /// Whether this action was recognized
    pub recognized: bool,
}

impl ParsedAction {
    /// Create an unrecognized action
    pub fn unrecognized(field_number: u32) -> Self {
        Self {
            name: format!("Unknown Action ({})", field_number),
            description: "This action type is not in the schema".to_string(),
            fields: Vec::new(),
            recognized: false,
        }
    }
}

// =============================================================================
// Asset Registry Types
// =============================================================================

/// A single asset entry in the registry
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AssetEntry {
    /// Asset ID (32 bytes)
    pub asset_id: [u8; 32],
    /// Base denomination (e.g., "upenumbra")
    pub denom: String,
    /// Display symbol (e.g., "UM")
    pub symbol: String,
    /// Decimal places
    pub decimals: u8,
    /// Human-readable name
    pub display_name: String,
}

impl AssetEntry {
    /// Get asset ID as hex string
    pub fn asset_id_hex(&self) -> String {
        self.asset_id.iter().map(|b| format!("{:02x}", b)).collect()
    }
}

/// Compact registry digest - merkle root of all assets
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RegistryDigest {
    /// Version of the digest format
    pub version: u32,
    /// Chain identifier
    pub chain_id: String,
    /// Merkle root of asset entries tree
    pub asset_tree_root: [u8; 32],
    /// Number of assets in the registry
    pub asset_count: u32,
    /// Timestamp of registry snapshot
    pub timestamp: u64,
}

impl RegistryDigest {
    /// Get merkle root as hex string (first 16 bytes for display)
    pub fn root_hex(&self) -> String {
        self.asset_tree_root[..16].iter().map(|b| format!("{:02x}", b)).collect()
    }
}

/// Merkleized schema digest (compact 32-byte root)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SchemaDigest {
    /// Version of the digest format
    pub version: u32,
    /// Chain identifier
    pub chain_id: String,
    /// Protocol version (e.g., "2.1.0")
    pub protocol_version: String,
    /// Merkle root of action definitions tree
    pub action_tree_root: [u8; 32],
    /// Number of actions in the tree
    pub action_count: u32,
}

impl SchemaDigest {
    /// Get merkle root as hex string
    pub fn root_hex(&self) -> String {
        self.action_tree_root.iter().map(|b| format!("{:02x}", b)).collect()
    }
}

// =============================================================================
// QR Payload Decoding
// =============================================================================

/// Decode a registry digest from binary QR payload
///
/// Format:
/// - 3 bytes: prelude (0x53, crypto_type, 0x14)
/// - 4 bytes: version (LE)
/// - 1 byte: chain_id length
/// - N bytes: chain_id
/// - 32 bytes: merkle root hash
/// - 4 bytes: asset count (LE)
/// - 8 bytes: timestamp (LE)
pub fn decode_registry_qr(data: &[u8]) -> Result<RegistryDigest, String> {
    // Minimum size: prelude(3) + version(4) + chain_len(1) + chain(1) + hash(32) + count(4) + timestamp(8) = 53
    if data.len() < 53 {
        return Err("Registry payload too short".to_string());
    }

    if data[0] != 0x53 || data[2] != PENUMBRA_REGISTRY_QR_TYPE {
        return Err("Invalid prelude for registry digest".to_string());
    }

    let version = u32::from_le_bytes([data[3], data[4], data[5], data[6]]);

    let chain_len = data[7] as usize;
    if data.len() < 8 + chain_len + 32 + 4 + 8 {
        return Err("Registry payload too short for chain_id".to_string());
    }

    let chain_id = String::from_utf8(data[8..8 + chain_len].to_vec())
        .map_err(|e| format!("Invalid chain_id: {}", e))?;

    let hash_start = 8 + chain_len;
    let mut asset_tree_root = [0u8; 32];
    asset_tree_root.copy_from_slice(&data[hash_start..hash_start + 32]);

    let count_start = hash_start + 32;
    let asset_count = u32::from_le_bytes([
        data[count_start],
        data[count_start + 1],
        data[count_start + 2],
        data[count_start + 3],
    ]);

    let ts_start = count_start + 4;
    let timestamp = u64::from_le_bytes([
        data[ts_start],
        data[ts_start + 1],
        data[ts_start + 2],
        data[ts_start + 3],
        data[ts_start + 4],
        data[ts_start + 5],
        data[ts_start + 6],
        data[ts_start + 7],
    ]);

    Ok(RegistryDigest {
        version,
        chain_id,
        asset_tree_root,
        asset_count,
        timestamp,
    })
}

/// Decode a schema digest from binary QR payload
///
/// Format:
/// - 3 bytes: prelude (0x53, crypto_type, 0x13)
/// - 4 bytes: version (LE)
/// - 1 byte: chain_id length
/// - N bytes: chain_id
/// - 1 byte: protocol_version length
/// - M bytes: protocol_version
/// - 32 bytes: merkle root hash
/// - 4 bytes: action count (LE)
pub fn decode_schema_digest_qr(data: &[u8]) -> Result<SchemaDigest, String> {
    // Minimum size: prelude(3) + version(4) + chain_len(1) + chain(1) + proto_len(1) + proto(1) + hash(32) + count(4) = 47
    if data.len() < 47 {
        return Err("Schema digest payload too short".to_string());
    }

    if data[0] != 0x53 || data[2] != PENUMBRA_MERKLE_SCHEMA_QR_TYPE {
        return Err("Invalid prelude for schema digest".to_string());
    }

    let version = u32::from_le_bytes([data[3], data[4], data[5], data[6]]);

    let chain_len = data[7] as usize;
    let chain_id = String::from_utf8(data[8..8 + chain_len].to_vec())
        .map_err(|e| format!("Invalid chain_id: {}", e))?;

    let proto_len_idx = 8 + chain_len;
    let proto_len = data[proto_len_idx] as usize;
    let protocol_version = String::from_utf8(data[proto_len_idx + 1..proto_len_idx + 1 + proto_len].to_vec())
        .map_err(|e| format!("Invalid protocol_version: {}", e))?;

    let hash_start = proto_len_idx + 1 + proto_len;
    if data.len() < hash_start + 32 + 4 {
        return Err("Schema digest payload too short for hash and count".to_string());
    }

    let mut action_tree_root = [0u8; 32];
    action_tree_root.copy_from_slice(&data[hash_start..hash_start + 32]);

    let count_start = hash_start + 32;
    let action_count = u32::from_le_bytes([
        data[count_start],
        data[count_start + 1],
        data[count_start + 2],
        data[count_start + 3],
    ]);

    Ok(SchemaDigest {
        version,
        chain_id,
        protocol_version,
        action_tree_root,
        action_count,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_schema_has_token_factory() {
        let schema = default_penumbra_schema();

        // Check TokenFactoryCreate
        let create = schema.get_action(61).expect("Should have field 61");
        assert_eq!(create.name, "ActionTokenFactoryCreate");
        assert_eq!(create.display_name, "Create Token");
        assert!(create.fields.iter().any(|f| f.path == "metadata.symbol"));

        // Check TokenFactoryMint
        let mint = schema.get_action(62).expect("Should have field 62");
        assert_eq!(mint.name, "ActionTokenFactoryMint");
        assert_eq!(mint.display_name, "Mint Tokens");
    }

    #[test]
    fn test_schema_serialization() {
        let schema = default_penumbra_schema();
        let json = serde_json::to_string(&schema).expect("Should serialize");
        let restored: PenumbraActionSchema = serde_json::from_str(&json).expect("Should deserialize");
        assert_eq!(schema, restored);
    }

    #[test]
    fn test_decode_registry_qr() {
        // Sample registry payload from pcli
        let hex = "530314010000000a70656e756d6272612d315cee5d323ffac30a78715e63dacc6f3882da1e0f5b42756d7a7fd45424075d38e40000004f16396900000000";
        let data: Vec<u8> = (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect();

        let digest = decode_registry_qr(&data).expect("Should decode");
        assert_eq!(digest.version, 1);
        assert_eq!(digest.chain_id, "penumbra-1");
        assert_eq!(digest.asset_count, 228);
    }
}
