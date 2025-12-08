//! penumbra transaction parsing
//!
//! parses penumbra transaction plans from QR codes and prepares them for signing.
//!
//! QR format (from prax wallet):
//! ```text
//! [0x53][0x03][0x10][metadata][transaction_plan_bytes]
//!
//! metadata format:
//!   asset_count: u8
//!   for each asset:
//!     name_len: u8
//!     name: [u8; name_len]
//! ```

use definitions::helpers::unhex;
use definitions::navigation::{
    Card, PenumbraTransactionSummary, TransactionAction, TransactionCard, TransactionCardSet,
};

use crate::{Error, Result};

// re-export signing types for convenience
pub use transaction_signing::penumbra::{
    PenumbraAuthorizationData, SpendKeyBytes, sign_spend, sign_transaction,
    EffectHash, PENUMBRA_COIN_TYPE,
    // FVK types
    FullViewingKey, NullifierKey, WalletId, FvkExportData, QR_TYPE_FVK_EXPORT,
};

/// penumbra chain identifier in QR prelude (0x03)
pub const PENUMBRA_CRYPTO_TYPE: u8 = 0x03;

/// penumbra transaction type (0x10)
pub const PENUMBRA_TX_TYPE: u8 = 0x10;

/// parsed penumbra transaction plan
#[derive(Debug, Clone)]
pub struct PenumbraTransactionPlan {
    /// raw transaction plan bytes (protobuf encoded)
    pub plan_bytes: Vec<u8>,
    /// asset metadata from QR (name mappings)
    pub asset_metadata: Vec<String>,
    /// extracted spend randomizers for signing
    pub spend_randomizers: Vec<[u8; 32]>,
    /// extracted delegator vote randomizers
    pub delegator_vote_randomizers: Vec<[u8; 32]>,
    /// extracted lqt vote randomizers
    pub lqt_vote_randomizers: Vec<[u8; 32]>,
    /// chain id if extracted
    pub chain_id: Option<String>,
    /// expiry height if present
    pub expiry_height: Option<u64>,
    /// pre-computed effect hash from hot wallet (64 bytes)
    /// this is what gets signed - Zigner trusts pcli to compute it correctly
    pub effect_hash: Option<[u8; 64]>,
}

impl PenumbraTransactionPlan {
    /// get the number of actions requiring signatures
    pub fn signature_count(&self) -> usize {
        self.spend_randomizers.len()
            + self.delegator_vote_randomizers.len()
            + self.lqt_vote_randomizers.len()
    }
}

/// parse asset metadata from QR payload
fn parse_asset_metadata(data: &[u8]) -> Result<(Vec<String>, usize)> {
    if data.is_empty() {
        return Ok((Vec::new(), 0));
    }

    let asset_count = data[0] as usize;
    let mut offset = 1;
    let mut assets = Vec::with_capacity(asset_count);

    for _ in 0..asset_count {
        if offset >= data.len() {
            return Err(Error::PenumbraParseError(
                "unexpected end of asset metadata".to_string(),
            ));
        }
        let name_len = data[offset] as usize;
        offset += 1;

        if offset + name_len > data.len() {
            return Err(Error::PenumbraParseError(
                "asset name extends beyond data".to_string(),
            ));
        }
        let name = String::from_utf8_lossy(&data[offset..offset + name_len]).to_string();
        assets.push(name);
        offset += name_len;
    }

    Ok((assets, offset))
}

/// extract randomizers from protobuf-encoded transaction plan
///
/// this is a simplified parser that looks for spend/vote action fields
/// and extracts the 32-byte randomizers without full protobuf parsing.
///
/// protobuf field structure (approximate):
/// - field 1: actions (repeated)
///   - spend action has randomizer in a nested field
///   - delegator_vote action has randomizer in a nested field
fn extract_randomizers_simple(_plan_bytes: &[u8]) -> (Vec<[u8; 32]>, Vec<[u8; 32]>, Vec<[u8; 32]>) {
    // for now, return empty - full implementation needs protobuf parsing
    // the effect hash will be computed by the signing module
    // and randomizers will be passed from the hot wallet
    (Vec::new(), Vec::new(), Vec::new())
}

/// parse a penumbra transaction from QR payload
///
/// payload format (extended with signing data from pcli):
/// [0x53][0x03][0x10]             - prelude (3 bytes)
/// [metadata]                     - asset names
/// [plan_bytes_len:4 LE]         - length of plan bytes (NEW)
/// [plan_bytes]                  - raw protobuf plan
/// [effect_hash:64]              - computed effect hash (NEW)
/// [spend_count:2 LE]            - number of spend randomizers (NEW)
/// [spend_randomizers:32 each]   - randomizer for each spend (NEW)
/// [vote_count:2 LE]             - number of vote randomizers (NEW)
/// [vote_randomizers:32 each]    - randomizer for each vote (NEW)
pub fn parse_penumbra_transaction(data_hex: &str) -> Result<PenumbraTransactionPlan> {
    let data = unhex(data_hex)?;

    // verify prelude
    if data.len() < 3 {
        return Err(Error::TooShort);
    }
    if data[0] != 0x53 {
        return Err(Error::NotSubstrate(format!("{:02x}", data[0])));
    }
    if data[1] != PENUMBRA_CRYPTO_TYPE {
        return Err(Error::PenumbraParseError(format!(
            "expected crypto type 0x03, got 0x{:02x}",
            data[1]
        )));
    }
    if data[2] != PENUMBRA_TX_TYPE {
        return Err(Error::PenumbraParseError(format!(
            "expected tx type 0x10, got 0x{:02x}",
            data[2]
        )));
    }

    // parse asset metadata
    let (asset_metadata, metadata_len) = parse_asset_metadata(&data[3..])?;
    let mut offset = 3 + metadata_len;

    // check if this is the new format (has plan length prefix) or old format
    // new format: [plan_len:4][plan][effect_hash:64][randomizers...]
    // old format: [plan_bytes_to_end]

    if data.len() < offset + 4 {
        return Err(Error::PenumbraParseError(
            "no transaction plan data".to_string(),
        ));
    }

    // read plan length (4 bytes LE)
    let plan_len = u32::from_le_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ]) as usize;
    offset += 4;

    // validate plan length
    if offset + plan_len > data.len() {
        return Err(Error::PenumbraParseError(format!(
            "plan length {} exceeds data (offset={}, len={})",
            plan_len, offset, data.len()
        )));
    }

    let plan_bytes = data[offset..offset + plan_len].to_vec();
    offset += plan_len;

    // parse effect hash (64 bytes) if present
    let effect_hash = if offset + 64 <= data.len() {
        let mut hash = [0u8; 64];
        hash.copy_from_slice(&data[offset..offset + 64]);
        offset += 64;
        Some(hash)
    } else {
        None
    };

    // parse spend randomizers
    let mut spend_randomizers = Vec::new();
    if offset + 2 <= data.len() {
        let spend_count = u16::from_le_bytes([data[offset], data[offset + 1]]) as usize;
        offset += 2;

        for _ in 0..spend_count {
            if offset + 32 > data.len() {
                return Err(Error::PenumbraParseError(
                    "truncated spend randomizer".to_string(),
                ));
            }
            let mut r = [0u8; 32];
            r.copy_from_slice(&data[offset..offset + 32]);
            spend_randomizers.push(r);
            offset += 32;
        }
    }

    // parse vote randomizers
    let mut delegator_vote_randomizers = Vec::new();
    if offset + 2 <= data.len() {
        let vote_count = u16::from_le_bytes([data[offset], data[offset + 1]]) as usize;
        offset += 2;

        for _ in 0..vote_count {
            if offset + 32 > data.len() {
                return Err(Error::PenumbraParseError(
                    "truncated vote randomizer".to_string(),
                ));
            }
            let mut r = [0u8; 32];
            r.copy_from_slice(&data[offset..offset + 32]);
            delegator_vote_randomizers.push(r);
            offset += 32;
        }
    }

    Ok(PenumbraTransactionPlan {
        plan_bytes,
        asset_metadata,
        spend_randomizers,
        delegator_vote_randomizers,
        lqt_vote_randomizers: Vec::new(), // LQT votes not yet supported
        chain_id: None,
        expiry_height: None,
        effect_hash,
    })
}

/// create transaction cards for display
fn create_penumbra_cards(plan: &PenumbraTransactionPlan) -> TransactionCardSet {
    let mut method_cards = Vec::new();

    // format effect hash for display
    let effect_hash_display = plan.effect_hash
        .map(|h| format!("{}...", hex::encode(&h[..16])))
        .unwrap_or_else(|| "not provided".to_string());

    // add summary card
    method_cards.push(TransactionCard {
        index: 0,
        indent: 0,
        card: Card::PenumbraSummaryCard {
            f: PenumbraTransactionSummary {
                chain_id: plan.chain_id.clone().unwrap_or_else(|| "penumbra-1".to_string()),
                expiry_height: plan.expiry_height,
                fee: "unknown".to_string(), // would need full protobuf parsing
                fee_asset: "penumbra".to_string(),
                spend_count: plan.spend_randomizers.len() as u64,
                output_count: 0, // would need full protobuf parsing
                effect_hash: effect_hash_display.clone(),
            },
        },
    });

    // add info about raw plan size
    method_cards.push(TransactionCard {
        index: 1,
        indent: 0,
        card: Card::TextCard {
            f: format!("Transaction plan: {} bytes", plan.plan_bytes.len()),
        },
    });

    // add effect hash info
    if plan.effect_hash.is_some() {
        method_cards.push(TransactionCard {
            index: 2,
            indent: 0,
            card: Card::TextCard {
                f: format!("Effect hash (first 32 chars): {}", effect_hash_display),
            },
        });
    }

    // add signing info
    method_cards.push(TransactionCard {
        index: 3,
        indent: 0,
        card: Card::TextCard {
            f: format!(
                "Signatures required: {} spend, {} vote",
                plan.spend_randomizers.len(),
                plan.delegator_vote_randomizers.len()
            ),
        },
    });

    // add asset metadata if present
    if !plan.asset_metadata.is_empty() {
        method_cards.push(TransactionCard {
            index: 4,
            indent: 0,
            card: Card::TextCard {
                f: format!("Assets: {}", plan.asset_metadata.join(", ")),
            },
        });
    }

    TransactionCardSet {
        method: Some(method_cards),
        ..Default::default()
    }
}

/// process a penumbra transaction QR code
///
/// this is called from handle_scanner_input when tx type is "10"
pub fn process_penumbra_transaction(
    _database: &sled::Db,
    data_hex: &str,
) -> Result<TransactionAction> {
    // parse the transaction
    let plan = parse_penumbra_transaction(data_hex)?;

    // create display cards
    let content = create_penumbra_cards(&plan);

    // for now, return as Read action since we need more info to sign
    // (seed phrase, account index, etc.)
    // full signing flow will be implemented when wiring up to UI
    Ok(TransactionAction::Read {
        r: Box::new(content),
    })
}

/// penumbra-specific transaction data stored for signing
#[derive(Debug, Clone)]
pub struct PenumbraSigningData {
    /// the parsed transaction plan
    pub plan: PenumbraTransactionPlan,
    /// computed effect hash (64 bytes)
    pub effect_hash: [u8; 64],
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_asset_metadata() {
        // empty metadata
        let (assets, len) = parse_asset_metadata(&[0]).unwrap();
        assert!(assets.is_empty());
        assert_eq!(len, 1);

        // single asset
        let data = [1, 3, b'u', b'm', b'p']; // 1 asset, len 3, "ump"
        let (assets, len) = parse_asset_metadata(&data).unwrap();
        assert_eq!(assets.len(), 1);
        assert_eq!(assets[0], "ump");
        assert_eq!(len, 5);

        // two assets
        let data = [2, 3, b'u', b'm', b'p', 4, b't', b'e', b's', b't'];
        let (assets, len) = parse_asset_metadata(&data).unwrap();
        assert_eq!(assets.len(), 2);
        assert_eq!(assets[0], "ump");
        assert_eq!(assets[1], "test");
        assert_eq!(len, 10);
    }

    #[test]
    fn test_parse_penumbra_transaction_new_format() {
        // new format: prelude + metadata + plan_len + plan + effect_hash + randomizers
        let mut hex = String::new();

        // prelude
        hex.push_str("530310");

        // metadata: 1 asset "um"
        hex.push_str("01"); // 1 asset
        hex.push_str("02"); // len 2
        hex.push_str("756d"); // "um"

        // plan length (4 bytes LE) - 4 bytes of plan
        hex.push_str("04000000");

        // plan bytes
        hex.push_str("deadbeef");

        // effect hash (64 bytes)
        for _ in 0..64 {
            hex.push_str("ab");
        }

        // spend count (2 bytes LE) - 1 spend
        hex.push_str("0100");

        // spend randomizer (32 bytes)
        for _ in 0..32 {
            hex.push_str("cd");
        }

        // vote count (2 bytes LE) - 0 votes
        hex.push_str("0000");

        let result = parse_penumbra_transaction(&hex);
        assert!(result.is_ok(), "Parse failed: {:?}", result);

        let plan = result.unwrap();
        assert_eq!(plan.asset_metadata.len(), 1);
        assert_eq!(plan.asset_metadata[0], "um");
        assert_eq!(plan.plan_bytes, vec![0xde, 0xad, 0xbe, 0xef]);
        assert!(plan.effect_hash.is_some());
        assert_eq!(plan.effect_hash.unwrap(), [0xab; 64]);
        assert_eq!(plan.spend_randomizers.len(), 1);
        assert_eq!(plan.spend_randomizers[0], [0xcd; 32]);
        assert_eq!(plan.delegator_vote_randomizers.len(), 0);
    }

    #[test]
    fn test_parse_penumbra_transaction_minimal() {
        // minimal new format: prelude + empty metadata + tiny plan + no signing data
        let mut hex = String::new();

        // prelude
        hex.push_str("530310");

        // metadata: 0 assets
        hex.push_str("00");

        // plan length (4 bytes LE) - 1 byte of plan
        hex.push_str("01000000");

        // plan bytes
        hex.push_str("ff");

        let result = parse_penumbra_transaction(&hex);
        assert!(result.is_ok(), "Parse failed: {:?}", result);

        let plan = result.unwrap();
        assert!(plan.asset_metadata.is_empty());
        assert_eq!(plan.plan_bytes, vec![0xff]);
        assert!(plan.effect_hash.is_none()); // no effect hash in minimal
        assert!(plan.spend_randomizers.is_empty());
    }

    #[test]
    fn test_invalid_prelude() {
        // wrong first byte
        let result = parse_penumbra_transaction("5403100001000000ff");
        assert!(matches!(result, Err(Error::NotSubstrate(_))));

        // wrong crypto type
        let result = parse_penumbra_transaction("5301100001000000ff");
        assert!(matches!(result, Err(Error::PenumbraParseError(_))));

        // wrong tx type
        let result = parse_penumbra_transaction("5303110001000000ff");
        assert!(matches!(result, Err(Error::PenumbraParseError(_))));
    }
}
