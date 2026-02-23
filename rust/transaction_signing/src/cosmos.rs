//! cosmos transaction signing
//!
//! parses amino JSON sign requests from QR codes and signs with secp256k1 ECDSA.
//! cosmos amino signing: sign SHA256(sign_doc_bytes) with secp256k1.
//!
//! NOTE: we cannot use sp_core::ecdsa::Pair::sign() because it uses blake2b-256
//! as prehash (Substrate convention). Cosmos requires SHA256.

use crate::{Error, Result};

/// QR prelude bytes for cosmos sign request: [0x53, 0x05, 0x10]
const COSMOS_PRELUDE: [u8; 3] = [0x53, 0x05, 0x10];

/// parsed cosmos sign request from QR
pub struct CosmosSignRequest {
    /// BIP44 account index
    pub account_index: u32,
    /// chain name (e.g. "noble", "osmosis")
    pub chain_name: String,
    /// amino JSON sign doc bytes (UTF-8)
    pub sign_doc_bytes: Vec<u8>,
}

/// display info extracted from amino JSON sign doc
pub struct CosmosSignDocDisplay {
    /// chain_id from sign doc
    pub chain_id: String,
    /// message type (e.g. "Send", "IBC Transfer")
    pub msg_type: String,
    /// recipient address
    pub recipient: String,
    /// amount string (e.g. "1000000 uusdc")
    pub amount: String,
    /// fee string
    pub fee: String,
    /// memo
    pub memo: String,
}

impl CosmosSignRequest {
    /// parse a cosmos sign request from QR hex data
    ///
    /// format:
    /// [0x53][0x05][0x10]       3B  prelude
    /// [account_index: 4 LE]    4B
    /// [chain_name_len: 1]      1B
    /// [chain_name: N]          NB
    /// [sign_doc_len: 4 LE]     4B
    /// [sign_doc_bytes: N]      NB  canonical amino JSON
    pub fn from_qr_hex(hex: &str) -> Result<Self> {
        let bytes = hex::decode(hex)
            .map_err(|e| Error::Other(anyhow::anyhow!("invalid hex: {e}")))?;

        if bytes.len() < 12 {
            return Err(Error::Other(anyhow::anyhow!("QR data too short")));
        }

        // check prelude
        if bytes[0..3] != COSMOS_PRELUDE {
            return Err(Error::Other(anyhow::anyhow!(
                "invalid cosmos QR prelude: expected 530510, got {:02x}{:02x}{:02x}",
                bytes[0], bytes[1], bytes[2]
            )));
        }

        let mut offset = 3;

        // account index (4 bytes LE)
        let account_index = u32::from_le_bytes(
            bytes[offset..offset + 4].try_into()
                .map_err(|_| Error::Other(anyhow::anyhow!("failed to read account index")))?
        );
        offset += 4;

        // chain name (length-prefixed, 1 byte)
        let chain_name_len = bytes[offset] as usize;
        offset += 1;

        if offset + chain_name_len > bytes.len() {
            return Err(Error::Other(anyhow::anyhow!("chain name extends past end of data")));
        }

        let chain_name = String::from_utf8(bytes[offset..offset + chain_name_len].to_vec())
            .map_err(|e| Error::Other(anyhow::anyhow!("invalid chain name UTF-8: {e}")))?;
        offset += chain_name_len;

        // sign doc bytes (length-prefixed, 4 bytes LE)
        if offset + 4 > bytes.len() {
            return Err(Error::Other(anyhow::anyhow!("missing sign doc length")));
        }
        let sign_doc_len = u32::from_le_bytes(
            bytes[offset..offset + 4].try_into()
                .map_err(|_| Error::Other(anyhow::anyhow!("failed to read sign doc length")))?
        ) as usize;
        offset += 4;

        if offset + sign_doc_len > bytes.len() {
            return Err(Error::Other(anyhow::anyhow!(
                "sign doc extends past end of data (need {}, have {})",
                offset + sign_doc_len, bytes.len()
            )));
        }

        let sign_doc_bytes = bytes[offset..offset + sign_doc_len].to_vec();

        Ok(CosmosSignRequest {
            account_index,
            chain_name,
            sign_doc_bytes,
        })
    }
}

impl CosmosSignDocDisplay {
    /// parse display info from amino JSON sign doc bytes
    pub fn from_json(bytes: &[u8]) -> Result<Self> {
        let json: serde_json::Value = serde_json::from_slice(bytes)
            .map_err(|e| Error::Other(anyhow::anyhow!("invalid sign doc JSON: {e}")))?;

        let chain_id = json["chain_id"].as_str().unwrap_or("").to_string();
        let memo = json["memo"].as_str().unwrap_or("").to_string();

        // parse fee
        let fee_amount = json["fee"]["amount"]
            .as_array()
            .and_then(|a| a.first())
            .map(|c| {
                let amt = c["amount"].as_str().unwrap_or("0");
                let denom = c["denom"].as_str().unwrap_or("");
                format!("{amt} {denom}")
            })
            .unwrap_or_else(|| "unknown".to_string());

        // parse first message
        let msg = json["msgs"]
            .as_array()
            .and_then(|a| a.first());

        let (msg_type, recipient, amount) = match msg {
            Some(m) => {
                let typ = m["type"].as_str().unwrap_or("");
                match typ {
                    "cosmos-sdk/MsgSend" => {
                        let to = m["value"]["to_address"].as_str().unwrap_or("").to_string();
                        let amt = m["value"]["amount"]
                            .as_array()
                            .and_then(|a| a.first())
                            .map(|c| {
                                let a = c["amount"].as_str().unwrap_or("0");
                                let d = c["denom"].as_str().unwrap_or("");
                                format!("{a} {d}")
                            })
                            .unwrap_or_else(|| "unknown".to_string());
                        ("Send".to_string(), to, amt)
                    }
                    "cosmos-sdk/MsgTransfer" => {
                        let to = m["value"]["receiver"].as_str().unwrap_or("").to_string();
                        let amt = m["value"]["token"]
                            .as_object()
                            .map(|t| {
                                let a = t["amount"].as_str().unwrap_or("0");
                                let d = t["denom"].as_str().unwrap_or("");
                                format!("{a} {d}")
                            })
                            .unwrap_or_else(|| "unknown".to_string());
                        ("IBC Transfer".to_string(), to, amt)
                    }
                    _ => (typ.to_string(), String::new(), String::new()),
                }
            }
            None => ("Unknown".to_string(), String::new(), String::new()),
        };

        Ok(CosmosSignDocDisplay {
            chain_id,
            msg_type,
            recipient,
            amount,
            fee: fee_amount,
            memo,
        })
    }
}

/// sign cosmos amino sign doc bytes with secp256k1 ECDSA
///
/// computes SHA256(sign_doc_bytes) then signs with the secret key.
/// returns 64-byte compact signature (r || s).
///
/// IMPORTANT: this does NOT use sp_core::ecdsa because that uses blake2b-256
/// as prehash. cosmos amino requires SHA256.
#[cfg(feature = "cosmos")]
pub fn sign_cosmos_amino(
    secret_key: &[u8; 32],
    sign_doc_bytes: &[u8],
) -> Result<[u8; 64]> {
    use secp256k1::{Message, Secp256k1, SecretKey};
    use sha2::{Digest, Sha256};

    let secp = Secp256k1::new();

    // SHA256 prehash (cosmos amino convention)
    let hash = Sha256::digest(sign_doc_bytes);

    let sk = SecretKey::from_slice(secret_key)
        .map_err(|e| Error::Other(anyhow::anyhow!("invalid secret key: {e}")))?;

    let message = Message::from_digest_slice(&hash)
        .map_err(|e| Error::Other(anyhow::anyhow!("invalid message hash: {e}")))?;

    let signature = secp.sign_ecdsa(&message, &sk);

    // compact serialization = 64 bytes (r || s)
    Ok(signature.serialize_compact())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_cosmos_sign_request() {
        // build a test QR payload
        let account_index: u32 = 0;
        let chain_name = b"noble";
        let sign_doc = br#"{"chain_id":"noble-1","memo":"","msgs":[],"fee":{"amount":[],"gas":"0"},"account_number":"0","sequence":"0"}"#;

        let mut payload = Vec::new();
        payload.extend_from_slice(&COSMOS_PRELUDE);
        payload.extend_from_slice(&account_index.to_le_bytes());
        payload.push(chain_name.len() as u8);
        payload.extend_from_slice(chain_name);
        payload.extend_from_slice(&(sign_doc.len() as u32).to_le_bytes());
        payload.extend_from_slice(sign_doc);

        let hex = hex::encode(&payload);
        let req = CosmosSignRequest::from_qr_hex(&hex).unwrap();

        assert_eq!(req.account_index, 0);
        assert_eq!(req.chain_name, "noble");
        assert_eq!(req.sign_doc_bytes, sign_doc.to_vec());
    }

    #[test]
    fn test_parse_sign_doc_display() {
        let sign_doc = br#"{"chain_id":"noble-1","memo":"test","msgs":[{"type":"cosmos-sdk/MsgSend","value":{"from_address":"noble1abc","to_address":"noble1xyz","amount":[{"denom":"uusdc","amount":"1000000"}]}}],"fee":{"amount":[{"denom":"uusdc","amount":"500"}],"gas":"100000"},"account_number":"42","sequence":"7"}"#;

        let display = CosmosSignDocDisplay::from_json(sign_doc).unwrap();

        assert_eq!(display.chain_id, "noble-1");
        assert_eq!(display.msg_type, "Send");
        assert_eq!(display.recipient, "noble1xyz");
        assert_eq!(display.amount, "1000000 uusdc");
        assert_eq!(display.fee, "500 uusdc");
        assert_eq!(display.memo, "test");
    }
}
