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

/// maximum sign doc size (64 KiB). amino JSON for any reasonable transaction
/// is well under this. defense in depth against oversized payloads.
const MAX_SIGN_DOC_LEN: usize = 65536;

/// parsed cosmos sign request from QR
pub struct CosmosSignRequest {
    /// BIP44 account index
    pub account_index: u32,
    /// chain name (e.g. "noble", "osmosis")
    pub chain_name: String,
    /// amino JSON sign doc bytes (UTF-8)
    pub sign_doc_bytes: Vec<u8>,
}

/// a single parsed message from the amino sign doc
pub struct CosmosMsg {
    /// message type (e.g. "Send", "IBC Transfer", "Swap", "Contract Call")
    pub msg_type: String,
    /// target address (recipient, validator, contract, etc.)
    pub recipient: String,
    /// amount string (e.g. "1000000 uusdc")
    pub amount: String,
    /// extra detail the user must see (min output, pool id, raw contract msg, etc.)
    pub detail: String,
    /// true if this message cannot be fully verified by the wallet.
    /// contract calls and unknown types are inherently blind — the UI
    /// must warn the user prominently before signing.
    pub blind: bool,
}

/// display info extracted from amino JSON sign doc
pub struct CosmosSignDocDisplay {
    /// chain_id from sign doc
    pub chain_id: String,
    /// ALL messages in the sign doc — a cold wallet must never hide messages
    pub msgs: Vec<CosmosMsg>,
    /// fee string
    pub fee: String,
    /// memo
    pub memo: String,
}

impl CosmosSignRequest {
    /// parse a cosmos sign request from QR hex data
    ///
    /// format:
    /// ```text
    /// [0x53][0x05][0x10]       3B  prelude
    /// [account_index: 4 LE]    4B
    /// [chain_name_len: 1]      1B
    /// [chain_name: N]          NB
    /// [sign_doc_len: 4 LE]     4B
    /// [sign_doc_bytes: N]      NB  canonical amino JSON
    /// ```
    pub fn from_qr_hex(hex: &str) -> Result<Self> {
        let bytes =
            hex::decode(hex).map_err(|e| Error::Other(anyhow::anyhow!("invalid hex: {e}")))?;

        if bytes.len() < 12 {
            return Err(Error::Other(anyhow::anyhow!("QR data too short")));
        }

        // check prelude
        if bytes[0..3] != COSMOS_PRELUDE {
            return Err(Error::Other(anyhow::anyhow!(
                "invalid cosmos QR prelude: expected 530510, got {:02x}{:02x}{:02x}",
                bytes[0],
                bytes[1],
                bytes[2]
            )));
        }

        let mut offset = 3;

        // account index (4 bytes LE)
        let account_index = u32::from_le_bytes(
            bytes[offset..offset + 4]
                .try_into()
                .map_err(|_| Error::Other(anyhow::anyhow!("failed to read account index")))?,
        );
        offset += 4;

        // chain name (length-prefixed, 1 byte)
        let chain_name_len = bytes[offset] as usize;
        offset += 1;

        if offset + chain_name_len > bytes.len() {
            return Err(Error::Other(anyhow::anyhow!(
                "chain name extends past end of data"
            )));
        }

        let chain_name = String::from_utf8(bytes[offset..offset + chain_name_len].to_vec())
            .map_err(|e| Error::Other(anyhow::anyhow!("invalid chain name UTF-8: {e}")))?;
        offset += chain_name_len;

        // sign doc bytes (length-prefixed, 4 bytes LE)
        if offset + 4 > bytes.len() {
            return Err(Error::Other(anyhow::anyhow!("missing sign doc length")));
        }
        let sign_doc_len = u32::from_le_bytes(
            bytes[offset..offset + 4]
                .try_into()
                .map_err(|_| Error::Other(anyhow::anyhow!("failed to read sign doc length")))?,
        ) as usize;
        offset += 4;

        if sign_doc_len > MAX_SIGN_DOC_LEN {
            return Err(Error::Other(anyhow::anyhow!(
                "sign doc too large ({sign_doc_len} bytes, max {MAX_SIGN_DOC_LEN})"
            )));
        }

        if offset + sign_doc_len > bytes.len() {
            return Err(Error::Other(anyhow::anyhow!(
                "sign doc extends past end of data (need {}, have {})",
                offset + sign_doc_len,
                bytes.len()
            )));
        }

        let sign_doc_bytes = bytes[offset..offset + sign_doc_len].to_vec();
        offset += sign_doc_len;

        // reject trailing garbage — ambiguous payloads are a parsing attack vector
        if offset != bytes.len() {
            return Err(Error::Other(anyhow::anyhow!(
                "trailing data after sign doc ({} extra bytes)",
                bytes.len() - offset
            )));
        }

        Ok(CosmosSignRequest {
            account_index,
            chain_name,
            sign_doc_bytes,
        })
    }
}

// ============================================================================
// JSON field helpers — no allocations escape scope, no Box::leak
// ============================================================================

/// format a single coin from {"amount": "X", "denom": "Y"}
fn format_coin(c: &serde_json::Value) -> String {
    let a = c["amount"].as_str().unwrap_or("0");
    let d = c["denom"].as_str().unwrap_or("");
    format!("{a} {d}")
}

/// format the first coin from an array of coins
fn format_first_coin(arr: &serde_json::Value) -> String {
    arr.as_array()
        .and_then(|a| a.first())
        .map(format_coin)
        .unwrap_or_else(|| "unknown".to_string())
}

/// format coin from an object (not array) — used by delegate/undelegate/single-token fields
fn format_coin_obj(obj: &serde_json::Value) -> String {
    obj.as_object()
        .map(|o| {
            let a = o.get("amount").and_then(|v| v.as_str()).unwrap_or("0");
            let d = o.get("denom").and_then(|v| v.as_str()).unwrap_or("");
            format!("{a} {d}")
        })
        .unwrap_or_else(|| "unknown".to_string())
}

/// extract a JSON number or string as a display string
fn json_num_or_str(v: &serde_json::Value) -> String {
    if let Some(s) = v.as_str() {
        s.to_string()
    } else if let Some(n) = v.as_u64() {
        n.to_string()
    } else if let Some(n) = v.as_i64() {
        n.to_string()
    } else {
        "?".to_string()
    }
}

/// format swap routes: "pool 1 → uatom, pool 7 → uosmo"
fn format_routes(routes: &[serde_json::Value]) -> String {
    if routes.is_empty() {
        return String::new();
    }
    let parts: Vec<String> = routes
        .iter()
        .map(|r| {
            let id = json_num_or_str(&r["pool_id"]);
            let denom = r["token_out_denom"].as_str().unwrap_or("?");
            format!("pool {id} → {denom}")
        })
        .collect();
    parts.join(", ")
}

// ============================================================================
// message parsing
// ============================================================================

impl CosmosMsg {
    fn from_json(m: &serde_json::Value) -> Self {
        let typ = m["type"].as_str().unwrap_or("");
        let v = &m["value"];
        match typ {
            // ================================================================
            // standard cosmos-sdk
            // ================================================================
            "cosmos-sdk/MsgSend" => CosmosMsg {
                msg_type: "Send".to_string(),
                recipient: v["to_address"].as_str().unwrap_or("").to_string(),
                amount: format_first_coin(&v["amount"]),
                detail: String::new(),
                blind: false,
            },
            "cosmos-sdk/MsgTransfer" => CosmosMsg {
                msg_type: "IBC Transfer".to_string(),
                recipient: v["receiver"].as_str().unwrap_or("").to_string(),
                amount: format_coin_obj(&v["token"]),
                detail: {
                    let ch = v["source_channel"].as_str().unwrap_or("");
                    if ch.is_empty() {
                        String::new()
                    } else {
                        format!("channel: {ch}")
                    }
                },
                blind: false,
            },
            "cosmos-sdk/MsgDelegate" => CosmosMsg {
                msg_type: "Delegate".to_string(),
                recipient: v["validator_address"].as_str().unwrap_or("").to_string(),
                amount: format_coin_obj(&v["amount"]),
                detail: String::new(),
                blind: false,
            },
            "cosmos-sdk/MsgUndelegate" => CosmosMsg {
                msg_type: "Undelegate".to_string(),
                recipient: v["validator_address"].as_str().unwrap_or("").to_string(),
                amount: format_coin_obj(&v["amount"]),
                detail: String::new(),
                blind: false,
            },
            "cosmos-sdk/MsgBeginRedelegate" => CosmosMsg {
                msg_type: "Redelegate".to_string(),
                recipient: v["validator_dst_address"]
                    .as_str()
                    .unwrap_or("")
                    .to_string(),
                amount: format_coin_obj(&v["amount"]),
                detail: {
                    let src = v["validator_src_address"].as_str().unwrap_or("");
                    if src.is_empty() {
                        String::new()
                    } else {
                        format!("from: {src}")
                    }
                },
                blind: false,
            },
            "cosmos-sdk/MsgWithdrawDelegationReward" => CosmosMsg {
                msg_type: "Claim Rewards".to_string(),
                recipient: v["validator_address"].as_str().unwrap_or("").to_string(),
                amount: String::new(),
                detail: String::new(),
                blind: false,
            },
            "cosmos-sdk/MsgVote" => CosmosMsg {
                msg_type: "Vote".to_string(),
                recipient: String::new(),
                amount: String::new(),
                detail: format!(
                    "proposal {} — {}",
                    json_num_or_str(&v["proposal_id"]),
                    v["option"].as_str().unwrap_or("?")
                ),
                blind: false,
            },

            // ================================================================
            // osmosis GAMM (classic AMM pools)
            // ================================================================
            "osmosis/gamm/swap-exact-amount-in" => {
                let routes = v["routes"].as_array().map(|a| a.as_slice()).unwrap_or(&[]);
                CosmosMsg {
                    msg_type: "Swap".to_string(),
                    recipient: String::new(),
                    amount: format_coin_obj(&v["token_in"]),
                    detail: {
                        let min_out = v["token_out_min_amount"].as_str().unwrap_or("0");
                        let route_str = format_routes(routes);
                        if route_str.is_empty() {
                            format!("min output: {min_out}")
                        } else {
                            format!("min output: {min_out}, route: {route_str}")
                        }
                    },
                    blind: false,
                }
            }
            "osmosis/gamm/swap-exact-amount-out" => {
                let routes = v["routes"].as_array().map(|a| a.as_slice()).unwrap_or(&[]);
                CosmosMsg {
                    msg_type: "Swap (exact out)".to_string(),
                    recipient: String::new(),
                    amount: {
                        let max_in = v["token_in_max_amount"].as_str().unwrap_or("0");
                        format!("max input: {max_in}")
                    },
                    detail: {
                        let out = format_coin_obj(&v["token_out"]);
                        let route_str = format_routes(routes);
                        if route_str.is_empty() {
                            format!("output: {out}")
                        } else {
                            format!("output: {out}, route: {route_str}")
                        }
                    },
                    blind: false,
                }
            }
            "osmosis/gamm/join-pool" => CosmosMsg {
                msg_type: "Join Pool".to_string(),
                recipient: String::new(),
                amount: {
                    let tokens: Vec<String> = v["token_in_maxs"]
                        .as_array()
                        .map(|a| a.iter().map(format_coin).collect())
                        .unwrap_or_default();
                    tokens.join(", ")
                },
                detail: {
                    let pool_id = json_num_or_str(&v["pool_id"]);
                    let shares = v["share_out_amount"].as_str().unwrap_or("?");
                    format!("pool {pool_id}, min shares: {shares}")
                },
                blind: false,
            },
            "osmosis/gamm/exit-pool" => CosmosMsg {
                msg_type: "Exit Pool".to_string(),
                recipient: String::new(),
                amount: {
                    let shares = v["share_in_amount"].as_str().unwrap_or("?");
                    format!("{shares} shares")
                },
                detail: {
                    let pool_id = json_num_or_str(&v["pool_id"]);
                    let mins: Vec<String> = v["token_out_mins"]
                        .as_array()
                        .map(|a| a.iter().map(format_coin).collect())
                        .unwrap_or_default();
                    if mins.is_empty() {
                        format!("pool {pool_id}")
                    } else {
                        format!("pool {pool_id}, min out: {}", mins.join(", "))
                    }
                },
                blind: false,
            },

            // ================================================================
            // osmosis concentrated liquidity
            // ================================================================
            "osmosis/cl/create-position" => CosmosMsg {
                msg_type: "Create CL Position".to_string(),
                recipient: String::new(),
                amount: {
                    let t0 = format_coin_obj(&v["token_desired0"]);
                    let t1 = format_coin_obj(&v["token_desired1"]);
                    format!("{t0}, {t1}")
                },
                detail: {
                    let pool_id = json_num_or_str(&v["pool_id"]);
                    let lower = json_num_or_str(&v["lower_tick"]);
                    let upper = json_num_or_str(&v["upper_tick"]);
                    format!("pool {pool_id}, ticks [{lower}, {upper}]")
                },
                blind: false,
            },
            "osmosis/cl/withdraw-position" => CosmosMsg {
                msg_type: "Withdraw CL Position".to_string(),
                recipient: String::new(),
                amount: v["liquidity_amount"].as_str().unwrap_or("?").to_string(),
                detail: format!("position {}", json_num_or_str(&v["position_id"])),
                blind: false,
            },

            // ================================================================
            // cosmwasm contract calls — BLIND SIGNING REQUIRED
            //
            // the contract address determines what code runs. we cannot
            // verify what the contract does. show the contract addr (full,
            // never truncated) and the raw msg JSON. the UI must display
            // a prominent warning that this is a blind sign.
            // ================================================================
            "cosmwasm/wasm/MsgExecuteContract" | "wasm/MsgExecuteContract" => {
                let contract = v["contract"].as_str().unwrap_or("").to_string();
                let funds: Vec<String> = v["funds"]
                    .as_array()
                    .or_else(|| v["sent_funds"].as_array())
                    .map(|a| a.iter().map(format_coin).collect())
                    .unwrap_or_default();
                // inner msg — show raw JSON so user sees exactly what's being signed.
                // we do NOT interpret the msg contents because we can't trust
                // that the contract does what the msg labels claim.
                let raw_msg = if v["msg"].is_object() || v["msg"].is_array() {
                    serde_json::to_string(&v["msg"]).unwrap_or_else(|_| "?".to_string())
                } else {
                    v["msg"].as_str().unwrap_or("?").to_string()
                };
                CosmosMsg {
                    msg_type: "Contract Call (BLIND)".to_string(),
                    recipient: contract,
                    amount: if funds.is_empty() {
                        "no funds attached".to_string()
                    } else {
                        funds.join(", ")
                    },
                    detail: raw_msg,
                    blind: true,
                }
            }

            // ================================================================
            // unknown msg type — BLIND SIGNING REQUIRED
            //
            // we don't recognize this message type. show the raw amino type
            // string so the user can at least see what it claims to be.
            // ================================================================
            _ => CosmosMsg {
                msg_type: if typ.is_empty() {
                    "(empty type)".to_string()
                } else {
                    typ.to_string()
                },
                recipient: String::new(),
                amount: String::new(),
                detail: serde_json::to_string(v).unwrap_or_default(),
                blind: true,
            },
        }
    }
}

impl CosmosSignDocDisplay {
    /// parse display info from amino JSON sign doc bytes.
    /// parses ALL messages — a cold wallet must never silently hide messages
    /// from the user, as that enables multi-message blind signing attacks.
    pub fn from_json(bytes: &[u8]) -> Result<Self> {
        let json: serde_json::Value = serde_json::from_slice(bytes)
            .map_err(|e| Error::Other(anyhow::anyhow!("invalid sign doc JSON: {e}")))?;

        let chain_id = json["chain_id"].as_str().unwrap_or("").to_string();
        let memo = json["memo"].as_str().unwrap_or("").to_string();

        // parse ALL fee coins — never hide fee components from user
        let fee_amount = json["fee"]["amount"]
            .as_array()
            .map(|coins| {
                let parts: Vec<String> = coins.iter().map(format_coin).collect();
                if parts.is_empty() {
                    "none".to_string()
                } else {
                    parts.join(" + ")
                }
            })
            .unwrap_or_else(|| "unknown".to_string());

        // parse ALL messages
        let msgs = match json["msgs"].as_array() {
            Some(arr) => arr.iter().map(CosmosMsg::from_json).collect(),
            None => vec![],
        };

        Ok(CosmosSignDocDisplay {
            chain_id,
            msgs,
            fee: fee_amount,
            memo,
        })
    }
}

/// Sign Cosmos Amino sign doc bytes with `secp256k1` ECDSA.
///
/// Computes `SHA256(sign_doc_bytes)` then signs with the secret key.
/// Returns 64-byte compact signature (r || s).
///
/// IMPORTANT: this does NOT use `sp_core::ecdsa` because that uses `blake2b-256`
/// as pre-hash. Cosmos Amino requires `SHA256`.
#[cfg(feature = "cosmos")]
pub fn sign_cosmos_amino(secret_key: &[u8; 32], sign_doc_bytes: &[u8]) -> Result<[u8; 64]> {
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
        assert_eq!(display.msgs.len(), 1);
        assert_eq!(display.msgs[0].msg_type, "Send");
        assert_eq!(display.msgs[0].recipient, "noble1xyz");
        assert_eq!(display.msgs[0].amount, "1000000 uusdc");
        assert!(!display.msgs[0].blind);
        assert_eq!(display.fee, "500 uusdc");
        assert_eq!(display.memo, "test");
    }

    #[test]
    fn test_multi_message_display() {
        let sign_doc = br#"{"chain_id":"osmosis-1","memo":"","msgs":[{"type":"cosmos-sdk/MsgSend","value":{"from_address":"osmo1abc","to_address":"osmo1xyz","amount":[{"denom":"uosmo","amount":"100"}]}},{"type":"cosmos-sdk/MsgTransfer","value":{"sender":"osmo1abc","receiver":"noble1evil","token":{"denom":"uusdc","amount":"9999999"},"source_channel":"channel-0","source_port":"transfer"}}],"fee":{"amount":[{"denom":"uosmo","amount":"500"}],"gas":"200000"},"account_number":"1","sequence":"0"}"#;

        let display = CosmosSignDocDisplay::from_json(sign_doc).unwrap();

        assert_eq!(display.msgs.len(), 2, "must parse ALL messages");
        assert_eq!(display.msgs[0].msg_type, "Send");
        assert_eq!(display.msgs[0].amount, "100 uosmo");
        assert!(!display.msgs[0].blind);
        assert_eq!(display.msgs[1].msg_type, "IBC Transfer");
        assert_eq!(display.msgs[1].recipient, "noble1evil");
        assert_eq!(display.msgs[1].amount, "9999999 uusdc");
        assert!(display.msgs[1].detail.contains("channel-0"));
    }

    #[test]
    fn test_delegate_undelegate_display() {
        let sign_doc = br#"{"chain_id":"cosmoshub-4","memo":"","msgs":[{"type":"cosmos-sdk/MsgDelegate","value":{"delegator_address":"cosmos1abc","validator_address":"cosmosvaloper1xyz","amount":{"denom":"uatom","amount":"1000000"}}},{"type":"cosmos-sdk/MsgUndelegate","value":{"delegator_address":"cosmos1abc","validator_address":"cosmosvaloper1def","amount":{"denom":"uatom","amount":"500000"}}}],"fee":{"amount":[{"denom":"uatom","amount":"5000"}],"gas":"300000"},"account_number":"5","sequence":"3"}"#;

        let display = CosmosSignDocDisplay::from_json(sign_doc).unwrap();

        assert_eq!(display.msgs.len(), 2);
        assert_eq!(display.msgs[0].msg_type, "Delegate");
        assert_eq!(display.msgs[0].recipient, "cosmosvaloper1xyz");
        assert_eq!(display.msgs[0].amount, "1000000 uatom");
        assert_eq!(display.msgs[1].msg_type, "Undelegate");
        assert_eq!(display.msgs[1].recipient, "cosmosvaloper1def");
        assert_eq!(display.msgs[1].amount, "500000 uatom");
    }

    #[test]
    fn test_osmosis_swap() {
        let sign_doc = br#"{"chain_id":"osmosis-1","memo":"","msgs":[{"type":"osmosis/gamm/swap-exact-amount-in","value":{"sender":"osmo1abc","routes":[{"pool_id":"1","token_out_denom":"uusdc"}],"token_in":{"denom":"uosmo","amount":"5000000"},"token_out_min_amount":"4900000"}}],"fee":{"amount":[{"denom":"uosmo","amount":"2500"}],"gas":"250000"},"account_number":"1","sequence":"5"}"#;

        let display = CosmosSignDocDisplay::from_json(sign_doc).unwrap();

        assert_eq!(display.msgs.len(), 1);
        assert_eq!(display.msgs[0].msg_type, "Swap");
        assert_eq!(display.msgs[0].amount, "5000000 uosmo");
        assert!(display.msgs[0].detail.contains("min output: 4900000"));
        assert!(display.msgs[0].detail.contains("pool 1"));
        assert!(!display.msgs[0].blind);
    }

    #[test]
    fn test_osmosis_join_pool() {
        let sign_doc = br#"{"chain_id":"osmosis-1","memo":"","msgs":[{"type":"osmosis/gamm/join-pool","value":{"sender":"osmo1abc","pool_id":"1","share_out_amount":"100000","token_in_maxs":[{"denom":"uosmo","amount":"5000000"},{"denom":"uusdc","amount":"5000000"}]}}],"fee":{"amount":[{"denom":"uosmo","amount":"2500"}],"gas":"250000"},"account_number":"1","sequence":"6"}"#;

        let display = CosmosSignDocDisplay::from_json(sign_doc).unwrap();

        assert_eq!(display.msgs[0].msg_type, "Join Pool");
        assert!(display.msgs[0].amount.contains("uosmo"));
        assert!(display.msgs[0].amount.contains("uusdc"));
        assert!(display.msgs[0].detail.contains("pool 1"));
        assert!(!display.msgs[0].blind);
    }

    #[test]
    fn test_cosmwasm_contract_call_is_blind() {
        let sign_doc = br#"{"chain_id":"osmosis-1","memo":"","msgs":[{"type":"cosmwasm/wasm/MsgExecuteContract","value":{"sender":"osmo1abc","contract":"osmo1contractaddr","msg":{"swap":{"input_denom":"uosmo"}},"funds":[{"denom":"uosmo","amount":"1000000"}]}}],"fee":{"amount":[{"denom":"uosmo","amount":"2500"}],"gas":"300000"},"account_number":"1","sequence":"7"}"#;

        let display = CosmosSignDocDisplay::from_json(sign_doc).unwrap();

        assert_eq!(display.msgs[0].msg_type, "Contract Call (BLIND)");
        assert_eq!(display.msgs[0].recipient, "osmo1contractaddr");
        assert_eq!(display.msgs[0].amount, "1000000 uosmo");
        assert!(display.msgs[0].detail.contains("swap"));
        assert!(display.msgs[0].blind, "contract calls must be marked blind");
    }

    #[test]
    fn test_unknown_msg_type_is_blind() {
        let sign_doc = br#"{"chain_id":"osmosis-1","memo":"","msgs":[{"type":"some-module/MsgDoSomething","value":{"foo":"bar"}}],"fee":{"amount":[{"denom":"uosmo","amount":"500"}],"gas":"100000"},"account_number":"1","sequence":"0"}"#;

        let display = CosmosSignDocDisplay::from_json(sign_doc).unwrap();

        assert_eq!(display.msgs[0].msg_type, "some-module/MsgDoSomething");
        assert!(display.msgs[0].blind, "unknown types must be marked blind");
        assert!(
            display.msgs[0].detail.contains("bar"),
            "should show raw value JSON"
        );
    }
}
