//! Bitcoin key derivation using BIP-32/44/84/86
//!
//! This implements key derivation for Bitcoin with support for:
//! - BIP-44: Legacy addresses (P2PKH) - m/44'/0'/account'/change/index
//! - BIP-84: Native SegWit addresses (P2WPKH) - m/84'/0'/account'/change/index
//! - BIP-86: Taproot addresses (P2TR) - m/86'/0'/account'/change/index
//!
//! Mainnet uses coin type 0, testnet uses coin type 1.

use crate::error::{Error, Result};
use bitcoin::bip32::{DerivationPath, Xpriv, Xpub};
use bitcoin::ecdsa::Signature as EcdsaSignature;
use bitcoin::hashes::Hash;
use bitcoin::psbt::Psbt;
use bitcoin::secp256k1::PublicKey as Secp256k1PublicKey;
use bitcoin::secp256k1::{Keypair, Message, Secp256k1, SecretKey};
use bitcoin::sighash::{EcdsaSighashType, SighashCache, TapSighashType};
use bitcoin::taproot::Signature as TaprootSignature;
use bitcoin::{Address, CompressedPublicKey, Network, PublicKey, Transaction};
use zeroize::Zeroize;

/// BIP-44 purpose constants
pub const PURPOSE_LEGACY: u32 = 44; // P2PKH
pub const PURPOSE_SEGWIT: u32 = 84; // P2WPKH (native segwit)
pub const PURPOSE_TAPROOT: u32 = 86; // P2TR (taproot)

/// SLIP-0044 coin types
pub const COIN_TYPE_MAINNET: u32 = 0;
pub const COIN_TYPE_TESTNET: u32 = 1;

/// Sled tree name for storing Bitcoin addresses
const BITCOIN_ADDRS: &str = "bitcoin_addresses";

/// Store a Bitcoin address for a given public key hex
pub fn store_bitcoin_address(database: &sled::Db, pubkey_hex: &str, address: &str) -> Result<()> {
    let tree = database.open_tree(BITCOIN_ADDRS)?;
    tree.insert(pubkey_hex.as_bytes(), address.as_bytes())?;
    Ok(())
}

/// Retrieve a Bitcoin address for a given public key hex
pub fn get_bitcoin_address(database: &sled::Db, pubkey_hex: &str) -> Result<Option<String>> {
    let tree = database.open_tree(BITCOIN_ADDRS)?;
    match tree.get(pubkey_hex.as_bytes())? {
        Some(bytes) => {
            let address = String::from_utf8(bytes.to_vec())
                .map_err(|e| Error::Other(anyhow::anyhow!("Invalid UTF-8: {}", e)))?;
            Ok(Some(address))
        }
        None => Ok(None),
    }
}

/// Bitcoin key pair with secp256k1 keys
#[derive(Clone)]
pub struct BitcoinKeyPair {
    /// 32-byte secp256k1 secret key
    secret_key: [u8; 32],
    /// 33-byte compressed secp256k1 public key
    pub public_key: [u8; 33],
    /// Derivation path used
    pub derivation_path: String,
    /// Network (mainnet or testnet)
    pub network: Network,
    /// Purpose (44, 84, or 86)
    pub purpose: u32,
}

impl Drop for BitcoinKeyPair {
    fn drop(&mut self) {
        self.secret_key.zeroize();
    }
}

impl BitcoinKeyPair {
    /// Get secret key bytes (for signing)
    pub fn secret_key(&self) -> &[u8; 32] {
        &self.secret_key
    }
}

impl BitcoinKeyPair {
    /// Get the Bitcoin address for this key
    pub fn address(&self) -> Result<String> {
        let secp = Secp256k1::new();
        let secp_pubkey = Secp256k1PublicKey::from_slice(&self.public_key)
            .map_err(|e| Error::Other(anyhow::anyhow!("Invalid public key: {}", e)))?;

        let compressed = CompressedPublicKey(secp_pubkey);

        let address = match self.purpose {
            PURPOSE_LEGACY => {
                // P2PKH address
                Address::p2pkh(compressed, self.network)
            }
            PURPOSE_SEGWIT => {
                // P2WPKH address (native segwit)
                Address::p2wpkh(&compressed, self.network)
            }
            PURPOSE_TAPROOT => {
                // P2TR address (taproot)
                let (xonly, _parity) = secp_pubkey.x_only_public_key();
                Address::p2tr(&secp, xonly, None, self.network)
            }
            _ => {
                return Err(Error::Other(anyhow::anyhow!(
                    "Unknown purpose: {}",
                    self.purpose
                )))
            }
        };

        Ok(address.to_string())
    }

    /// Get the x-only public key (for taproot/schnorr)
    pub fn x_only_pubkey(&self) -> [u8; 32] {
        let secp_pubkey =
            Secp256k1PublicKey::from_slice(&self.public_key).expect("Valid public key");
        let (xonly, _parity) = secp_pubkey.x_only_public_key();
        xonly.serialize()
    }

    /// Sign a message hash using ECDSA (for legacy/segwit)
    pub fn sign_ecdsa(&self, message_hash: &[u8; 32]) -> Result<[u8; 64]> {
        use bitcoin::secp256k1::Message;

        let secp = Secp256k1::new();
        let secret = SecretKey::from_slice(&self.secret_key)
            .map_err(|e| Error::Other(anyhow::anyhow!("Invalid secret key: {}", e)))?;
        let msg = Message::from_digest_slice(message_hash)
            .map_err(|e| Error::Other(anyhow::anyhow!("Invalid message: {}", e)))?;

        let sig = secp.sign_ecdsa(&msg, &secret);
        let compact = sig.serialize_compact();
        Ok(compact)
    }

    /// Sign a message hash using Schnorr (BIP-340, for taproot)
    pub fn sign_schnorr(&self, message_hash: &[u8; 32]) -> Result<[u8; 64]> {
        use bitcoin::secp256k1::{Keypair, Message};

        let secp = Secp256k1::new();
        let secret = SecretKey::from_slice(&self.secret_key)
            .map_err(|e| Error::Other(anyhow::anyhow!("Invalid secret key: {}", e)))?;
        let keypair = Keypair::from_secret_key(&secp, &secret);
        let msg = Message::from_digest_slice(message_hash)
            .map_err(|e| Error::Other(anyhow::anyhow!("Invalid message: {}", e)))?;

        let sig = secp.sign_schnorr_no_aux_rand(&msg, &keypair);
        Ok(*sig.as_ref())
    }
}

/// Derive Bitcoin key from seed phrase
///
/// # Arguments
/// * `seed_phrase` - BIP39 mnemonic phrase
/// * `purpose` - BIP purpose (44 for legacy, 84 for segwit, 86 for taproot)
/// * `network` - Bitcoin network (mainnet or testnet)
/// * `account` - Account index (typically 0)
/// * `change` - Change index (0 for receive, 1 for change)
/// * `address_index` - Address index within the account
pub fn derive_bitcoin_key(
    seed_phrase: &str,
    purpose: u32,
    network: Network,
    account: u32,
    change: u32,
    address_index: u32,
) -> Result<BitcoinKeyPair> {
    use bip39::{Language, Mnemonic, Seed};

    // Parse mnemonic and generate seed
    let mnemonic = Mnemonic::from_phrase(seed_phrase, Language::English)
        .map_err(|e| Error::Other(anyhow::anyhow!("Invalid mnemonic: {}", e)))?;
    let seed = Seed::new(&mnemonic, ""); // No passphrase

    // Determine coin type based on network
    let coin_type = match network {
        Network::Bitcoin => COIN_TYPE_MAINNET,
        _ => COIN_TYPE_TESTNET, // Testnet, Testnet4, Signet, Regtest all use coin type 1
    };

    // Build derivation path
    let path_str = format!(
        "m/{}'/{}'/{}'/{}/{}",
        purpose, coin_type, account, change, address_index
    );
    let path: DerivationPath = path_str
        .parse()
        .map_err(|e| Error::Other(anyhow::anyhow!("Invalid derivation path: {}", e)))?;

    // Derive master key
    let secp = Secp256k1::new();
    let master = Xpriv::new_master(network, seed.as_bytes())
        .map_err(|e| Error::Other(anyhow::anyhow!("Master key derivation failed: {}", e)))?;

    // Derive child key
    let derived = master
        .derive_priv(&secp, &path)
        .map_err(|e| Error::Other(anyhow::anyhow!("Key derivation failed: {}", e)))?;

    // Extract keys
    let mut secret_key = [0u8; 32];
    secret_key.copy_from_slice(&derived.private_key.secret_bytes());

    let pubkey = derived.private_key.public_key(&secp);
    let mut public_key = [0u8; 33];
    public_key.copy_from_slice(&pubkey.serialize());

    Ok(BitcoinKeyPair {
        secret_key,
        public_key,
        derivation_path: path_str,
        network,
        purpose,
    })
}

/// Derive a Native SegWit (BIP-84) key
/// Path: m/84'/0'/account'/change/index
pub fn derive_segwit_key(
    seed_phrase: &str,
    mainnet: bool,
    account: u32,
    change: u32,
    index: u32,
) -> Result<BitcoinKeyPair> {
    let network = if mainnet {
        Network::Bitcoin
    } else {
        Network::Testnet
    };
    derive_bitcoin_key(seed_phrase, PURPOSE_SEGWIT, network, account, change, index)
}

/// Derive a Taproot (BIP-86) key
/// Path: m/86'/0'/account'/change/index
pub fn derive_taproot_key(
    seed_phrase: &str,
    mainnet: bool,
    account: u32,
    change: u32,
    index: u32,
) -> Result<BitcoinKeyPair> {
    let network = if mainnet {
        Network::Bitcoin
    } else {
        Network::Testnet
    };
    derive_bitcoin_key(
        seed_phrase,
        PURPOSE_TAPROOT,
        network,
        account,
        change,
        index,
    )
}

/// Parse Bitcoin derivation path
///
/// Supports:
/// - Full BIP path: m/84'/0'/0'/0/0
/// - Simplified: //bitcoin//0 (uses BIP-84 mainnet)
/// - With purpose: //bitcoin_taproot//0 (uses BIP-86)
pub fn parse_bitcoin_path(path: &str) -> Result<(u32, bool, u32, u32, u32)> {
    // Try parsing as full BIP path
    if path.starts_with("m/") {
        let parts: Vec<&str> = path.trim_start_matches("m/").split('/').collect();
        if parts.len() >= 5 {
            let purpose = parts[0]
                .trim_end_matches('\'')
                .parse::<u32>()
                .map_err(|_| Error::InvalidDerivation(path.to_string()))?;
            let coin = parts[1]
                .trim_end_matches('\'')
                .parse::<u32>()
                .map_err(|_| Error::InvalidDerivation(path.to_string()))?;
            let account = parts[2]
                .trim_end_matches('\'')
                .parse::<u32>()
                .map_err(|_| Error::InvalidDerivation(path.to_string()))?;
            let change = parts[3]
                .parse::<u32>()
                .map_err(|_| Error::InvalidDerivation(path.to_string()))?;
            let index = parts[4]
                .parse::<u32>()
                .map_err(|_| Error::InvalidDerivation(path.to_string()))?;

            let mainnet = coin == COIN_TYPE_MAINNET;
            return Ok((purpose, mainnet, account, change, index));
        }
    }

    // Simplified path parsing
    let path_lower = path.to_lowercase();
    let parts: Vec<&str> = path.split("//").filter(|s| !s.is_empty()).collect();

    // Extract account number
    let account = parts
        .iter()
        .filter_map(|p| p.parse::<u32>().ok())
        .next()
        .unwrap_or(0);

    // Determine purpose from path
    let purpose = if path_lower.contains("taproot") || path_lower.contains("tr") {
        PURPOSE_TAPROOT
    } else if path_lower.contains("legacy") || path_lower.contains("p2pkh") {
        PURPOSE_LEGACY
    } else {
        PURPOSE_SEGWIT // Default to native segwit
    };

    // Determine network
    let mainnet = !path_lower.contains("test");

    Ok((purpose, mainnet, account, 0, 0))
}

/// Export extended public key (xpub/ypub/zpub) for watch-only wallet
pub fn export_xpub(seed_phrase: &str, purpose: u32, mainnet: bool, account: u32) -> Result<String> {
    use bip39::{Language, Mnemonic, Seed};

    let mnemonic = Mnemonic::from_phrase(seed_phrase, Language::English)
        .map_err(|e| Error::Other(anyhow::anyhow!("Invalid mnemonic: {}", e)))?;
    let seed = Seed::new(&mnemonic, "");

    let network = if mainnet {
        Network::Bitcoin
    } else {
        Network::Testnet
    };
    let coin_type = if mainnet {
        COIN_TYPE_MAINNET
    } else {
        COIN_TYPE_TESTNET
    };

    let path_str = format!("m/{}'/{}'/{}'", purpose, coin_type, account);
    let path: DerivationPath = path_str
        .parse()
        .map_err(|e| Error::Other(anyhow::anyhow!("Invalid path: {}", e)))?;

    let secp = Secp256k1::new();
    let master = Xpriv::new_master(network, seed.as_bytes())
        .map_err(|e| Error::Other(anyhow::anyhow!("Master key error: {}", e)))?;

    let derived = master
        .derive_priv(&secp, &path)
        .map_err(|e| Error::Other(anyhow::anyhow!("Derivation error: {}", e)))?;

    let xpub = Xpub::from_priv(&secp, &derived);
    Ok(xpub.to_string())
}

// ============================================================================
// PSBT (Partially Signed Bitcoin Transaction) Support - BIP-174
// ============================================================================

/// Information about a PSBT input for display
#[derive(Clone, Debug)]
pub struct PsbtInputInfo {
    /// Previous transaction ID (txid)
    pub prev_txid: String,
    /// Previous output index
    pub prev_vout: u32,
    /// Amount being spent (satoshis), if known
    pub amount: Option<u64>,
    /// Address being spent from, if determinable
    pub address: Option<String>,
    /// Whether we can sign this input (has matching key)
    pub can_sign: bool,
    /// Derivation path hint, if present
    pub derivation_path: Option<String>,
    /// Is this a Taproot input?
    pub is_taproot: bool,
}

/// Information about a PSBT output for display
#[derive(Clone, Debug)]
pub struct PsbtOutputInfo {
    /// Amount (satoshis)
    pub amount: u64,
    /// Destination address
    pub address: String,
    /// Whether this is change (going back to our wallet)
    pub is_change: bool,
}

/// Summary of a PSBT for user review
#[derive(Clone, Debug)]
pub struct PsbtInfo {
    /// Transaction ID (before signing)
    pub txid: String,
    /// Input details
    pub inputs: Vec<PsbtInputInfo>,
    /// Output details
    pub outputs: Vec<PsbtOutputInfo>,
    /// Total input amount (satoshis)
    pub total_input: u64,
    /// Total output amount (satoshis)
    pub total_output: u64,
    /// Fee (satoshis)
    pub fee: u64,
    /// Fee rate (sat/vB estimate)
    pub fee_rate: f64,
    /// Number of inputs we can sign
    pub signable_inputs: usize,
    /// Network
    pub network: Network,
}

/// Parse a PSBT from base64 string
pub fn parse_psbt_base64(base64_str: &str) -> Result<Psbt> {
    use bitcoin::base64::{engine::general_purpose::STANDARD, Engine};

    let bytes = STANDARD
        .decode(base64_str)
        .map_err(|e| Error::Other(anyhow::anyhow!("Invalid base64: {}", e)))?;

    parse_psbt_bytes(&bytes)
}

/// Parse a PSBT from raw bytes
pub fn parse_psbt_bytes(bytes: &[u8]) -> Result<Psbt> {
    Psbt::deserialize(bytes).map_err(|e| Error::Other(anyhow::anyhow!("Invalid PSBT: {}", e)))
}

/// Analyze a PSBT and extract display information
pub fn analyze_psbt(
    psbt: &Psbt,
    our_pubkey: Option<&[u8; 33]>,
    network: Network,
) -> Result<PsbtInfo> {
    let unsigned_tx = &psbt.unsigned_tx;
    let txid = unsigned_tx.compute_txid().to_string();

    let mut inputs = Vec::new();
    let mut total_input: u64 = 0;
    let mut signable_inputs = 0;

    for (i, input) in psbt.inputs.iter().enumerate() {
        let tx_input = &unsigned_tx.input[i];
        let prev_txid = tx_input.previous_output.txid.to_string();
        let prev_vout = tx_input.previous_output.vout;

        // Get amount from witness_utxo or non_witness_utxo
        let amount = input
            .witness_utxo
            .as_ref()
            .map(|utxo| utxo.value.to_sat())
            .or_else(|| {
                input.non_witness_utxo.as_ref().and_then(|tx| {
                    tx.output
                        .get(prev_vout as usize)
                        .map(|out| out.value.to_sat())
                })
            });

        if let Some(amt) = amount {
            total_input += amt;
        }

        // Try to determine address
        let address = input
            .witness_utxo
            .as_ref()
            .and_then(|utxo| Address::from_script(&utxo.script_pubkey, network).ok())
            .map(|a| a.to_string());

        // Check if we can sign this input
        let is_taproot = input.tap_key_sig.is_none()
            && (input.tap_internal_key.is_some()
                || input
                    .witness_utxo
                    .as_ref()
                    .map(|u| u.script_pubkey.is_p2tr())
                    .unwrap_or(false));

        let can_sign = our_pubkey
            .map(|pk| {
                // Check BIP32 derivations - keys in psbt are secp256k1::PublicKey
                let in_bip32 = input.bip32_derivation.keys().any(|k| k.serialize() == *pk);
                // Check tap key path
                let in_tap = input
                    .tap_internal_key
                    .map(|xonly| {
                        let secp_pubkey = Secp256k1PublicKey::from_slice(pk).ok();
                        secp_pubkey
                            .map(|p| p.x_only_public_key().0 == xonly)
                            .unwrap_or(false)
                    })
                    .unwrap_or(false);
                in_bip32 || in_tap
            })
            .unwrap_or(false);

        if can_sign {
            signable_inputs += 1;
        }

        // Get derivation path hint
        let derivation_path = input
            .bip32_derivation
            .values()
            .next()
            .map(|(_, path)| format!("{}", path));

        inputs.push(PsbtInputInfo {
            prev_txid,
            prev_vout,
            amount,
            address,
            can_sign,
            derivation_path,
            is_taproot,
        });
    }

    // Process outputs
    let mut outputs = Vec::new();
    let mut total_output: u64 = 0;

    for (i, output) in unsigned_tx.output.iter().enumerate() {
        let amount = output.value.to_sat();
        total_output += amount;

        let address = Address::from_script(&output.script_pubkey, network)
            .map(|a| a.to_string())
            .unwrap_or_else(|_| "unknown".to_string());

        // Check if this is change (has BIP32 derivation in psbt output)
        let is_change = psbt
            .outputs
            .get(i)
            .map(|o| !o.bip32_derivation.is_empty() || o.tap_internal_key.is_some())
            .unwrap_or(false);

        outputs.push(PsbtOutputInfo {
            amount,
            address,
            is_change,
        });
    }

    let fee = total_input.saturating_sub(total_output);

    // Estimate fee rate (rough estimate based on typical tx size)
    let estimated_vsize =
        (unsigned_tx.input.len() * 68 + unsigned_tx.output.len() * 31 + 10) as f64;
    let fee_rate = fee as f64 / estimated_vsize;

    Ok(PsbtInfo {
        txid,
        inputs,
        outputs,
        total_input,
        total_output,
        fee,
        fee_rate,
        signable_inputs,
        network,
    })
}

/// Sign a PSBT with the given key pair
///
/// This function signs all inputs that match our public key.
/// Supports both ECDSA (SegWit) and Schnorr (Taproot) signatures.
pub fn sign_psbt(psbt: &mut Psbt, keypair: &BitcoinKeyPair) -> Result<usize> {
    let secp = Secp256k1::new();
    let secret = SecretKey::from_slice(keypair.secret_key())
        .map_err(|e| Error::Other(anyhow::anyhow!("Invalid secret key: {}", e)))?;
    let secp_pubkey = Secp256k1PublicKey::from_slice(&keypair.public_key)
        .map_err(|e| Error::Other(anyhow::anyhow!("Invalid public key: {}", e)))?;
    // bitcoin::PublicKey wraps secp256k1::PublicKey for PSBT operations
    let btc_pubkey = PublicKey::new(secp_pubkey);
    let kp = Keypair::from_secret_key(&secp, &secret);
    let (x_only_pubkey, _parity) = kp.x_only_public_key();

    let unsigned_tx = psbt.unsigned_tx.clone();
    let mut sighash_cache = SighashCache::new(&unsigned_tx);
    let mut signed_count = 0;

    for i in 0..psbt.inputs.len() {
        let input = &psbt.inputs[i];

        // Determine if this is a Taproot input
        let is_taproot = input.tap_internal_key.is_some()
            || input
                .witness_utxo
                .as_ref()
                .map(|u| u.script_pubkey.is_p2tr())
                .unwrap_or(false);

        // Check if we should sign this input
        let should_sign = if is_taproot {
            // For Taproot, check internal key matches our x-only pubkey
            input
                .tap_internal_key
                .map(|k| k == x_only_pubkey)
                .unwrap_or(false)
        } else {
            // For SegWit, check BIP32 derivations - keys are secp256k1::PublicKey
            input.bip32_derivation.keys().any(|k| *k == secp_pubkey)
        };

        if !should_sign {
            continue;
        }

        if is_taproot {
            // Sign Taproot key path
            if input.witness_utxo.is_some() {
                // Collect all prevouts for sighash computation
                let mut prevouts = Vec::new();
                for (j, inp) in psbt.inputs.iter().enumerate() {
                    if let Some(u) = &inp.witness_utxo {
                        prevouts.push(u.clone());
                    } else {
                        return Err(Error::Other(anyhow::anyhow!(
                            "Missing witness_utxo for Taproot input {}",
                            j
                        )));
                    }
                }

                let sighash = sighash_cache
                    .taproot_key_spend_signature_hash(
                        i,
                        &bitcoin::sighash::Prevouts::All(&prevouts),
                        TapSighashType::Default,
                    )
                    .map_err(|e| Error::Other(anyhow::anyhow!("Sighash error: {}", e)))?;

                let msg = Message::from_digest_slice(sighash.as_ref())
                    .map_err(|e| Error::Other(anyhow::anyhow!("Message error: {}", e)))?;

                let sig = secp.sign_schnorr_no_aux_rand(&msg, &kp);
                let tap_sig = TaprootSignature {
                    signature: sig,
                    sighash_type: TapSighashType::Default,
                };

                psbt.inputs[i].tap_key_sig = Some(tap_sig);
                signed_count += 1;
            }
        } else {
            // Sign SegWit (P2WPKH)
            if let Some(utxo) = &input.witness_utxo {
                let script_code = bitcoin::script::ScriptBuf::new_p2wpkh(
                    &bitcoin::WPubkeyHash::from_slice(&utxo.script_pubkey.as_bytes()[2..])
                        .map_err(|e| Error::Other(anyhow::anyhow!("Script error: {}", e)))?,
                );

                let sighash = sighash_cache
                    .p2wpkh_signature_hash(i, &script_code, utxo.value, EcdsaSighashType::All)
                    .map_err(|e| Error::Other(anyhow::anyhow!("Sighash error: {}", e)))?;

                let msg = Message::from_digest_slice(sighash.as_ref())
                    .map_err(|e| Error::Other(anyhow::anyhow!("Message error: {}", e)))?;

                let sig = secp.sign_ecdsa(&msg, &secret);
                let ecdsa_sig = EcdsaSignature {
                    signature: sig,
                    sighash_type: EcdsaSighashType::All,
                };

                psbt.inputs[i].partial_sigs.insert(btc_pubkey, ecdsa_sig);
                signed_count += 1;
            }
        }
    }

    Ok(signed_count)
}

/// Finalize a fully-signed PSBT and extract the transaction
pub fn finalize_psbt(psbt: &mut Psbt) -> Result<Transaction> {
    // Finalize each input
    for i in 0..psbt.inputs.len() {
        let input = &psbt.inputs[i];

        // Check if it's a Taproot input
        if input.tap_key_sig.is_some() {
            // Taproot key-path spend - just needs the signature
            if let Some(sig) = &input.tap_key_sig {
                psbt.inputs[i].final_script_witness =
                    Some(bitcoin::Witness::from_slice(&[sig.to_vec()]));
            }
        } else if !input.partial_sigs.is_empty() {
            // SegWit (P2WPKH) - needs signature and pubkey
            if let Some((pubkey, sig)) = input.partial_sigs.iter().next() {
                let mut witness = bitcoin::Witness::new();
                witness.push(sig.to_vec());
                witness.push(pubkey.inner.serialize());
                psbt.inputs[i].final_script_witness = Some(witness);
            }
        }

        // Clear unnecessary fields after finalization
        psbt.inputs[i].partial_sigs.clear();
        psbt.inputs[i].bip32_derivation.clear();
        psbt.inputs[i].tap_key_sig = None;
        psbt.inputs[i].tap_internal_key = None;
    }

    Ok(psbt.unsigned_tx.clone())
}

/// Serialize a PSBT to base64 string
pub fn psbt_to_base64(psbt: &Psbt) -> String {
    use bitcoin::base64::{engine::general_purpose::STANDARD, Engine};
    STANDARD.encode(psbt.serialize())
}

/// Serialize a PSBT to hex string
pub fn psbt_to_hex(psbt: &Psbt) -> String {
    hex::encode(psbt.serialize())
}

/// Format satoshis as BTC string
pub fn format_btc(satoshis: u64) -> String {
    let btc = satoshis as f64 / 100_000_000.0;
    format!("{:.8} BTC", btc)
}

/// Format satoshis for display
pub fn format_sats(satoshis: u64) -> String {
    if satoshis >= 100_000_000 {
        format_btc(satoshis)
    } else if satoshis >= 1000 {
        format!(
            "{} sats ({:.4} mBTC)",
            satoshis,
            satoshis as f64 / 100_000.0
        )
    } else {
        format!("{} sats", satoshis)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bitcoin_segwit_derivation() {
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

        let key = derive_segwit_key(mnemonic, true, 0, 0, 0).unwrap();
        let address = key.address().unwrap();

        println!("SegWit public key: {}", hex::encode(&key.public_key));
        println!("SegWit address: {}", address);

        // Native segwit addresses start with bc1q
        assert!(address.starts_with("bc1q"));
    }

    #[test]
    fn test_bitcoin_taproot_derivation() {
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

        let key = derive_taproot_key(mnemonic, true, 0, 0, 0).unwrap();
        let address = key.address().unwrap();

        println!("Taproot public key: {}", hex::encode(&key.public_key));
        println!("Taproot x-only: {}", hex::encode(key.x_only_pubkey()));
        println!("Taproot address: {}", address);

        // Taproot addresses start with bc1p
        assert!(address.starts_with("bc1p"));
    }

    #[test]
    fn test_testnet_derivation() {
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

        let key = derive_segwit_key(mnemonic, false, 0, 0, 0).unwrap();
        let address = key.address().unwrap();

        println!("Testnet SegWit address: {}", address);

        // Testnet segwit addresses start with tb1q
        assert!(address.starts_with("tb1q"));
    }

    #[test]
    fn test_schnorr_signing() {
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

        let key = derive_taproot_key(mnemonic, true, 0, 0, 0).unwrap();

        // Sign a test message hash
        let message_hash = [0u8; 32];
        let signature = key.sign_schnorr(&message_hash).unwrap();

        assert_eq!(signature.len(), 64);
        println!("Schnorr signature: {}", hex::encode(signature));
    }

    #[test]
    fn test_multiple_accounts() {
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

        let key0 = derive_segwit_key(mnemonic, true, 0, 0, 0).unwrap();
        let key1 = derive_segwit_key(mnemonic, true, 1, 0, 0).unwrap();

        assert_ne!(key0.public_key, key1.public_key);

        println!("Account 0: {}", key0.address().unwrap());
        println!("Account 1: {}", key1.address().unwrap());
    }

    #[test]
    fn test_xpub_export() {
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

        let xpub = export_xpub(mnemonic, PURPOSE_SEGWIT, true, 0).unwrap();
        println!("SegWit xpub: {}", xpub);

        // xpub for mainnet starts with xpub
        assert!(xpub.starts_with("xpub"));
    }

    #[test]
    fn test_parse_bitcoin_path() {
        // Full path
        let (purpose, mainnet, account, change, index) =
            parse_bitcoin_path("m/84'/0'/0'/0/0").unwrap();
        assert_eq!(purpose, 84);
        assert!(mainnet);
        assert_eq!(account, 0);
        assert_eq!(change, 0);
        assert_eq!(index, 0);

        // Simplified path
        let (purpose, mainnet, account, _, _) = parse_bitcoin_path("//bitcoin//0").unwrap();
        assert_eq!(purpose, PURPOSE_SEGWIT);
        assert!(mainnet);
        assert_eq!(account, 0);

        // Taproot path
        let (purpose, _, _, _, _) = parse_bitcoin_path("//bitcoin_taproot//0").unwrap();
        assert_eq!(purpose, PURPOSE_TAPROOT);
    }

    #[test]
    fn test_format_sats() {
        assert_eq!(format_sats(100), "100 sats");
        assert_eq!(format_sats(50000), "50000 sats (0.5000 mBTC)");
        assert_eq!(format_sats(100_000_000), "1.00000000 BTC");
        assert_eq!(format_sats(250_000_000), "2.50000000 BTC");
    }

    #[test]
    fn test_psbt_create_and_analyze() {
        use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, TxIn, TxOut, Txid};
        use std::str::FromStr;

        // Create a minimal PSBT for testing
        let tx = Transaction {
            version: bitcoin::transaction::Version(2),
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: Txid::from_str(
                        "0000000000000000000000000000000000000000000000000000000000000001",
                    )
                    .unwrap(),
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: bitcoin::Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(50000),
                script_pubkey: ScriptBuf::new_p2wpkh(
                    &bitcoin::WPubkeyHash::from_str("751e76e8199196d454941c45d1b3a323f1433bd6")
                        .unwrap(),
                ),
            }],
        };

        let mut psbt = Psbt::from_unsigned_tx(tx).unwrap();

        // Add witness utxo to input (simulating 100k sats input)
        psbt.inputs[0].witness_utxo = Some(TxOut {
            value: Amount::from_sat(100000),
            script_pubkey: ScriptBuf::new_p2wpkh(
                &bitcoin::WPubkeyHash::from_str("751e76e8199196d454941c45d1b3a323f1433bd6")
                    .unwrap(),
            ),
        });

        // Analyze the PSBT
        let info = analyze_psbt(&psbt, None, Network::Bitcoin).unwrap();

        println!("PSBT txid: {}", info.txid);
        println!("Inputs: {}", info.inputs.len());
        println!("Outputs: {}", info.outputs.len());
        println!("Total input: {} sats", info.total_input);
        println!("Total output: {} sats", info.total_output);
        println!("Fee: {} sats", info.fee);
        println!("Fee rate: {:.1} sat/vB", info.fee_rate);

        assert_eq!(info.inputs.len(), 1);
        assert_eq!(info.outputs.len(), 1);
        assert_eq!(info.total_input, 100000);
        assert_eq!(info.total_output, 50000);
        assert_eq!(info.fee, 50000);
    }

    #[test]
    fn test_psbt_serialization() {
        use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, TxIn, TxOut, Txid};
        use std::str::FromStr;

        let tx = Transaction {
            version: bitcoin::transaction::Version(2),
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: Txid::from_str(
                        "0000000000000000000000000000000000000000000000000000000000000001",
                    )
                    .unwrap(),
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: bitcoin::Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(50000),
                script_pubkey: ScriptBuf::new_p2wpkh(
                    &bitcoin::WPubkeyHash::from_str("751e76e8199196d454941c45d1b3a323f1433bd6")
                        .unwrap(),
                ),
            }],
        };

        let psbt = Psbt::from_unsigned_tx(tx).unwrap();

        // Test base64 serialization
        let base64_str = psbt_to_base64(&psbt);
        println!("PSBT base64: {}", base64_str);
        assert!(base64_str.starts_with("cHNidP8")); // PSBT magic

        // Test hex serialization
        let hex_str = psbt_to_hex(&psbt);
        println!("PSBT hex: {}", hex_str);
        assert!(hex_str.starts_with("70736274ff")); // PSBT magic in hex

        // Test round-trip
        let parsed = parse_psbt_base64(&base64_str).unwrap();
        assert_eq!(
            parsed.unsigned_tx.compute_txid(),
            psbt.unsigned_tx.compute_txid()
        );
    }
}
