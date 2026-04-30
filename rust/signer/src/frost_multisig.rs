// frost_multisig.rs — FROST threshold multisig for Zigner cold signer
//
// Zigner participates as a signer in a t-of-n FROST multisig.
// It stores a KeyPackage (from DKG) and produces signature shares
// when presented with a sighash + alphas.
//
// All orchestration logic lives in frost_spend::orchestrate.
// This module wraps it for uniffi FFI.

use std::collections::HashSet;
use std::convert::TryInto;
use std::sync::Mutex;

use frost_spend::orchestrate;

lazy_static::lazy_static! {
    /// Track nonce hashes that have been consumed by signing.
    /// A nonce that appears here has been used and MUST NOT be reused.
    /// This prevents catastrophic key recovery from nonce reuse.
    static ref USED_NONCES: Mutex<HashSet<[u8; 16]>> = Mutex::new(HashSet::new());
}

/// Compute a short fingerprint of a nonce for tracking.
/// We don't store the full nonce — just enough to detect reuse.
fn nonce_fingerprint(nonces_hex: &str) -> [u8; 16] {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut h = DefaultHasher::new();
    nonces_hex.hash(&mut h);
    let hash1 = h.finish();
    // second round for 128 bits
    h.write_u8(0xff);
    let hash2 = h.finish();
    let mut fp = [0u8; 16];
    fp[..8].copy_from_slice(&hash1.to_le_bytes());
    fp[8..].copy_from_slice(&hash2.to_le_bytes());
    fp
}

/// Mark a nonce as consumed. Returns Err if already used.
fn consume_nonce(nonces_hex: &str) -> Result<(), String> {
    let fp = nonce_fingerprint(nonces_hex);
    let mut used = USED_NONCES
        .lock()
        .map_err(|_| "nonce tracker poisoned".to_string())?;
    if !used.insert(fp) {
        return Err(
            "CRITICAL: Nonce reuse detected. This nonce was already used for signing. \
             Reusing a FROST nonce with a different message would leak the private key. \
             Generate fresh nonces with sign_round1."
                .to_string(),
        );
    }
    // Limit size to prevent unbounded growth (old entries are stale anyway)
    if used.len() > 1000 {
        used.clear();
        used.insert(fp);
    }
    Ok(())
}

/// DKG round 1: generate ephemeral identity + signed commitment.
/// Returns JSON: { "secret": hex, "broadcast": hex }
pub fn frost_dkg_part1(max_signers: u16, min_signers: u16) -> Result<String, String> {
    let result = orchestrate::dkg_part1(max_signers, min_signers).map_err(|e| e.to_string())?;
    serde_json::to_string(&serde_json::json!({
        "secret": result.secret_hex,
        "broadcast": result.broadcast_hex,
    }))
    .map_err(|e| e.to_string())
}

/// DKG round 2: process signed round1 broadcasts.
/// peer_broadcasts_json: JSON array of hex strings.
/// Returns JSON: { "secret": hex, "peer_packages": [hex, ...] }
pub fn frost_dkg_part2(secret_hex: &str, peer_broadcasts_json: &str) -> Result<String, String> {
    let broadcasts: Vec<String> = serde_json::from_str(peer_broadcasts_json)
        .map_err(|e| format!("bad broadcasts JSON: {}", e))?;
    let result = orchestrate::dkg_part2(secret_hex, &broadcasts).map_err(|e| e.to_string())?;
    serde_json::to_string(&serde_json::json!({
        "secret": result.secret_hex,
        "peer_packages": result.peer_packages,
    }))
    .map_err(|e| e.to_string())
}

/// DKG round 3: finalize — returns key package + public key package.
/// Returns JSON: { "key_package": hex, "public_key_package": hex, "ephemeral_seed": hex }
pub fn frost_dkg_part3(
    secret_hex: &str,
    round1_broadcasts_json: &str,
    round2_packages_json: &str,
) -> Result<String, String> {
    let r1: Vec<String> = serde_json::from_str(round1_broadcasts_json)
        .map_err(|e| format!("bad round1 JSON: {}", e))?;
    let r2: Vec<String> = serde_json::from_str(round2_packages_json)
        .map_err(|e| format!("bad round2 JSON: {}", e))?;
    let result = orchestrate::dkg_part3(secret_hex, &r1, &r2).map_err(|e| e.to_string())?;
    serde_json::to_string(&serde_json::json!({
        "key_package": result.key_package_hex,
        "public_key_package": result.public_key_package_hex,
        "ephemeral_seed": result.ephemeral_seed_hex,
    }))
    .map_err(|e| e.to_string())
}

/// signing round 1: generate nonces + signed commitments.
/// Returns JSON: { "nonces": hex, "commitments": hex }
pub fn frost_sign_round1(
    ephemeral_seed_hex: &str,
    key_package_hex: &str,
) -> Result<String, String> {
    let seed = parse_seed(ephemeral_seed_hex)?;
    let (nonces, commitments) =
        orchestrate::sign_round1(&seed, key_package_hex).map_err(|e| e.to_string())?;
    serde_json::to_string(&serde_json::json!({
        "nonces": nonces,
        "commitments": commitments,
    }))
    .map_err(|e| e.to_string())
}

/// spend-authorize round 2: produce FROST share bound to sighash + alpha.
/// This is what Zigner does when participating in a multisig spend.
/// commitments_json: JSON array of hex-encoded signed commitments from all signers.
/// Returns: hex-encoded signature share.
pub fn frost_spend_sign_round2(
    key_package_hex: &str,
    nonces_hex: &str,
    sighash_hex: &str,
    alpha_hex: &str,
    commitments_json: &str,
) -> Result<String, String> {
    // Consume nonce BEFORE signing — prevents reuse even if signing fails
    consume_nonce(nonces_hex)?;

    let sighash = parse_32(sighash_hex, "sighash")?;
    let alpha = parse_32(alpha_hex, "alpha")?;
    let commitments: Vec<String> = serde_json::from_str(commitments_json)
        .map_err(|e| format!("bad commitments JSON: {}", e))?;
    orchestrate::spend_sign_round2(key_package_hex, nonces_hex, &sighash, &alpha, &commitments)
        .map_err(|e| e.to_string())
}

/// sign multiple actions at once (one share per alpha).
/// alphas_json: JSON array of hex-encoded 32-byte alphas (one per Orchard action).
/// commitments_json: JSON array of hex-encoded signed commitments.
/// Returns JSON: { "shares": [hex, ...] }
pub fn frost_spend_sign_actions(
    key_package_hex: &str,
    nonces_hex: &str,
    sighash_hex: &str,
    alphas_json: &str,
    commitments_json: &str,
) -> Result<String, String> {
    // Consume nonce BEFORE any signing — prevents reuse even if one action fails
    consume_nonce(nonces_hex)?;

    let sighash = parse_32(sighash_hex, "sighash")?;
    let alphas: Vec<String> =
        serde_json::from_str(alphas_json).map_err(|e| format!("bad alphas JSON: {}", e))?;
    let commitments: Vec<String> = serde_json::from_str(commitments_json)
        .map_err(|e| format!("bad commitments JSON: {}", e))?;

    let mut shares = Vec::new();
    for alpha_hex in &alphas {
        let alpha = parse_32(alpha_hex, "alpha")?;
        let share = orchestrate::spend_sign_round2(
            key_package_hex,
            nonces_hex,
            &sighash,
            &alpha,
            &commitments,
        )
        .map_err(|e| e.to_string())?;
        shares.push(share);
    }

    serde_json::to_string(&serde_json::json!({ "shares": shares })).map_err(|e| e.to_string())
}

/// derive raw Orchard address bytes (43 bytes, hex-encoded) from public key package.
/// Caller encodes to unified address string for the appropriate network.
pub fn frost_derive_address_raw(
    public_key_package_hex: &str,
    diversifier_index: u32,
) -> Result<String, String> {
    let raw = orchestrate::derive_address_raw(public_key_package_hex, diversifier_index)
        .map_err(|e| e.to_string())?;
    Ok(hex::encode(raw))
}

/// Derive both the Orchard-only UFVK (`uview1…`) and unified address (`u1…`)
/// from a FROST public_key_package + the host-broadcast `sk`. Every participant
/// who calls this with identical inputs lands on byte-identical outputs.
/// Returns JSON `{ "orchard_fvk_uview": "...", "address": "..." }`.
pub fn frost_derive_metadata(
    public_key_package_hex: &str,
    sk_hex: &str,
    mainnet: bool,
    diversifier_index: u32,
) -> Result<String, String> {
    use frost_spend::frost_keys::PublicKeyPackage;
    use frost_spend::keys::{derive_address as fs_derive_address, derive_fvk_from_sk};
    use frost_spend::orchestrate::from_hex;
    use zcash_address::unified::{
        Address as UnifiedAddress, Encoding, Fvk, Receiver, Ufvk,
    };
    use zcash_address::Network;

    let sk = parse_32(sk_hex, "fvk sk")?;
    let pubkeys: PublicKeyPackage = from_hex(public_key_package_hex).map_err(|e| e.to_string())?;
    let fvk = derive_fvk_from_sk(sk, &pubkeys)
        .ok_or_else(|| "failed to derive FVK from group key + sk".to_string())?;
    let addr = fs_derive_address(&fvk, diversifier_index);
    let raw = addr.to_raw_address_bytes();

    let network = if mainnet { Network::Main } else { Network::Test };

    let ufvk_str = Ufvk::try_from_items(vec![Fvk::Orchard(fvk.to_bytes())])
        .map_err(|e| format!("build UFVK: {e}"))?
        .encode(&network);

    let addr_str = UnifiedAddress::try_from_items(vec![Receiver::Orchard(raw)])
        .map_err(|e| format!("build address: {e}"))?
        .encode(&network);

    serde_json::to_string(&serde_json::json!({
        "orchard_fvk_uview": ufvk_str,
        "address": addr_str,
    }))
    .map_err(|e| e.to_string())
}

// ── helpers ──

fn parse_seed(hex_str: &str) -> Result<[u8; 32], String> {
    let bytes = hex::decode(hex_str).map_err(|e| format!("bad seed hex: {}", e))?;
    bytes
        .try_into()
        .map_err(|_| "seed must be 32 bytes".to_string())
}

fn parse_32(hex_str: &str, name: &str) -> Result<[u8; 32], String> {
    let bytes = hex::decode(hex_str).map_err(|e| format!("bad {} hex: {}", name, e))?;
    bytes
        .try_into()
        .map_err(|_| format!("{} must be 32 bytes", name))
}
