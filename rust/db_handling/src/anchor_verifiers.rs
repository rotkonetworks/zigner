//! Anchor-attestation verifier registry.
//!
//! Zigner verifies Zcash anchor attestations against ANY enabled entry in
//! this sled tree. The tree is bootstrapped from `ROTKO_ZCASH_VERIFIER`
//! (a built-in default) on first run, but users running their own zidecar
//! can scan in additional verifier keys via the dedicated UR import path.
//!
//! Tree key:   32-byte ed25519 pubkey (the verifier's public key).
//! Tree value: JSON-encoded `VerifierRecord` (label, source, timestamps).
//!
//! Enabling/disabling entries is a soft toggle — disabled entries stay in
//! the tree so they can be re-enabled, but their signatures are not
//! accepted while disabled.

use crate::error::{Error, Result};
use constants::ANCHOR_VERIFIERS_TREE;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub enum VerifierSource {
    /// Bootstrapped from the binary's hardcoded constant on first run.
    BuiltIn,
    /// Added by the user via QR scan.
    User,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct VerifierRecord {
    pub label: String,
    pub source: VerifierSource,
    pub added_at: u64,
    pub enabled: bool,
}

/// Public listing entry — same as VerifierRecord but with the pubkey
/// alongside, suitable for FFI or settings UI.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct VerifierEntry {
    pub pubkey_hex: String,
    pub label: String,
    pub source: VerifierSource,
    pub added_at: u64,
    pub enabled: bool,
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Add a verifier key. Returns Err if it already exists (caller should
/// surface a "already trusted" message). To replace label/enabled state,
/// use `update_verifier`.
pub fn add_verifier(
    database: &sled::Db,
    pubkey: &[u8; 32],
    label: &str,
    source: VerifierSource,
) -> Result<()> {
    let tree = database.open_tree(ANCHOR_VERIFIERS_TREE)?;
    if tree.get(pubkey)?.is_some() {
        return Err(Error::Other(anyhow::anyhow!(
            "verifier already trusted (use update to change label)"
        )));
    }
    let record = VerifierRecord {
        label: label.to_string(),
        source,
        added_at: now_secs(),
        enabled: true,
    };
    let json =
        serde_json::to_vec(&record).map_err(|e| Error::Other(anyhow::anyhow!("encode: {e}")))?;
    tree.insert(pubkey, json.as_slice())?;
    tree.flush()?;
    Ok(())
}

/// Update an existing verifier's label and/or enabled flag. Source and
/// added_at are preserved. Returns Err if the verifier is not present.
pub fn update_verifier(
    database: &sled::Db,
    pubkey: &[u8; 32],
    new_label: Option<&str>,
    new_enabled: Option<bool>,
) -> Result<()> {
    let tree = database.open_tree(ANCHOR_VERIFIERS_TREE)?;
    let bytes = tree
        .get(pubkey)?
        .ok_or_else(|| Error::Other(anyhow::anyhow!("verifier not found")))?;
    let mut record: VerifierRecord =
        serde_json::from_slice(&bytes).map_err(|e| Error::Other(anyhow::anyhow!("decode: {e}")))?;
    if let Some(label) = new_label {
        record.label = label.to_string();
    }
    if let Some(enabled) = new_enabled {
        record.enabled = enabled;
    }
    let json =
        serde_json::to_vec(&record).map_err(|e| Error::Other(anyhow::anyhow!("encode: {e}")))?;
    tree.insert(pubkey, json.as_slice())?;
    tree.flush()?;
    Ok(())
}

/// Remove a verifier. Caller is responsible for refusing to remove the
/// last enabled entry on a device that has the sticky-attestation flag
/// set (otherwise the device cannot import any future note bundles).
pub fn remove_verifier(database: &sled::Db, pubkey: &[u8; 32]) -> Result<()> {
    let tree = database.open_tree(ANCHOR_VERIFIERS_TREE)?;
    tree.remove(pubkey)?;
    tree.flush()?;
    Ok(())
}

/// List every verifier in the tree (enabled and disabled).
pub fn list_verifiers(database: &sled::Db) -> Result<Vec<VerifierEntry>> {
    let tree = database.open_tree(ANCHOR_VERIFIERS_TREE)?;
    let mut out = Vec::new();
    for entry in tree.iter() {
        let (key, value) = entry?;
        if key.len() != 32 {
            continue;
        }
        let record: VerifierRecord = match serde_json::from_slice(&value) {
            Ok(r) => r,
            Err(_) => continue,
        };
        out.push(VerifierEntry {
            pubkey_hex: hex::encode(&key),
            label: record.label,
            source: record.source,
            added_at: record.added_at,
            enabled: record.enabled,
        });
    }
    Ok(out)
}

/// Iterate enabled verifiers as `[u8; 32]` pubkeys. Used by the
/// attestation verification path.
pub fn enabled_pubkeys(database: &sled::Db) -> Result<Vec<[u8; 32]>> {
    let tree = database.open_tree(ANCHOR_VERIFIERS_TREE)?;
    let mut out = Vec::new();
    for entry in tree.iter() {
        let (key, value) = entry?;
        if key.len() != 32 {
            continue;
        }
        let record: VerifierRecord = match serde_json::from_slice(&value) {
            Ok(r) => r,
            Err(_) => continue,
        };
        if !record.enabled {
            continue;
        }
        let mut pk = [0u8; 32];
        pk.copy_from_slice(&key);
        out.push(pk);
    }
    Ok(out)
}

/// Bootstrap the tree with the built-in default verifier on first run.
/// Idempotent: if the tree is already non-empty (or the default is
/// already present), this is a no-op.
pub fn bootstrap_default(
    database: &sled::Db,
    default_pubkey: &[u8; 32],
    default_label: &str,
) -> Result<()> {
    let tree = database.open_tree(ANCHOR_VERIFIERS_TREE)?;
    if tree.get(default_pubkey)?.is_some() {
        return Ok(());
    }
    if !tree.is_empty() {
        // User has at least one custom verifier — don't overwrite their
        // configuration. They can choose whether to add the default back.
        return Ok(());
    }
    let record = VerifierRecord {
        label: default_label.to_string(),
        source: VerifierSource::BuiltIn,
        added_at: now_secs(),
        enabled: true,
    };
    let json =
        serde_json::to_vec(&record).map_err(|e| Error::Other(anyhow::anyhow!("encode: {e}")))?;
    tree.insert(default_pubkey, json.as_slice())?;
    tree.flush()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn open_tmp_db() -> sled::Db {
        let path = std::env::temp_dir().join(format!(
            "zigner-anchor-verifiers-test-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        sled::open(&path).unwrap()
    }

    #[test]
    fn add_list_remove() {
        let db = open_tmp_db();
        let pk = [0xaau8; 32];
        add_verifier(&db, &pk, "rotko", VerifierSource::BuiltIn).unwrap();

        let list = list_verifiers(&db).unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].label, "rotko");
        assert!(list[0].enabled);

        remove_verifier(&db, &pk).unwrap();
        assert!(list_verifiers(&db).unwrap().is_empty());
    }

    #[test]
    fn add_duplicate_rejected() {
        let db = open_tmp_db();
        let pk = [0xbbu8; 32];
        add_verifier(&db, &pk, "first", VerifierSource::User).unwrap();
        let err = add_verifier(&db, &pk, "second", VerifierSource::User);
        assert!(err.is_err());
    }

    #[test]
    fn enable_disable() {
        let db = open_tmp_db();
        let pk = [0xccu8; 32];
        add_verifier(&db, &pk, "test", VerifierSource::User).unwrap();
        assert_eq!(enabled_pubkeys(&db).unwrap().len(), 1);

        update_verifier(&db, &pk, None, Some(false)).unwrap();
        assert_eq!(enabled_pubkeys(&db).unwrap().len(), 0);
        assert_eq!(list_verifiers(&db).unwrap().len(), 1); // still in tree

        update_verifier(&db, &pk, None, Some(true)).unwrap();
        assert_eq!(enabled_pubkeys(&db).unwrap().len(), 1);
    }

    #[test]
    fn bootstrap_idempotent() {
        let db = open_tmp_db();
        let pk = [0xdd; 32];
        bootstrap_default(&db, &pk, "rotko").unwrap();
        bootstrap_default(&db, &pk, "rotko").unwrap();
        assert_eq!(list_verifiers(&db).unwrap().len(), 1);
    }

    #[test]
    fn bootstrap_skips_when_user_has_keys() {
        let db = open_tmp_db();
        let user_pk = [0x01; 32];
        let default_pk = [0x02; 32];
        add_verifier(&db, &user_pk, "mine", VerifierSource::User).unwrap();
        bootstrap_default(&db, &default_pk, "rotko").unwrap();
        let list = list_verifiers(&db).unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].pubkey_hex, hex::encode(user_pk));
    }
}
