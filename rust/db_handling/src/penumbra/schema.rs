//! Penumbra action schema and registry storage
//!
//! Stores and retrieves Penumbra action schemas and asset registry digests
//! from the sled database. Schemas define how to parse and display transaction
//! actions, while registries provide asset metadata for display.

use crate::error::Error;
use anyhow::anyhow;
use definitions::penumbra_schema::{
    default_penumbra_schema, PenumbraActionSchema, RegistryDigest, SchemaDigest,
};

/// Database tree name for Penumbra schemas
const PENUMBRA_SCHEMA_TREE: &str = "penumbra_schema";

/// Database tree name for asset registries
const PENUMBRA_REGISTRY_TREE: &str = "penumbra_registry";

/// Key for the current active schema
const CURRENT_SCHEMA_KEY: &[u8] = b"current";

/// Key for the current registry digest
const CURRENT_REGISTRY_KEY: &[u8] = b"registry_digest";

/// Key for the schema digest (merkleized)
const SCHEMA_DIGEST_KEY: &[u8] = b"schema_digest";

/// Store a Penumbra action schema
pub fn store_schema(db: &sled::Db, schema: &PenumbraActionSchema) -> Result<(), Error> {
    let tree = db.open_tree(PENUMBRA_SCHEMA_TREE)?;

    // Serialize schema to JSON (could use bincode for smaller size)
    let schema_bytes = serde_json::to_vec(schema)
        .map_err(|e| Error::Other(anyhow!("Failed to serialize schema: {}", e)))?;

    tree.insert(CURRENT_SCHEMA_KEY, schema_bytes)?;
    tree.flush()?;

    Ok(())
}

/// Get the current Penumbra action schema
/// Returns the default schema if none is stored
pub fn get_schema(db: &sled::Db) -> Result<PenumbraActionSchema, Error> {
    let tree = db.open_tree(PENUMBRA_SCHEMA_TREE)?;

    match tree.get(CURRENT_SCHEMA_KEY)? {
        Some(bytes) => {
            let schema: PenumbraActionSchema = serde_json::from_slice(&bytes)
                .map_err(|e| Error::Other(anyhow!("Failed to deserialize schema: {}", e)))?;
            Ok(schema)
        }
        None => {
            // Return default schema if none stored
            Ok(default_penumbra_schema())
        }
    }
}

/// Check if a schema is stored
pub fn has_schema(db: &sled::Db) -> Result<bool, Error> {
    let tree = db.open_tree(PENUMBRA_SCHEMA_TREE)?;
    Ok(tree.contains_key(CURRENT_SCHEMA_KEY)?)
}

/// Get schema version info without loading the full schema
pub fn get_schema_version(db: &sled::Db) -> Result<Option<(u32, String, String)>, Error> {
    let tree = db.open_tree(PENUMBRA_SCHEMA_TREE)?;

    match tree.get(CURRENT_SCHEMA_KEY)? {
        Some(bytes) => {
            let schema: PenumbraActionSchema = serde_json::from_slice(&bytes)
                .map_err(|e| Error::Other(anyhow!("Failed to deserialize schema: {}", e)))?;
            Ok(Some((
                schema.version,
                schema.chain_id,
                schema.protocol_version,
            )))
        }
        None => Ok(None),
    }
}

/// Clear the stored schema (revert to default)
pub fn clear_schema(db: &sled::Db) -> Result<(), Error> {
    let tree = db.open_tree(PENUMBRA_SCHEMA_TREE)?;
    tree.remove(CURRENT_SCHEMA_KEY)?;
    tree.flush()?;
    Ok(())
}

/// Store schema by chain_id (for multi-chain support)
pub fn store_schema_for_chain(
    db: &sled::Db,
    chain_id: &str,
    schema: &PenumbraActionSchema,
) -> Result<(), Error> {
    let tree = db.open_tree(PENUMBRA_SCHEMA_TREE)?;

    let key = format!("chain:{}", chain_id);
    let schema_bytes = serde_json::to_vec(schema)
        .map_err(|e| Error::Other(anyhow!("Failed to serialize schema: {}", e)))?;

    tree.insert(key.as_bytes(), schema_bytes)?;
    tree.flush()?;

    Ok(())
}

/// Get schema for a specific chain
pub fn get_schema_for_chain(
    db: &sled::Db,
    chain_id: &str,
) -> Result<Option<PenumbraActionSchema>, Error> {
    let tree = db.open_tree(PENUMBRA_SCHEMA_TREE)?;

    let key = format!("chain:{}", chain_id);

    match tree.get(key.as_bytes())? {
        Some(bytes) => {
            let schema: PenumbraActionSchema = serde_json::from_slice(&bytes)
                .map_err(|e| Error::Other(anyhow!("Failed to deserialize schema: {}", e)))?;
            Ok(Some(schema))
        }
        None => Ok(None),
    }
}

// =============================================================================
// Registry Digest Storage
// =============================================================================

/// Store an asset registry digest
pub fn store_registry_digest(db: &sled::Db, digest: &RegistryDigest) -> Result<(), Error> {
    let tree = db.open_tree(PENUMBRA_REGISTRY_TREE)?;

    let digest_bytes = serde_json::to_vec(digest)
        .map_err(|e| Error::Other(anyhow!("Failed to serialize registry digest: {}", e)))?;

    tree.insert(CURRENT_REGISTRY_KEY, digest_bytes)?;
    tree.flush()?;

    Ok(())
}

/// Get the current asset registry digest
pub fn get_registry_digest(db: &sled::Db) -> Result<Option<RegistryDigest>, Error> {
    let tree = db.open_tree(PENUMBRA_REGISTRY_TREE)?;

    match tree.get(CURRENT_REGISTRY_KEY)? {
        Some(bytes) => {
            let digest: RegistryDigest = serde_json::from_slice(&bytes).map_err(|e| {
                Error::Other(anyhow!("Failed to deserialize registry digest: {}", e))
            })?;
            Ok(Some(digest))
        }
        None => Ok(None),
    }
}

/// Store registry digest for a specific chain
pub fn store_registry_for_chain(
    db: &sled::Db,
    chain_id: &str,
    digest: &RegistryDigest,
) -> Result<(), Error> {
    let tree = db.open_tree(PENUMBRA_REGISTRY_TREE)?;

    let key = format!("registry:{}", chain_id);
    let digest_bytes = serde_json::to_vec(digest)
        .map_err(|e| Error::Other(anyhow!("Failed to serialize registry digest: {}", e)))?;

    tree.insert(key.as_bytes(), digest_bytes)?;
    tree.flush()?;

    Ok(())
}

/// Get registry digest for a specific chain
pub fn get_registry_for_chain(
    db: &sled::Db,
    chain_id: &str,
) -> Result<Option<RegistryDigest>, Error> {
    let tree = db.open_tree(PENUMBRA_REGISTRY_TREE)?;

    let key = format!("registry:{}", chain_id);

    match tree.get(key.as_bytes())? {
        Some(bytes) => {
            let digest: RegistryDigest = serde_json::from_slice(&bytes).map_err(|e| {
                Error::Other(anyhow!("Failed to deserialize registry digest: {}", e))
            })?;
            Ok(Some(digest))
        }
        None => Ok(None),
    }
}

// =============================================================================
// Schema Digest Storage (Merkleized)
// =============================================================================

/// Store a merkleized schema digest
pub fn store_schema_digest(db: &sled::Db, digest: &SchemaDigest) -> Result<(), Error> {
    let tree = db.open_tree(PENUMBRA_SCHEMA_TREE)?;

    let digest_bytes = serde_json::to_vec(digest)
        .map_err(|e| Error::Other(anyhow!("Failed to serialize schema digest: {}", e)))?;

    tree.insert(SCHEMA_DIGEST_KEY, digest_bytes)?;
    tree.flush()?;

    Ok(())
}

/// Get the current schema digest
pub fn get_schema_digest(db: &sled::Db) -> Result<Option<SchemaDigest>, Error> {
    let tree = db.open_tree(PENUMBRA_SCHEMA_TREE)?;

    match tree.get(SCHEMA_DIGEST_KEY)? {
        Some(bytes) => {
            let digest: SchemaDigest = serde_json::from_slice(&bytes)
                .map_err(|e| Error::Other(anyhow!("Failed to deserialize schema digest: {}", e)))?;
            Ok(Some(digest))
        }
        None => Ok(None),
    }
}

/// Get info about stored schema/registry for display
pub fn get_penumbra_metadata_info(db: &sled::Db) -> Result<PenumbraMetadataInfo, Error> {
    let schema_version = get_schema_version(db)?;
    let registry_digest = get_registry_digest(db)?;
    let schema_digest = get_schema_digest(db)?;

    Ok(PenumbraMetadataInfo {
        schema_version,
        schema_digest_root: schema_digest.map(|d| d.root_hex()),
        registry_chain_id: registry_digest.as_ref().map(|d| d.chain_id.clone()),
        registry_asset_count: registry_digest.as_ref().map(|d| d.asset_count),
        registry_root: registry_digest.map(|d| d.root_hex()),
    })
}

/// Summary of stored Penumbra metadata
#[derive(Debug, Clone)]
pub struct PenumbraMetadataInfo {
    /// Schema version (version, chain_id, protocol_version)
    pub schema_version: Option<(u32, String, String)>,
    /// Schema digest merkle root (hex)
    pub schema_digest_root: Option<String>,
    /// Registry chain ID
    pub registry_chain_id: Option<String>,
    /// Number of assets in registry
    pub registry_asset_count: Option<u32>,
    /// Registry merkle root (hex)
    pub registry_root: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_schema_storage_roundtrip() {
        let dir = tempdir().unwrap();
        let db = sled::open(dir.path()).unwrap();

        let schema = default_penumbra_schema();

        // Store
        store_schema(&db, &schema).unwrap();

        // Retrieve
        let retrieved = get_schema(&db).unwrap();

        assert_eq!(schema, retrieved);
    }

    #[test]
    fn test_default_schema_when_none_stored() {
        let dir = tempdir().unwrap();
        let db = sled::open(dir.path()).unwrap();

        // Should return default schema
        let schema = get_schema(&db).unwrap();
        assert_eq!(schema.chain_id, "penumbra-1");
        assert!(schema.actions.contains_key(&61)); // TokenFactoryCreate
    }

    #[test]
    fn test_has_schema() {
        let dir = tempdir().unwrap();
        let db = sled::open(dir.path()).unwrap();

        assert!(!has_schema(&db).unwrap());

        store_schema(&db, &default_penumbra_schema()).unwrap();

        assert!(has_schema(&db).unwrap());
    }
}
