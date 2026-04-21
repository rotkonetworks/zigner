//! Contact storage (address book)
//!
//! Stores address → label mappings in sled. Used during PCZT review to show
//! human-readable names instead of raw addresses. Exported/imported via QR.

use crate::error::{Error, Result};
use constants::CONTACTS_TREE;

/// A single contact entry.
#[derive(Debug, Clone)]
pub struct Contact {
    pub address: String,
    pub label: String,
    pub chain_id: String,
}

/// Maximum number of contacts to prevent OOM from malicious input.
const MAX_CONTACTS: usize = 10_000;

/// Maximum length for any single contact field (address, label, chain_id).
const MAX_FIELD_LEN: usize = 1024;

/// Store a contact. Overwrites if address already exists.
/// Rejects fields containing null bytes or exceeding length limits.
pub fn store_contact(database: &sled::Db, contact: &Contact) -> Result<()> {
    validate_contact(contact)?;
    let tree = database.open_tree(CONTACTS_TREE)?;
    // value = "chain_id\0label" — null bytes in fields are rejected by validate_contact
    let value = format!("{}\0{}", contact.chain_id, contact.label);
    tree.insert(contact.address.as_bytes(), value.as_bytes())?;
    Ok(())
}

fn validate_contact(contact: &Contact) -> Result<()> {
    for (name, field) in [
        ("address", &contact.address),
        ("label", &contact.label),
        ("chain_id", &contact.chain_id),
    ] {
        if field.contains('\0') {
            return Err(Error::Other(anyhow::anyhow!(
                "contact {name} must not contain null bytes"
            )));
        }
        if field.len() > MAX_FIELD_LEN {
            return Err(Error::Other(anyhow::anyhow!(
                "contact {name} exceeds max length ({} > {MAX_FIELD_LEN})",
                field.len()
            )));
        }
    }
    if contact.address.is_empty() {
        return Err(Error::Other(anyhow::anyhow!(
            "contact address must not be empty"
        )));
    }
    Ok(())
}

/// Get all contacts.
pub fn get_contacts(database: &sled::Db) -> Result<Vec<Contact>> {
    let tree = database.open_tree(CONTACTS_TREE)?;
    let mut contacts = Vec::new();
    for entry in tree.iter() {
        let (key, value) = entry?;
        let address = String::from_utf8(key.to_vec())
            .map_err(|e| Error::Other(anyhow::anyhow!("bad contact key: {e}")))?;
        let raw = String::from_utf8(value.to_vec())
            .map_err(|e| Error::Other(anyhow::anyhow!("bad contact value: {e}")))?;
        let (chain_id, label) = raw.split_once('\0').unwrap_or(("", &raw));
        contacts.push(Contact {
            address,
            label: label.to_string(),
            chain_id: chain_id.to_string(),
        });
    }
    Ok(contacts)
}

/// Look up a contact by address. Returns the label if found.
pub fn get_contact_label(database: &sled::Db, address: &str) -> Result<Option<String>> {
    let tree = database.open_tree(CONTACTS_TREE)?;
    match tree.get(address.as_bytes())? {
        Some(value) => {
            let raw = String::from_utf8(value.to_vec())
                .map_err(|e| Error::Other(anyhow::anyhow!("bad contact value: {e}")))?;
            let label = raw.split_once('\0').map_or(&*raw, |(_, l)| l);
            Ok(Some(label.to_string()))
        }
        None => Ok(None),
    }
}

/// Delete a contact by address.
pub fn delete_contact(database: &sled::Db, address: &str) -> Result<()> {
    let tree = database.open_tree(CONTACTS_TREE)?;
    tree.remove(address.as_bytes())?;
    Ok(())
}

/// Delete all contacts.
pub fn clear_contacts(database: &sled::Db) -> Result<()> {
    let tree = database.open_tree(CONTACTS_TREE)?;
    tree.clear()?;
    Ok(())
}

/// Import contacts from a list, merging with existing.
/// Validates each contact and rejects batches exceeding MAX_CONTACTS.
pub fn import_contacts(database: &sled::Db, contacts: &[Contact]) -> Result<usize> {
    if contacts.len() > MAX_CONTACTS {
        return Err(Error::Other(anyhow::anyhow!(
            "too many contacts ({} > {MAX_CONTACTS})",
            contacts.len()
        )));
    }
    let tree = database.open_tree(CONTACTS_TREE)?;
    let mut count = 0;
    for contact in contacts {
        validate_contact(contact)?;
        let value = format!("{}\0{}", contact.chain_id, contact.label);
        tree.insert(contact.address.as_bytes(), value.as_bytes())?;
        count += 1;
    }
    Ok(count)
}
