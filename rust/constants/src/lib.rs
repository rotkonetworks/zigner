//! Constants used throughout in [Zigner](https://github.com/rotkonetworks/zigner).
//!
//! Zigner uses the **cold** database, generated during the build
//! (`db_handling`, `make_cold_release`) and then operated on the device.
//!
//! Cold database contains following trees:
//!
//! - [`SPECSTREE`], with network specs
//! - [`ADDRTREE`], with user addresses public information
//! - [`SETTREE`], containing Vault danger status and schema version
//! - [`HISTORY`], with history log
//! - Zcash, Penumbra, FROST, anchor-verifier and contacts trees
//!
//! Databases written before Substrate signing was removed also have
//! [`METATREE`], [`VERIFIERS`] and [`TRANSACTION`], and [`TYPES`] /
//! [`GENERALVERIFIER`] entries in [`SETTREE`]. Nothing reads them; the names
//! are kept for the migration that will drop them.
//!
//! Also here: recurring test seed phrase for Alice, and QR graphic settings
//! used for both static and animated PNG QR codes.

#![deny(rustdoc::broken_intra_doc_links)]

pub mod test_values;

/// Default folder for cold database generated during the Vault build
pub const COLD_DB_NAME_RELEASE: &str = "../database/database_cold_release";

/// Tree name for the tree storing the network specs in cold database
pub const SPECSTREE: &[u8] = b"chainspecs";

/// Tree name for the tree that stored the network verifiers information in
/// cold database. Legacy, no longer read.
pub const VERIFIERS: &[u8] = b"verifiers";

/// Tree name for the tree that stored the network metadata. Legacy, no longer
/// read.
pub const METATREE: &[u8] = b"metadata";

/// Tree name for the tree storing user addresses associated public
/// information in cold database
pub const ADDRTREE: &[u8] = b"addresses";

/// Tree that held Penumbra addresses up to 0.12.0. Those addresses came from a
/// non-standard derivation that no Penumbra key owns (zigner#35); the tree is
/// never read again and is dropped when a fixed address is stored.
pub const PENUMBRA_ADDRS_UNSPENDABLE: &[u8] = b"penumbra_addresses";

/// Tree storing Penumbra receive addresses derived with penumbra-sdk.
/// Key: hex-encoded key id (see `db_handling::penumbra::key_id`), Value:
/// bech32m address string
pub const PENUMBRA_RECEIVE_ADDRS: &[u8] = b"penumbra_receive_addresses";

/// Tree name for the tree storing Zcash unified addresses
/// Key: hex-encoded FVK prefix (32 bytes), Value: unified address string
pub const ZCASH_ADDRESS_TREE: &[u8] = b"zcash_addresses";

/// Tree name for the tree storing verified Zcash notes (synced via QR)
/// Key: nullifier (32 bytes), Value: CBOR-encoded note data
pub const ZCASH_NOTES_TREE: &[u8] = b"zcash_notes";

/// Tree name for the tree storing FROST multisig key packages
/// Key: wallet_id (8 bytes, truncated blake3 of public_key_package)
/// Value: JSON-encoded FrostWalletData
pub const FROST_KEYS_TREE: &[u8] = b"frost_keys";

/// Tree name for the tree storing fingerprints of consumed FROST signing
/// nonces. Persisting these across app restarts is critical: an attacker
/// who force-quits the app between commitment and signing could otherwise
/// replay an already-used nonce against a different message, leaking the
/// FROST private key. Key: SHA-256(nonces_hex) (32 bytes). Value: 8-byte
/// little-endian unix timestamp.
pub const FROST_NONCES_TREE: &[u8] = b"frost_used_nonces";

/// Tree name for the tree storing trusted Zcash anchor-attestation
/// verifier ed25519 public keys. The signer trusts ANY enabled entry to
/// attest that an anchor matches the chain — supporting self-hosted
/// zidecar instances alongside the built-in default. Key: 32-byte
/// ed25519 pubkey. Value: JSON `{label, added_at, source, enabled}`.
/// Bootstrapped from `ROTKO_ZCASH_VERIFIER` on first DB init when the
/// tree is empty.
pub const ANCHOR_VERIFIERS_TREE: &[u8] = b"anchor_verifiers";

/// Tree name for the tree storing contacts (address book)
/// Key: address string bytes, Value: JSON-encoded contact metadata
pub const CONTACTS_TREE: &[u8] = b"contacts";

/// Rotko Networks ed25519 public key for Zcash anchor verification.
/// The signer trusts this key to attest that anchors come from the real chain.
/// Same trust model as Parity's verifier key in Polkadot Vault.
///
pub const ROTKO_ZCASH_VERIFIER: [u8; 32] = [
    0x5f, 0xbc, 0xaa, 0xbe, 0x9b, 0x00, 0xd2, 0x3a, 0x2b, 0xeb, 0xb6, 0x37, 0x0f, 0x1a, 0xcb, 0xa3,
    0x0e, 0x61, 0x85, 0x4e, 0xce, 0x40, 0x20, 0x0d, 0xf6, 0xf3, 0x23, 0xd6, 0xa2, 0x1a, 0xc7, 0x84,
];

/// Tree name for the tree storing database settings
///
/// The settings tree contains Vault danger status and database schema
/// version.
pub const SETTREE: &[u8] = b"settings";

/// Tree name for the tree that temporarily stored Substrate transaction
/// entries. Legacy, no longer read.
pub const TRANSACTION: &[u8] = b"transaction";

/// Tree name for the tree storing Vault history
pub const HISTORY: &[u8] = b"history";

/// Key in settings tree [`SETTREE`] for Substrate types information.
/// Legacy, no longer read.
pub const TYPES: &[u8] = b"types";

/// Key in settings tree [`SETTREE`] for the general verifier of Substrate
/// updates. Legacy, no longer read.
pub const GENERALVERIFIER: &[u8] = b"general_verifier";

/// Key in settings tree [`SETTREE`] for Vault danger status
pub const DANGER: &[u8] = b"dangerous_encounter";

/// Key in settings tree [`SETTREE`] for Vault database schema version
pub const SCHEMA_VERSION: &[u8] = b"schema_version";

/// Maximum number of words displayed to user based on user input in seed
/// recovery process
pub const MAX_WORDS_DISPLAY: usize = 8;

/// Number of entries on log history page
pub const HISTORY_PAGE_SIZE: usize = 20;

/// Alice seed phrase
pub const ALICE_SEED_PHRASE: &str =
    "bottom drive obey lake curtain smoke basket hold race lonely fit walk";

/// Data chunk size for fountain QR code generation
pub const CHUNK_SIZE: u16 = 1072;

/// Main color for QR codes (both static and animated ones)
pub const MAIN_COLOR: [u8; 3] = [0x00, 0x00, 0x00];

/// Main color for **dangerous** QR codes (static only, in Vault)
pub const MAIN_COLOR_DANGER: [u8; 3] = [0xe6, 0x00, 0x7a];

/// Background color for QR codes (both static and animated ones)
pub const BACK_COLOR: [u8; 3] = [0xff, 0xff, 0xff];

/// Color palette for QR codes (both static and animated ones)
pub fn qr_palette() -> Vec<u8> {
    [MAIN_COLOR.to_vec(), BACK_COLOR.to_vec()].concat()
}

/// Color palette for **dangerous** QR codes (static only, in Vault)
pub fn qr_palette_danger() -> Vec<u8> {
    [MAIN_COLOR_DANGER.to_vec(), BACK_COLOR.to_vec()].concat()
}

/// Scaling factor for QR codes (size of QR code dot, in pixels)
pub const SCALING: i32 = 4;

/// Numerator of the fraction of time (in seconds) for which the frame in the
/// animated QR code is displayed
pub const FPS_NOM: u16 = 1;

/// Denominator of the fraction of time (in seconds) for which the frame in the
/// animated QR code is displayed
pub const FPS_DEN: u16 = 15;

/// Width of the QR code border, in QR code dots
pub const BORDER: i32 = 4;

/// Current database schema version
pub const LIVE_SCHEMA_VERSION: u32 = 1;
