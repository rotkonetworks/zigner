#![deny(unused_crate_dependencies)]
#![deny(rustdoc::broken_intra_doc_links)]

// Used by the integration tests in tests/, which share dev-dependencies.
#[cfg(test)]
use db_handling as _;

mod error;
pub use error::{Error, Result};

// penumbra signing module
#[cfg(feature = "penumbra")]
pub mod penumbra;
#[cfg(feature = "penumbra")]
pub mod penumbra_review;
#[cfg(feature = "penumbra")]
pub use penumbra::{
    derive_spend_auth_key as penumbra_derive_spend_auth_key, sign_spend as penumbra_sign_spend,
    sign_transaction as penumbra_sign_transaction, EffectHash as PenumbraEffectHash,
    PenumbraAuthorizationData, SpendKeyBytes as PenumbraSpendKeyBytes, PENUMBRA_BIP44_PATH,
    PENUMBRA_COIN_TYPE,
};

// cosmos signing module
#[cfg(feature = "cosmos")]
pub mod cosmos;
#[cfg(feature = "cosmos")]
pub use cosmos::{sign_cosmos_amino, CosmosSignDocDisplay, CosmosSignRequest};

// zcash signing module
#[cfg(feature = "zcash")]
pub mod zcash;
#[cfg(feature = "zcash")]
pub use zcash::{
    attestation_digest, decode_notes_bundle_from_cbor,
    derive_orchard_fvk as zcash_derive_orchard_fvk,
    derive_transparent_address as zcash_derive_transparent_address, encode_notes_bundle_to_cbor,
    verify_merkle_path, OrchardFullViewingKey as ZcashOrchardFvk,
    OrchardSpendingKey as ZcashOrchardKey, TransparentSpendingKey as ZcashTransparentKey,
    ZcashFvkExportData, ZcashNoteSyncResult, ZcashNoteWithPath, ZcashNotesBundle,
    ZcashVerifiedNote, QR_TYPE_ZCASH_FVK_EXPORT, QR_TYPE_ZCASH_NOTES, ZCASH_COIN_TYPE,
};
