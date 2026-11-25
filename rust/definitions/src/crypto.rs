//! Encryption algorithms
//!
//! Each address in Vault has an associated encryption algorithm
//! [`Encryption`]. This is reflected in [`AddressDetails`](crate::users::AddressDetails)
//! field `encryption` and in corresponding database key
//! [`AddressKey`](crate::keyring::AddressKey). Networks carry one too, in
//! [`NetworkSpecs`](crate::network_specs::NetworkSpecs) and in
//! [`NetworkSpecsKey`](crate::keyring::NetworkSpecsKey); an address is
//! associated with a network only under a matching [`Encryption`].
//!
//! The key layer stores every public key as a
//! [`MultiSigner`](https://docs.rs/sp-runtime/6.0.0/sp_runtime/enum.MultiSigner.html);
//! the Zcash, Penumbra and Cosmos variants of [`Encryption`] reuse its
//! 32/33-byte slots as identifiers.
use parity_scale_codec::{Decode, Encode};

use crate::error::Error;
use crate::helpers::IdenticonStyle;

/// Encryption algorithm
///
/// Lists all encryption algorithms supported by Substrate
#[derive(Copy, Clone, Debug, Decode, Encode, PartialEq, Eq)]
pub enum Encryption {
    Ed25519,
    Sr25519,
    Ecdsa,
    Ethereum,
    Penumbra,
    /// Zcash - uses ZIP-32 key derivation for shielded transactions
    Zcash,
    /// Ledger Ed25519 - uses SLIP-10/BIP32-Ed25519 derivation instead of substrate derivation
    LedgerEd25519,
    /// Cosmos SDK chains - uses BIP44 secp256k1 with bech32 addresses
    /// Path: m/44'/118'/account'/0/0 (or chain-specific coin type)
    Cosmos,
    /// Bitcoin - uses BIP-84 (native segwit) or BIP-86 (taproot)
    /// Path: m/84'/0'/account'/change/index or m/86'/0'/account'/change/index
    /// Schnorr signatures (BIP-340) for taproot, ECDSA for legacy/segwit
    Bitcoin,
    /// Nostr - uses NIP-06 key derivation with Schnorr signatures
    /// Path: m/44'/1237'/account'/0/0
    Nostr,
    /// AT Protocol (Bluesky) - uses secp256k1 with did:plc identifiers
    /// Path: m/44'/29'/account'/0/0 (using coin type 29 for AT Protocol)
    /// ECDSA signatures for repo commits and identity operations
    AtProtocol,
}

impl Encryption {
    /// Display the encryption
    ///
    /// This is used both in error printing and in json data exports
    pub fn show(&self) -> String {
        match &self {
            Encryption::Ed25519 => String::from("ed25519"),
            Encryption::Sr25519 => String::from("sr25519"),
            Encryption::Ecdsa => String::from("ecdsa"),
            Encryption::Ethereum => String::from("ethereum"),
            Encryption::Penumbra => String::from("penumbra"),
            Encryption::Zcash => String::from("zcash"),
            Encryption::LedgerEd25519 => String::from("ledger_ed25519"),
            Encryption::Cosmos => String::from("cosmos"),
            Encryption::Bitcoin => String::from("bitcoin"),
            Encryption::Nostr => String::from("nostr"),
            Encryption::AtProtocol => String::from("atproto"),
        }
    }

    /// The style to use for identicons.
    ///
    /// Dots ss58
    /// Blockies for ethereum h160 addrs.
    pub fn identicon_style(&self) -> IdenticonStyle {
        match self {
            Encryption::Ethereum => IdenticonStyle::Blockies,
            Encryption::Penumbra => IdenticonStyle::Dots, // using dots for now
            Encryption::Zcash => IdenticonStyle::Dots,    // using dots for now
            Encryption::LedgerEd25519 => IdenticonStyle::Dots,
            Encryption::Cosmos => IdenticonStyle::Dots, // could use blockies since same curve as ETH
            Encryption::Bitcoin => IdenticonStyle::Dots, // Bitcoin addresses
            Encryption::Nostr => IdenticonStyle::Dots,  // Nostr npub
            Encryption::AtProtocol => IdenticonStyle::Dots, // AT Protocol did:plc
            _ => IdenticonStyle::Dots,
        }
    }
}

impl TryFrom<String> for Encryption {
    type Error = Error;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        match value.to_lowercase().as_str() {
            "ed25519" => Ok(Encryption::Ed25519),
            "sr25519" => Ok(Encryption::Sr25519),
            "ecdsa" => Ok(Encryption::Ecdsa),
            "ethereum" => Ok(Encryption::Ethereum),
            "penumbra" => Ok(Encryption::Penumbra),
            "zcash" => Ok(Encryption::Zcash),
            "ledger_ed25519" => Ok(Encryption::LedgerEd25519),
            "cosmos" => Ok(Encryption::Cosmos),
            "bitcoin" => Ok(Encryption::Bitcoin),
            "nostr" => Ok(Encryption::Nostr),
            "atproto" | "atprotocol" | "bluesky" => Ok(Encryption::AtProtocol),
            _ => Err(Error::UnknownEncryption(value)),
        }
    }
}
