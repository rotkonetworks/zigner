//! Network specs and verifier types
//!
//! Vault could be used only for networks introduced to the database. Each
//! network has a set of parameters, its network specs; the cold database
//! stores [`OrderedNetworkSpecs`] in `SPECSTREE`, and keys point at them by
//! [`NetworkSpecsKey`](crate::keyring::NetworkSpecsKey).
//!
//! [`Verifier`], [`VerifierValue`] and [`ValidCurrentVerifier`] are kept
//! because history log events written by older releases (when Vault still
//! accepted signed Substrate network and metadata updates) contain them.
use parity_scale_codec::{Decode, Encode};
use sled::IVec;
use sp_core::H256;
use sp_runtime::MultiSigner;

use crate::{
    error::{Error, Result},
    helpers::IdenticonStyle,
    navigation::Identicon,
};

use crate::helpers::{
    make_identicon_from_multisigner, multisigner_to_encryption, multisigner_to_public,
};
use crate::{crypto::Encryption, keyring::NetworkSpecsKey};

use crate::navigation::MVerifierDetails;

/// Network parameters stored SCALE-encoded in the **cold** database
/// `SPECSTREE` tree under [`NetworkSpecsKey`]
///
/// These network parameters must be in Vault database for the Vault to be
/// able to operate with this network.
#[derive(Decode, Encode, PartialEq, Eq, Debug, Clone)]
pub struct OrderedNetworkSpecs {
    pub specs: NetworkSpecs,

    /// Order in which the network is displayed by Vault
    pub order: u8,
}

/// Network parameters stored SCALE-encoded in the **hot** database
/// `SPECSTREEPREP` tree under [`NetworkSpecsKey`] and sent as QR code
/// in `add_specs` messages
///
/// These network parameters are sufficient to add network into Vault database.
#[derive(Decode, Encode, PartialEq, Eq, Debug, Clone)]
pub struct NetworkSpecs {
    /// Network-specific prefix for address representation in
    /// [base58 format](https://docs.rs/sp-core/6.0.0/sp_core/crypto/trait.Ss58Codec.html#method.to_ss58check_with_version)  
    pub base58prefix: u16,

    /// Network-associated color.  
    /// Historically is there, not doing much at the moment.  
    pub color: String,

    /// Order of magnitude, by which the token unit exceeds the balance integer unit.  
    /// Is used to display balance-related values properly.  
    pub decimals: u8,

    /// Encryption algorithm the network uses  
    pub encryption: Encryption,

    /// Network genesis hash  
    pub genesis_hash: H256,

    /// Network associated logo  
    pub logo: String,

    /// Network name, as it appears in network metadata  
    pub name: String,

    /// Default derivation path for addresses in this network  
    pub path_id: String,

    /// Network-associated secondary color.  
    /// Historically is there, not doing much at the moment.  
    pub secondary_color: String,

    /// Network title, as it appears in Vault menus.
    pub title: String,

    /// Token name, to display balance-related values properly.  
    pub unit: String,
}

impl OrderedNetworkSpecs {
    /// Gets [`OrderedNetworkSpecs`] from [`NetworkSpecsKey`] and associated value
    /// from cold database tree `SPECSTREE`  
    ///
    /// Checks that there is no genesis hash or encryption mismatch between
    /// key and specs content.  
    pub fn from_entry_with_key_checked(
        network_specs_key: &NetworkSpecsKey,
        network_specs_encoded: IVec,
    ) -> Result<Self> {
        let (genesis_hash_vec, encryption) = network_specs_key.genesis_hash_encryption()?;
        let ordered_specs = Self::decode(&mut &network_specs_encoded[..])?;
        let network_specs = &ordered_specs.specs;
        if &genesis_hash_vec[..] != network_specs.genesis_hash.as_bytes() {
            return Err(Error::SpecsGenesisHashMismatch {
                network_specs_key: network_specs_key.to_owned(),
                genesis_hash: network_specs.genesis_hash,
            });
        }
        if encryption != network_specs.encryption {
            return Err(Error::SpecsToSendEncryptionMismatch {
                network_specs_key: network_specs_key.to_owned(),
                encryption: network_specs.encryption,
            });
        }
        Ok(ordered_specs)
    }

    /// Gets [`OrderedNetworkSpecs`] from cold database tree `SPECSTREE` (key, value)
    /// entry  
    ///
    /// Checks that there is no genesis hash or encryption mismatch between
    /// key and specs content.  
    pub fn from_entry_checked(
        (network_specs_key_vec, network_specs_encoded): (IVec, IVec),
    ) -> Result<Self> {
        let network_specs_key = NetworkSpecsKey::from_ivec(&network_specs_key_vec);
        Self::from_entry_with_key_checked(&network_specs_key, network_specs_encoded)
    }
}

/// Verifier information
///
/// Either real verifier or information that there is no verifier.
#[derive(Decode, Encode, PartialEq, Eq, Debug, Clone)]
pub struct Verifier {
    pub v: Option<VerifierValue>,
}

/// Information on known and existing verifier  
///
/// Verifier public key with associated encryption algorithm.
#[derive(Decode, Encode, PartialEq, Eq, Debug, Clone)]
pub enum VerifierValue {
    /// public key for standard substrate-compatible encryption algorithms  
    Standard { m: MultiSigner },
}

impl Verifier {
    /// Get the [`MVerifierDetails`] for UI to show.
    pub fn show_card(&self) -> MVerifierDetails {
        match &self.v {
            Some(a) => a.show_card(),
            None => MVerifierDetails {
                public_key: String::new(),
                identicon: Identicon::default(),
                encryption: String::new(),
            },
        }
    }

    /// Display [`Verifier`] in human-readable format, for errors  
    pub fn show_error(&self) -> String {
        match &self.v {
            Some(a) => a.show_error(),
            None => String::from("none"),
        }
    }
}

impl VerifierValue {
    /// Get the [`MVerifierDetails`] for UI to show.
    pub fn show_card(&self) -> MVerifierDetails {
        match &self {
            VerifierValue::Standard { m } => {
                let public_key = hex::encode(multisigner_to_public(m));
                let encryption = multisigner_to_encryption(m).show();
                let identicon = make_identicon_from_multisigner(m, IdenticonStyle::Dots);

                MVerifierDetails {
                    public_key,
                    identicon,
                    encryption,
                }
            }
        }
    }

    /// Display [`VerifierValue`] in human-readable format, for errors  
    pub fn show_error(&self) -> String {
        match &self {
            VerifierValue::Standard {
                m: MultiSigner::Ed25519(x),
            } => {
                format!("public key: {}, encryption: ed25519", hex::encode(x.0))
            }
            VerifierValue::Standard {
                m: MultiSigner::Sr25519(x),
            } => {
                format!("public key: {}, encryption: sr25519", hex::encode(x.0))
            }
            VerifierValue::Standard {
                m: MultiSigner::Ecdsa(x),
            } => {
                format!("public key: {}, encryption: ecdsa", hex::encode(x.0))
            }
        }
    }
}

/// Possible variants of valid current network verifier
///
/// Could be general verifier (by default for networks Polkadot, Kusama, Westend),
/// or custom verifier.
#[derive(Decode, Encode, PartialEq, Eq, Debug, Clone)]
pub enum ValidCurrentVerifier {
    /// Network has general verifier
    General,

    /// Network has some other verifier, different from the general one
    Custom { v: Verifier },
}
