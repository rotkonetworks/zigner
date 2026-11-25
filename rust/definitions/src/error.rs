use hex::FromHexError;
use sp_core::H256;

use crate::{
    crypto::Encryption,
    keyring::{AddressKey, NetworkSpecsKey},
};

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    HexDecodingError(#[from] FromHexError),

    #[error(transparent)]
    CodecError(#[from] parity_scale_codec::Error),

    #[error(transparent)]
    Ss58(#[from] sp_core::crypto::PublicError),

    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error(transparent)]
    LibSecp(#[from] libsecp256k1::Error),

    /// Received public key length is different from the one expected for
    /// given encryption algorithm.
    #[error("Public key length does not match the encryption.")]
    WrongPublicKeyLength,

    /// `Error` when there is encryption mismatch between one of
    /// [`NetworkSpecsKey`] in `network_id` field of [`AddressDetails`] and the
    /// `encryption` field of [`AddressDetails`]
    ///
    /// [`AddressDetails`]: crate::users::AddressDetails
    #[error(
        "Address details entry with address key {} has not matching encryption {}.",
        hex::encode(address_key.key()),
        encryption.show(),
    )]
    EncryptionMismatch {
        address_key: AddressKey,
        encryption: Encryption,
    },

    /// [`NetworkSpecsKey`] is built using network genesis hash and [`Encryption`].
    /// [`OrderedNetworkSpecs`](crate::network_specs::OrderedNetworkSpecs) entry stored under
    /// this `NetworkSpecsKey` in `SPECSTREE` tree of the cold database
    /// contains `genesis_hash` field with a different genesis hash.
    #[error(
        "Network specs (NetworkSpecs) entry with network specs key {} \
        has not matching genesis hash {}.",
        hex::encode(network_specs_key.key()),
        hex::encode(genesis_hash),
    )]
    SpecsGenesisHashMismatch {
        network_specs_key: NetworkSpecsKey,
        genesis_hash: H256,
    },

    /// [`NetworkSpecsKey`] is built using network genesis hash and [`Encryption`].
    /// [`OrderedNetworkSpecs`](crate::network_specs::OrderedNetworkSpecs)
    /// entry stored under this `NetworkSpecsKey` in `SPECSTREE` contains
    /// `encryption` field with a different [`Encryption`].
    #[error(
        "specs encryption mismatch {} {}`",
        hex::encode(network_specs_key.key()),
        encryption.show()
    )]
    SpecsToSendEncryptionMismatch {
        network_specs_key: NetworkSpecsKey,
        encryption: Encryption,
    },

    #[error("Cannot convert {0} to valid encryption.")]
    UnknownEncryption(String),
}
