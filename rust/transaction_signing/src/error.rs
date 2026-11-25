/// Transaction signing result.
pub type Result<T> = std::result::Result<T, Error>;

/// Transaction signing error.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("An error occured: {0}.")]
    Other(#[from] anyhow::Error),

    /// Penumbra key derivation error
    #[error("Penumbra key derivation error: {0}")]
    PenumbraKeyDerivation(String),

    /// Penumbra signing error
    #[error("Penumbra signing error: {0}")]
    PenumbraSigning(String),

    /// Penumbra effect hash error
    #[error("Penumbra effect hash error: {0}")]
    PenumbraEffectHash(String),

    /// Zcash key derivation error
    #[error("Zcash key derivation error: {0}")]
    ZcashKeyDerivation(String),

    /// Zcash signing error
    #[error("Zcash signing error: {0}")]
    ZcashSigning(String),

    /// Zcash parsing error
    #[error("Zcash parsing error: {0}")]
    ZcashParsing(String),
}
