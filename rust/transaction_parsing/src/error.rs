/// Transaction parsing result.
pub type Result<T> = std::result::Result<T, Error>;

/// Transaction parsing error.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Definitions(#[from] definitions::error::Error),

    /// Received transaction is unexpectedly short, more bytes were expected.
    #[error("Input is too short.")]
    TooShort,

    /// Every signing request starts with the 0x53 prelude byte.
    ///
    /// Associated data is the first byte of the received payload, in hex.
    #[error("Transaction is expected to start with 0x53, this one starts with 0x{0}")]
    UnexpectedPrelude(String),

    /// Penumbra transaction parsing error
    #[error("Penumbra parsing error: {0}")]
    PenumbraParseError(String),
}
