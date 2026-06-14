//! Error types for the SOE protocol crate.

use std::result::Result as StdResult;

/// A specialized [`Result`] type for SOE protocol operations.
pub type Result<T> = StdResult<T, Error>;

/// Errors that can occur while encoding, decoding or processing SOE protocol data.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// A buffer was too short to read or write the expected data.
    #[error("buffer too short: needed {needed} bytes but only {available} available")]
    BufferTooShort {
        /// The number of bytes required.
        needed: usize,
        /// The number of bytes available.
        available: usize,
    },

    /// A value did not fit within the expected bounds.
    #[error("value out of range: {0}")]
    OutOfRange(String),

    /// A zlib (de)compression error occurred.
    #[error("zlib error: {0}")]
    Zlib(#[from] std::io::Error),
}
