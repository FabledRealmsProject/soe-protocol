//! Zlib (de)compression helpers, used for optional packet compression.
//!
//! The SOE protocol compresses the wrapped packet data using zlib at the default
//! compression level when compression is negotiated for a session.

use std::io::{Read, Write};

use flate2::Compression;
use flate2::read::ZlibDecoder;
use flate2::write::ZlibEncoder;

use crate::error::Result;

/// Compresses `data` using zlib at the default compression level.
pub fn deflate(data: &[u8]) -> Result<Vec<u8>> {
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(data)?;
    Ok(encoder.finish()?)
}

/// Decompresses zlib-compressed `data`.
pub fn inflate(data: &[u8]) -> Result<Vec<u8>> {
    let mut decoder = ZlibDecoder::new(data);
    let mut out = Vec::new();
    decoder.read_to_end(&mut out)?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deflate_inflate_round_trip() {
        let original = b"The quick brown fox jumps over the lazy dog. ".repeat(16);
        let compressed = deflate(&original).unwrap();
        let decompressed = inflate(&compressed).unwrap();
        assert_eq!(decompressed, original);
    }

    #[test]
    fn empty_round_trip() {
        let compressed = deflate(&[]).unwrap();
        assert_eq!(inflate(&compressed).unwrap(), Vec::<u8>::new());
    }
}
