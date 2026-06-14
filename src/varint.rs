//! Variable-length integer encoding used by the SOE protocol.
//!
//! The protocol uses two subtly different variable-length integer schemes:
//!
//! * [`multi_packet`] — used to prefix sub-packets within a `MultiPacket`
//!   (Appendix B). A single-byte length may be up to `0xFF` inclusive, relying on
//!   every core OP code beginning with `0x00` (given big endian) to disambiguate a
//!   single-byte `0xFF` from the multi-byte forms.
//! * [`data_bundle`] — used to prefix data buffers within a reliable-data bundle
//!   (Appendix C). A single-byte length may only be up to `0xFE`.
//!
//! Larger values are encoded as three bytes (`0xFF` + big-endian `u16`) or seven
//! bytes (`0xFF 0xFF 0xFF` + big-endian `u32`).

use crate::error::{Error, Result};
use crate::io::{BinaryReader, BinaryWriter};

fn write_multibyte(writer: &mut BinaryWriter, length: u32) -> Result<()> {
    if length < 0xFFFF {
        writer.write_u8(0xFF)?;
        writer.write_u16(length as u16)
    } else {
        writer.write_u8(0xFF)?;
        writer.write_u8(0xFF)?;
        writer.write_u8(0xFF)?;
        writer.write_u32(length)
    }
}

/// The MultiPacket variable-length integer scheme (Appendix B).
pub mod multi_packet {
    use super::*;

    /// Returns the number of bytes a value of `length` occupies under this scheme.
    pub fn encoded_size(length: u32) -> usize {
        if length <= 0xFF {
            1
        } else if length < 0xFFFF {
            3
        } else {
            7
        }
    }

    /// Reads a variable-length value from `reader`, advancing it past the value.
    pub fn read(reader: &mut BinaryReader) -> Result<u32> {
        let b0 = reader.peek(0).ok_or(Error::BufferTooShort {
            needed: 1,
            available: 0,
        })?;

        if b0 < 0xFF {
            reader.skip(1)?;
            Ok(b0 as u32)
        } else if reader.peek(1) == Some(0) {
            // The implied 0x00 in front of all core OP codes (big endian) signals a
            // single-byte length value of 0xFF.
            reader.skip(1)?;
            Ok(0xFF)
        } else if reader.peek(1) == Some(0xFF) && reader.peek(2) == Some(0xFF) {
            reader.skip(3)?;
            Ok(reader.read_u32()?)
        } else {
            reader.skip(1)?;
            Ok(reader.read_u16()? as u32)
        }
    }

    /// Writes a variable-length value to `writer`, advancing it past the value.
    pub fn write(writer: &mut BinaryWriter, length: u32) -> Result<()> {
        if length <= 0xFF {
            writer.write_u8(length as u8)
        } else {
            write_multibyte(writer, length)
        }
    }
}

/// The data-bundle variable-length integer scheme (Appendix C).
pub mod data_bundle {
    use super::*;

    /// Returns the number of bytes a value of `length` occupies under this scheme.
    pub fn encoded_size(length: u32) -> usize {
        if length < 0xFF {
            1
        } else if length < 0xFFFF {
            3
        } else {
            7
        }
    }

    /// Reads a variable-length value from `reader`, advancing it past the value.
    pub fn read(reader: &mut BinaryReader) -> Result<u32> {
        let b0 = reader.peek(0).ok_or(Error::BufferTooShort {
            needed: 1,
            available: 0,
        })?;

        if b0 < 0xFF {
            reader.skip(1)?;
            Ok(b0 as u32)
        } else if reader.peek(1) == Some(0xFF) && reader.peek(2) == Some(0xFF) {
            reader.skip(3)?;
            Ok(reader.read_u32()?)
        } else {
            reader.skip(1)?;
            Ok(reader.read_u16()? as u32)
        }
    }

    /// Writes a variable-length value to `writer`, advancing it past the value.
    pub fn write(writer: &mut BinaryWriter, length: u32) -> Result<()> {
        if length < 0xFF {
            writer.write_u8(length as u8)
        } else {
            write_multibyte(writer, length)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn multi_packet_encoded_size_boundaries() {
        assert_eq!(multi_packet::encoded_size(0), 1);
        assert_eq!(multi_packet::encoded_size(0xFF), 1);
        assert_eq!(multi_packet::encoded_size(0x100), 3);
        assert_eq!(multi_packet::encoded_size(0xFFFE), 3);
        assert_eq!(multi_packet::encoded_size(0xFFFF), 7);
    }

    #[test]
    fn data_bundle_encoded_size_boundaries() {
        assert_eq!(data_bundle::encoded_size(0), 1);
        assert_eq!(data_bundle::encoded_size(0xFE), 1);
        assert_eq!(data_bundle::encoded_size(0xFF), 3);
        assert_eq!(data_bundle::encoded_size(0xFFFE), 3);
        assert_eq!(data_bundle::encoded_size(0xFFFF), 7);
    }

    #[test]
    fn data_bundle_round_trip() {
        for &len in &[0u32, 1, 0xFE, 0xFF, 0x100, 0xFFFE, 0xFFFF, 0x1_0000, 0xFFFF_FFFF] {
            let mut buf = [0u8; 8];
            let mut w = BinaryWriter::new(&mut buf);
            data_bundle::write(&mut w, len).unwrap();
            let written = w.offset();
            assert_eq!(written, data_bundle::encoded_size(len), "size len={len:#x}");
            let mut r = BinaryReader::new(&buf);
            let got = data_bundle::read(&mut r).unwrap();
            assert_eq!(got, len, "len={len:#x}");
            assert_eq!(r.offset(), written);
        }
    }

    #[test]
    fn multi_packet_round_trip() {
        // The single-byte 0xFF case relies on a following 0x00 (the high byte of a
        // sub-packet OP code); the buffer is zero-initialized so this holds.
        for &len in &[0u32, 1, 0xFE, 0xFF, 0x100, 0xFFFE, 0xFFFF, 0x1_0000, 0xFFFF_FFFF] {
            let mut buf = [0u8; 9];
            let mut w = BinaryWriter::new(&mut buf);
            multi_packet::write(&mut w, len).unwrap();
            let written = w.offset();
            assert_eq!(written, multi_packet::encoded_size(len), "size len={len:#x}");
            let mut r = BinaryReader::new(&buf);
            let got = multi_packet::read(&mut r).unwrap();
            assert_eq!(got, len, "len={len:#x}");
            assert_eq!(r.offset(), written);
        }
    }

    #[test]
    fn multi_packet_single_byte_ff() {
        let mut buf = [0u8; 4];
        let mut w = BinaryWriter::new(&mut buf);
        multi_packet::write(&mut w, 0xFF).unwrap();
        assert_eq!(w.offset(), 1);
        assert_eq!(buf[0], 0xFF);
        let mut r = BinaryReader::new(&buf);
        assert_eq!(multi_packet::read(&mut r).unwrap(), 0xFF);
        assert_eq!(r.offset(), 1);
    }
}
