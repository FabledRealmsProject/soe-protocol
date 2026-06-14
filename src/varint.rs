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

fn read_u16_be(data: &[u8], offset: usize) -> Result<u16> {
    if offset + 2 > data.len() {
        return Err(Error::BufferTooShort {
            needed: 2,
            available: data.len().saturating_sub(offset),
        });
    }
    Ok(u16::from_be_bytes([data[offset], data[offset + 1]]))
}

fn read_u32_be(data: &[u8], offset: usize) -> Result<u32> {
    if offset + 4 > data.len() {
        return Err(Error::BufferTooShort {
            needed: 4,
            available: data.len().saturating_sub(offset),
        });
    }
    Ok(u32::from_be_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ]))
}

fn ensure(buffer: &[u8], offset: usize, needed: usize) -> Result<()> {
    if offset + needed > buffer.len() {
        return Err(Error::BufferTooShort {
            needed,
            available: buffer.len().saturating_sub(offset),
        });
    }
    Ok(())
}

fn write_multibyte(buffer: &mut [u8], length: u32, offset: &mut usize) -> Result<()> {
    if length < 0xFFFF {
        ensure(buffer, *offset, 3)?;
        buffer[*offset] = 0xFF;
        buffer[*offset + 1..*offset + 3].copy_from_slice(&(length as u16).to_be_bytes());
        *offset += 3;
    } else {
        ensure(buffer, *offset, 7)?;
        buffer[*offset] = 0xFF;
        buffer[*offset + 1] = 0xFF;
        buffer[*offset + 2] = 0xFF;
        buffer[*offset + 3..*offset + 7].copy_from_slice(&length.to_be_bytes());
        *offset += 7;
    }
    Ok(())
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

    /// Reads a variable-length value at `*offset`, advancing it past the value.
    pub fn read(data: &[u8], offset: &mut usize) -> Result<u32> {
        let o = *offset;
        if o >= data.len() {
            return Err(Error::BufferTooShort {
                needed: 1,
                available: 0,
            });
        }

        if data[o] < 0xFF {
            *offset += 1;
            Ok(data[o] as u32)
        } else if o + 1 < data.len() && data[o + 1] == 0 {
            // The implied 0x00 in front of all core OP codes (big endian) signals a
            // single-byte length value of 0xFF.
            *offset += 1;
            Ok(data[o] as u32)
        } else if o + 2 < data.len() && data[o + 1] == 0xFF && data[o + 2] == 0xFF {
            *offset += 3;
            let v = read_u32_be(data, *offset)?;
            *offset += 4;
            Ok(v)
        } else {
            *offset += 1;
            let v = read_u16_be(data, *offset)?;
            *offset += 2;
            Ok(v as u32)
        }
    }

    /// Writes a variable-length value at `*offset`, advancing it past the value.
    pub fn write(buffer: &mut [u8], length: u32, offset: &mut usize) -> Result<()> {
        if length <= 0xFF {
            ensure(buffer, *offset, 1)?;
            buffer[*offset] = length as u8;
            *offset += 1;
            Ok(())
        } else {
            write_multibyte(buffer, length, offset)
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

    /// Reads a variable-length value at `*offset`, advancing it past the value.
    pub fn read(data: &[u8], offset: &mut usize) -> Result<u32> {
        let o = *offset;
        if o >= data.len() {
            return Err(Error::BufferTooShort {
                needed: 1,
                available: 0,
            });
        }

        if data[o] < 0xFF {
            *offset += 1;
            Ok(data[o] as u32)
        } else if o + 2 < data.len() && data[o + 1] == 0xFF && data[o + 2] == 0xFF {
            *offset += 3;
            let v = read_u32_be(data, *offset)?;
            *offset += 4;
            Ok(v)
        } else {
            *offset += 1;
            let v = read_u16_be(data, *offset)?;
            *offset += 2;
            Ok(v as u32)
        }
    }

    /// Writes a variable-length value at `*offset`, advancing it past the value.
    pub fn write(buffer: &mut [u8], length: u32, offset: &mut usize) -> Result<()> {
        if length < 0xFF {
            ensure(buffer, *offset, 1)?;
            buffer[*offset] = length as u8;
            *offset += 1;
            Ok(())
        } else {
            write_multibyte(buffer, length, offset)
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
            let mut wo = 0usize;
            data_bundle::write(&mut buf, len, &mut wo).unwrap();
            assert_eq!(wo, data_bundle::encoded_size(len), "size len={len:#x}");
            let mut ro = 0usize;
            let got = data_bundle::read(&buf, &mut ro).unwrap();
            assert_eq!(got, len, "len={len:#x}");
            assert_eq!(ro, wo);
        }
    }

    #[test]
    fn multi_packet_round_trip() {
        // The single-byte 0xFF case relies on a following 0x00 (the high byte of a
        // sub-packet OP code); the buffer is zero-initialized so this holds.
        for &len in &[0u32, 1, 0xFE, 0xFF, 0x100, 0xFFFE, 0xFFFF, 0x1_0000, 0xFFFF_FFFF] {
            let mut buf = [0u8; 9];
            let mut wo = 0usize;
            multi_packet::write(&mut buf, len, &mut wo).unwrap();
            assert_eq!(wo, multi_packet::encoded_size(len), "size len={len:#x}");
            let mut ro = 0usize;
            let got = multi_packet::read(&buf, &mut ro).unwrap();
            assert_eq!(got, len, "len={len:#x}");
            assert_eq!(ro, wo);
        }
    }

    #[test]
    fn multi_packet_single_byte_ff() {
        let mut buf = [0u8; 4];
        let mut wo = 0usize;
        multi_packet::write(&mut buf, 0xFF, &mut wo).unwrap();
        assert_eq!(wo, 1);
        assert_eq!(buf[0], 0xFF);
        let mut ro = 0usize;
        assert_eq!(multi_packet::read(&buf, &mut ro).unwrap(), 0xFF);
        assert_eq!(ro, 1);
    }
}
