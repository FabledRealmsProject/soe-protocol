//! Big-endian binary reading and writing helpers.
//!
//! All SOE protocol packets use big-endian byte order. These helpers provide
//! cursor-style reading and writing over byte slices, tracking an offset and
//! returning [`Error::BufferTooShort`] when there is insufficient space.

use crate::error::{Error, Result};

/// A cursor-style reader over a big-endian byte slice.
#[derive(Debug, Clone)]
pub struct BinaryReader<'a> {
    data: &'a [u8],
    offset: usize,
}

impl<'a> BinaryReader<'a> {
    /// Creates a new reader over the given slice.
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, offset: 0 }
    }

    /// Returns the current read offset.
    pub fn offset(&self) -> usize {
        self.offset
    }

    /// Returns the number of bytes remaining to be read.
    pub fn remaining(&self) -> usize {
        self.data.len() - self.offset
    }

    /// Returns the underlying slice.
    pub fn data(&self) -> &'a [u8] {
        self.data
    }

    fn ensure(&self, needed: usize) -> Result<()> {
        if self.remaining() < needed {
            return Err(Error::BufferTooShort {
                needed,
                available: self.remaining(),
            });
        }
        Ok(())
    }

    /// Reads a single byte.
    pub fn read_u8(&mut self) -> Result<u8> {
        self.ensure(1)?;
        let v = self.data[self.offset];
        self.offset += 1;
        Ok(v)
    }

    /// Reads a boolean (a single non-zero byte is `true`).
    pub fn read_bool(&mut self) -> Result<bool> {
        Ok(self.read_u8()? != 0)
    }

    /// Reads a big-endian `u16`.
    pub fn read_u16(&mut self) -> Result<u16> {
        self.ensure(2)?;
        let v = u16::from_be_bytes([self.data[self.offset], self.data[self.offset + 1]]);
        self.offset += 2;
        Ok(v)
    }

    /// Reads a big-endian `u32`.
    pub fn read_u32(&mut self) -> Result<u32> {
        self.ensure(4)?;
        let mut buf = [0u8; 4];
        buf.copy_from_slice(&self.data[self.offset..self.offset + 4]);
        self.offset += 4;
        Ok(u32::from_be_bytes(buf))
    }

    /// Reads a big-endian `u64`.
    pub fn read_u64(&mut self) -> Result<u64> {
        self.ensure(8)?;
        let mut buf = [0u8; 8];
        buf.copy_from_slice(&self.data[self.offset..self.offset + 8]);
        self.offset += 8;
        Ok(u64::from_be_bytes(buf))
    }

    /// Reads `len` bytes, returning a borrowed slice.
    pub fn read_bytes(&mut self, len: usize) -> Result<&'a [u8]> {
        self.ensure(len)?;
        let slice = &self.data[self.offset..self.offset + len];
        self.offset += len;
        Ok(slice)
    }

    /// Reads a null-terminated ASCII/UTF-8 string, consuming the terminator.
    pub fn read_null_terminated_string(&mut self) -> Result<String> {
        let start = self.offset;
        while self.offset < self.data.len() {
            if self.data[self.offset] == 0 {
                let s = String::from_utf8_lossy(&self.data[start..self.offset]).into_owned();
                self.offset += 1; // consume terminator
                return Ok(s);
            }
            self.offset += 1;
        }
        Err(Error::BufferTooShort {
            needed: 1,
            available: 0,
        })
    }

    /// Returns the remaining bytes without advancing.
    pub fn remaining_bytes(&self) -> &'a [u8] {
        &self.data[self.offset..]
    }
}

/// A cursor-style writer over a mutable big-endian byte slice.
#[derive(Debug)]
pub struct BinaryWriter<'a> {
    data: &'a mut [u8],
    offset: usize,
}

impl<'a> BinaryWriter<'a> {
    /// Creates a new writer over the given mutable slice.
    pub fn new(data: &'a mut [u8]) -> Self {
        Self { data, offset: 0 }
    }

    /// Returns the number of bytes written so far.
    pub fn offset(&self) -> usize {
        self.offset
    }

    /// Returns the remaining writable capacity.
    pub fn remaining(&self) -> usize {
        self.data.len() - self.offset
    }

    fn ensure(&self, needed: usize) -> Result<()> {
        if self.remaining() < needed {
            return Err(Error::BufferTooShort {
                needed,
                available: self.remaining(),
            });
        }
        Ok(())
    }

    /// Writes a single byte.
    pub fn write_u8(&mut self, value: u8) -> Result<()> {
        self.ensure(1)?;
        self.data[self.offset] = value;
        self.offset += 1;
        Ok(())
    }

    /// Writes a boolean as a single byte (`1` or `0`).
    pub fn write_bool(&mut self, value: bool) -> Result<()> {
        self.write_u8(value as u8)
    }

    /// Writes a big-endian `u16`.
    pub fn write_u16(&mut self, value: u16) -> Result<()> {
        self.ensure(2)?;
        self.data[self.offset..self.offset + 2].copy_from_slice(&value.to_be_bytes());
        self.offset += 2;
        Ok(())
    }

    /// Writes a big-endian `u32`.
    pub fn write_u32(&mut self, value: u32) -> Result<()> {
        self.ensure(4)?;
        self.data[self.offset..self.offset + 4].copy_from_slice(&value.to_be_bytes());
        self.offset += 4;
        Ok(())
    }

    /// Writes a big-endian `u64`.
    pub fn write_u64(&mut self, value: u64) -> Result<()> {
        self.ensure(8)?;
        self.data[self.offset..self.offset + 8].copy_from_slice(&value.to_be_bytes());
        self.offset += 8;
        Ok(())
    }

    /// Writes a raw byte slice.
    pub fn write_bytes(&mut self, bytes: &[u8]) -> Result<()> {
        self.ensure(bytes.len())?;
        self.data[self.offset..self.offset + bytes.len()].copy_from_slice(bytes);
        self.offset += bytes.len();
        Ok(())
    }

    /// Writes a string followed by a null terminator.
    pub fn write_null_terminated_string(&mut self, value: &str) -> Result<()> {
        self.write_bytes(value.as_bytes())?;
        self.write_u8(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_primitives() {
        let mut buf = [0u8; 32];
        {
            let mut w = BinaryWriter::new(&mut buf);
            w.write_u8(0x12).unwrap();
            w.write_u16(0x3456).unwrap();
            w.write_u32(0x789a_bcde).unwrap();
            w.write_u64(0x0102_0304_0506_0708).unwrap();
            w.write_bool(true).unwrap();
            assert_eq!(w.offset(), 16);
        }
        let mut r = BinaryReader::new(&buf);
        assert_eq!(r.read_u8().unwrap(), 0x12);
        assert_eq!(r.read_u16().unwrap(), 0x3456);
        assert_eq!(r.read_u32().unwrap(), 0x789a_bcde);
        assert_eq!(r.read_u64().unwrap(), 0x0102_0304_0506_0708);
        assert!(r.read_bool().unwrap());
    }

    #[test]
    fn big_endian_byte_order() {
        let mut buf = [0u8; 2];
        BinaryWriter::new(&mut buf).write_u16(0x0102).unwrap();
        assert_eq!(buf, [0x01, 0x02]);
    }

    #[test]
    fn null_terminated_string() {
        let mut buf = [0u8; 16];
        BinaryWriter::new(&mut buf)
            .write_null_terminated_string("Hi")
            .unwrap();
        assert_eq!(&buf[..3], b"Hi\0");
        let mut r = BinaryReader::new(&buf);
        assert_eq!(r.read_null_terminated_string().unwrap(), "Hi");
        assert_eq!(r.offset(), 3);
    }

    #[test]
    fn short_buffer_errors() {
        let mut r = BinaryReader::new(&[0x00]);
        assert!(matches!(r.read_u32(), Err(Error::BufferTooShort { .. })));
    }
}
