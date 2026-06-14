//! Utilities for validating, checksumming and (un)bundling SOE protocol packets.

use crate::crc32::Crc32;
use crate::error::{Error, Result};
use crate::packets::{
    Acknowledge, AcknowledgeAll, Disconnect, RemapConnection, SessionRequest, SessionResponse,
    UnknownSender,
};
use crate::protocol::OpCode;
use crate::varint::multi_packet;

const OP_CODE_SIZE: usize = 2;

/// The result of validating that a buffer plausibly contains an SOE packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidationResult {
    /// The packet is valid.
    Valid,
    /// The packet is too short for its type.
    TooShort,
    /// The packet failed CRC validation.
    CrcMismatch,
    /// The packet had an unknown OP code.
    InvalidOpCode,
}

/// Reads the OP code from the start of a packet buffer, if present and known.
pub fn read_op_code(buffer: &[u8]) -> Option<OpCode> {
    if buffer.len() < OP_CODE_SIZE {
        return None;
    }
    OpCode::from_u16(u16::from_be_bytes([buffer[0], buffer[1]]))
}

/// Returns `true` if the OP code denotes a packet used within a session context.
#[allow(dead_code)]
pub fn is_contextual(op: OpCode) -> bool {
    matches!(
        op,
        OpCode::MultiPacket
            | OpCode::Disconnect
            | OpCode::Heartbeat
            | OpCode::NetStatusRequest
            | OpCode::NetStatusResponse
            | OpCode::ReliableData
            | OpCode::ReliableDataFragment
            | OpCode::Acknowledge
            | OpCode::AcknowledgeAll
    )
}

/// Computes a CRC over `buffer[..written]` and appends the low `crc_length` bytes
/// (big-endian) immediately after it. Returns the new total length.
///
/// `crc_length` must be 0..=4; a length of 0 is a no-op.
pub fn append_crc(buffer: &mut [u8], written: usize, crc: &Crc32, crc_length: u8) -> Result<usize> {
    if crc_length == 0 {
        return Ok(written);
    }
    let crc_length = crc_length as usize;
    if written + crc_length > buffer.len() {
        return Err(Error::BufferTooShort {
            needed: written + crc_length,
            available: buffer.len(),
        });
    }

    let hash = crc.hash(&buffer[..written]).to_be_bytes();
    buffer[written..written + crc_length].copy_from_slice(&hash[4 - crc_length..]);
    Ok(written + crc_length)
}

/// Validates that `packet_data` plausibly contains an SOE protocol packet,
/// returning the validation result and the decoded OP code (if any).
///
/// `crc` must be seeded with the session's CRC seed. Contextless packets and
/// sessions with a `crc_length` of 0 skip the CRC check.
pub fn validate_packet(
    packet_data: &[u8],
    crc: &Crc32,
    crc_length: u8,
    is_compression_enabled: bool,
) -> (ValidationResult, Option<OpCode>) {
    if packet_data.len() < OP_CODE_SIZE {
        return (ValidationResult::TooShort, None);
    }

    let op = match read_op_code(packet_data) {
        Some(op) => op,
        None => return (ValidationResult::InvalidOpCode, None),
    };

    let minimum_length = packet_minimum_length(op, is_compression_enabled, crc_length);
    if minimum_length > packet_data.len() {
        return (ValidationResult::TooShort, Some(op));
    }

    if op.is_contextless() || crc_length == 0 {
        return (ValidationResult::Valid, Some(op));
    }

    let crc_length = crc_length as usize;
    let body = &packet_data[..packet_data.len() - crc_length];
    let expected = crc.hash(body).to_be_bytes();
    let actual = &packet_data[packet_data.len() - crc_length..];

    if &expected[4 - crc_length..] == actual {
        (ValidationResult::Valid, Some(op))
    } else {
        (ValidationResult::CrcMismatch, Some(op))
    }
}

/// Returns the per-packet padding (OP code + optional compression flag + CRC)
/// applied to contextual packets.
fn contextual_padding(is_compression_enabled: bool, crc_length: u8) -> usize {
    OP_CODE_SIZE + is_compression_enabled as usize + crc_length as usize
}

/// Returns the minimum valid serialized length of a packet given its OP code.
pub fn packet_minimum_length(op: OpCode, is_compression_enabled: bool, crc_length: u8) -> usize {
    let pad = || contextual_padding(is_compression_enabled, crc_length);
    match op {
        OpCode::SessionRequest => SessionRequest::MIN_SIZE,
        OpCode::SessionResponse => SessionResponse::SIZE,
        // Data length varint (>=1) + first byte of data.
        OpCode::MultiPacket => pad() + 2,
        OpCode::Disconnect => pad() + Disconnect::SIZE,
        OpCode::Heartbeat => pad(),
        OpCode::NetStatusRequest => pad(),
        OpCode::NetStatusResponse => pad(),
        // Sequence (u16) + first byte of data.
        OpCode::ReliableData | OpCode::ReliableDataFragment => pad() + 2 + 1,
        OpCode::Acknowledge => pad() + Acknowledge::SIZE,
        OpCode::AcknowledgeAll => pad() + AcknowledgeAll::SIZE,
        OpCode::UnknownSender => UnknownSender::SIZE,
        OpCode::RemapConnection => RemapConnection::SIZE,
    }
}

/// MultiPacket bundling/unbundling helpers.
///
/// A MultiPacket payload (the bytes after the `0x00 0x03` OP code) consists of
/// back-to-back sub-packets, each prefixed by its length as a MultiPacket varint.
//
// The session currently parses MultiPacket bundles inline; this module provides a
// standalone pack/unpack surface that isn't yet wired into a production path.
#[allow(dead_code)]
pub mod multi {
    use super::*;
    use crate::io::{BinaryReader, BinaryWriter};

    /// Iterates the sub-packets within a MultiPacket payload (excluding the
    /// MultiPacket's own OP code).
    pub fn unpack(payload: &[u8]) -> Result<Vec<&[u8]>> {
        let mut out = Vec::new();
        let mut reader = BinaryReader::new(payload);
        while reader.remaining() > 0 {
            let len = multi_packet::read(&mut reader)? as usize;
            if len < OP_CODE_SIZE || len > reader.remaining() {
                return Err(Error::OutOfRange(format!(
                    "invalid multi-packet sub-packet length {len}"
                )));
            }
            out.push(reader.read_bytes(len)?);
        }
        Ok(out)
    }

    /// Returns the number of bytes required to pack the given sub-packets into a
    /// MultiPacket payload (excluding the MultiPacket's own OP code).
    pub fn packed_size(sub_packets: &[&[u8]]) -> usize {
        sub_packets
            .iter()
            .map(|p| multi_packet::encoded_size(p.len() as u32) + p.len())
            .sum()
    }

    /// Packs `sub_packets` into `buffer` as a MultiPacket payload (excluding the
    /// MultiPacket's own OP code), returning the number of bytes written.
    pub fn pack(sub_packets: &[&[u8]], buffer: &mut [u8]) -> Result<usize> {
        let mut writer = BinaryWriter::new(buffer);
        for packet in sub_packets {
            multi_packet::write(&mut writer, packet.len() as u32)?;
            writer.write_bytes(packet)?;
        }
        Ok(writer.offset())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::io::BinaryWriter;

    // Ported from SoePacketUtilsTests.AppendCrc_Correct_ForAllValidLengths
    #[test]
    fn append_crc_correct_for_all_valid_lengths() {
        for crc_length in 0u8..=4 {
            let crc = Crc32::new(5);
            let mut buffer = vec![0u8; 4 + crc_length as usize];
            {
                let mut w = BinaryWriter::new(&mut buffer);
                w.write_u32(454_653_524).unwrap();
            }
            let expected = crc.hash(&buffer[..4]).to_be_bytes();
            let total = append_crc(&mut buffer, 4, &crc, crc_length).unwrap();
            assert_eq!(total, 4 + crc_length as usize);
            for i in 0..crc_length as usize {
                assert_eq!(buffer[4 + i], expected[4 - crc_length as usize + i]);
            }
        }
    }

    // Ported from ValidatePacket_InvalidatesPacket_WithShortOpCode
    #[test]
    fn validate_rejects_short_op_code() {
        let crc = Crc32::new(5);
        let (result, _) = validate_packet(&[OpCode::SessionRequest.as_u16() as u8], &crc, 0, false);
        assert_eq!(result, ValidationResult::TooShort);
    }

    // Ported from ValidatePacket_InvalidatesPacket_WithInvalidOpCode
    #[test]
    fn validate_rejects_invalid_op_code() {
        let crc = Crc32::new(5);
        for op in [0u8, 4, 0xFF] {
            let (result, _) = validate_packet(&[0, op], &crc, 0, false);
            assert_eq!(result, ValidationResult::InvalidOpCode, "op={op}");
        }
    }

    // Ported from ValidatePacket_Validates_OpOnlyContextlessPacket
    #[test]
    fn validate_accepts_op_only_contextless_packet() {
        let crc = Crc32::new(5);
        let (result, op) =
            validate_packet(&[0, OpCode::UnknownSender.as_u16() as u8], &crc, 0, false);
        assert_eq!(result, ValidationResult::Valid);
        assert_eq!(op, Some(OpCode::UnknownSender));
    }

    // Ported from ValidatePacket_Validates_ValidContextualPacketForAllCrcLengths
    #[test]
    fn validate_accepts_contextual_packet_for_all_crc_lengths() {
        for crc_length in 0u8..=4 {
            let crc = Crc32::new(5);
            let mut packet = vec![0u8; OP_CODE_SIZE + AcknowledgeAll::SIZE + crc_length as usize];
            let written;
            {
                let mut w = BinaryWriter::new(&mut packet);
                w.write_u16(OpCode::AcknowledgeAll.as_u16()).unwrap();
                w.write_u16(10).unwrap();
                written = w.offset();
            }
            append_crc(&mut packet, written, &crc, crc_length).unwrap();
            let (result, _) = validate_packet(&packet, &crc, crc_length, false);
            assert_eq!(result, ValidationResult::Valid, "crc_length={crc_length}");
        }
    }

    // Ported from ValidatePacket_Invalidates_ContextualPacketWithIncorrectCrc
    #[test]
    fn validate_rejects_contextual_packet_with_incorrect_crc() {
        const CRC_LENGTH: u8 = 2;
        let session_crc = Crc32::new(5);
        let wrong_crc = Crc32::new(0);
        let mut packet = vec![0u8; OP_CODE_SIZE + AcknowledgeAll::SIZE + CRC_LENGTH as usize];
        let written;
        {
            let mut w = BinaryWriter::new(&mut packet);
            w.write_u16(OpCode::AcknowledgeAll.as_u16()).unwrap();
            w.write_u16(10).unwrap();
            written = w.offset();
        }
        append_crc(&mut packet, written, &wrong_crc, CRC_LENGTH).unwrap();
        let (result, _) = validate_packet(&packet, &session_crc, CRC_LENGTH, false);
        assert_eq!(result, ValidationResult::CrcMismatch);
    }

    #[test]
    fn multi_packet_pack_unpack_round_trip() {
        // Use realistic sub-packets that begin with a 0x00 OP-code high byte.
        let ack: &[u8] = &[0x00, 0x11, 0x00, 0x05];
        let heartbeat: &[u8] = &[0x00, 0x06];
        let subs = [ack, heartbeat];

        let mut buf = vec![0u8; multi::packed_size(&subs)];
        let n = multi::pack(&subs, &mut buf).unwrap();
        assert_eq!(n, buf.len());

        let unpacked = multi::unpack(&buf).unwrap();
        assert_eq!(unpacked.len(), 2);
        assert_eq!(unpacked[0], ack);
        assert_eq!(unpacked[1], heartbeat);
    }

    #[test]
    fn multi_packet_unpack_rejects_bad_length() {
        // Claims a sub-packet of length 10 but only 2 bytes follow.
        let bad = [0x0A, 0x00, 0x06];
        assert!(multi::unpack(&bad).is_err());
    }
}
