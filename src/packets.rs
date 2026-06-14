//! Wire representations of the SOE protocol packets, with (de)serialization.
//!
//! Two categories of packet exist:
//!
//! * **Session-control packets** (e.g. [`SessionRequest`], [`SessionResponse`],
//!   [`RemapConnection`], [`UnknownSender`]) embed their own OP code. Their
//!   `serialize` writes the OP code, and `deserialize` takes a `has_op_code` flag.
//! * **Session-context packets** (e.g. [`Disconnect`], [`Acknowledge`],
//!   [`AcknowledgeAll`]) are written without an OP code or CRC; those are added by
//!   the contextual packet wrapper.

use crate::constants::SOE_PROTOCOL_VERSION;
use crate::error::Result;
use crate::io::{BinaryReader, BinaryWriter};
use crate::protocol::{DisconnectReason, OpCode};

const OP_CODE_SIZE: usize = 2;

/// A packet used to request the start of a session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionRequest {
    /// The version of the SOE protocol in use.
    pub soe_protocol_version: u32,
    /// A randomly generated session identifier.
    pub session_id: u32,
    /// The maximum length of a UDP packet that the sender can receive.
    pub udp_length: u32,
    /// The application protocol that the sender wishes to transport.
    pub application_protocol: String,
}

impl SessionRequest {
    /// The minimum serialized size (with an empty application protocol).
    pub const MIN_SIZE: usize = OP_CODE_SIZE + 4 + 4 + 4 + 1;

    /// Returns the serialized size of this packet.
    pub fn size(&self) -> usize {
        OP_CODE_SIZE + 4 + 4 + 4 + self.application_protocol.len() + 1
    }

    /// Deserializes a packet from `buffer`.
    pub fn deserialize(buffer: &[u8], has_op_code: bool) -> Result<Self> {
        let mut r = BinaryReader::new(buffer);
        if has_op_code {
            r.read_u16()?;
        }
        Ok(Self {
            soe_protocol_version: r.read_u32()?,
            session_id: r.read_u32()?,
            udp_length: r.read_u32()?,
            application_protocol: r.read_null_terminated_string()?,
        })
    }

    /// Serializes this packet (including its OP code) into `buffer`, returning the
    /// number of bytes written.
    pub fn serialize(&self, buffer: &mut [u8]) -> Result<usize> {
        let mut w = BinaryWriter::new(buffer);
        w.write_u16(OpCode::SessionRequest.as_u16())?;
        w.write_u32(self.soe_protocol_version)?;
        w.write_u32(self.session_id)?;
        w.write_u32(self.udp_length)?;
        w.write_null_terminated_string(&self.application_protocol)?;
        Ok(w.offset())
    }
}

/// A packet used to confirm a session request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionResponse {
    /// The ID of the session being confirmed.
    pub session_id: u32,
    /// A randomly generated seed used to calculate CRC-32 check values.
    pub crc_seed: u32,
    /// The number of bytes used to store CRC-32 check values.
    pub crc_length: u8,
    /// Whether relevant packets may be compressed.
    pub is_compression_enabled: bool,
    /// Unknown. Always observed to be `0`.
    pub unknown_value_1: u8,
    /// The maximum length of a UDP packet that the sender can receive.
    pub udp_length: u32,
    /// The version of the SOE protocol in use.
    pub soe_protocol_version: u32,
}

impl SessionResponse {
    /// The serialized size of this packet.
    pub const SIZE: usize = OP_CODE_SIZE + 4 + 4 + 1 + 1 + 1 + 4 + 4;

    /// Deserializes a packet from `buffer`.
    pub fn deserialize(buffer: &[u8], has_op_code: bool) -> Result<Self> {
        let mut r = BinaryReader::new(buffer);
        if has_op_code {
            r.read_u16()?;
        }
        Ok(Self {
            session_id: r.read_u32()?,
            crc_seed: r.read_u32()?,
            crc_length: r.read_u8()?,
            is_compression_enabled: r.read_bool()?,
            unknown_value_1: r.read_u8()?,
            udp_length: r.read_u32()?,
            soe_protocol_version: r.read_u32()?,
        })
    }

    /// Serializes this packet (including its OP code) into `buffer`, returning the
    /// number of bytes written.
    pub fn serialize(&self, buffer: &mut [u8]) -> Result<usize> {
        let mut w = BinaryWriter::new(buffer);
        w.write_u16(OpCode::SessionResponse.as_u16())?;
        w.write_u32(self.session_id)?;
        w.write_u32(self.crc_seed)?;
        w.write_u8(self.crc_length)?;
        w.write_bool(self.is_compression_enabled)?;
        w.write_u8(self.unknown_value_1)?;
        w.write_u32(self.udp_length)?;
        w.write_u32(self.soe_protocol_version)?;
        Ok(w.offset())
    }
}

/// A packet used to terminate a session. Serialized without OP code or CRC.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Disconnect {
    /// The ID of the session being terminated.
    pub session_id: u32,
    /// The reason for the termination.
    pub reason: DisconnectReason,
}

impl Disconnect {
    /// The serialized size of this packet (excluding OP code and CRC).
    pub const SIZE: usize = 4 + 2;

    /// Creates a new disconnect packet.
    pub fn new(session_id: u32, reason: DisconnectReason) -> Self {
        Self { session_id, reason }
    }

    /// Deserializes a packet from `buffer`.
    pub fn deserialize(buffer: &[u8]) -> Result<Self> {
        let mut r = BinaryReader::new(buffer);
        let session_id = r.read_u32()?;
        let reason = DisconnectReason::from_u16(r.read_u16()?);
        Ok(Self { session_id, reason })
    }

    /// Serializes this packet into `buffer`, returning the number of bytes written.
    pub fn serialize(&self, buffer: &mut [u8]) -> Result<usize> {
        let mut w = BinaryWriter::new(buffer);
        w.write_u32(self.session_id)?;
        w.write_u16(self.reason.as_u16())?;
        Ok(w.offset())
    }
}

/// A packet used to remap an existing session to a new port.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RemapConnection {
    /// The ID of the session to remap.
    pub session_id: u32,
    /// The CRC seed being used in the session.
    pub crc_seed: u32,
}

impl RemapConnection {
    /// The serialized size of this packet (including OP code).
    pub const SIZE: usize = OP_CODE_SIZE + 4 + 4;

    /// Deserializes a packet from `buffer`.
    pub fn deserialize(buffer: &[u8], has_op_code: bool) -> Result<Self> {
        let mut r = BinaryReader::new(buffer);
        if has_op_code {
            r.read_u16()?;
        }
        Ok(Self {
            session_id: r.read_u32()?,
            crc_seed: r.read_u32()?,
        })
    }

    /// Serializes this packet (including its OP code) into `buffer`, returning the
    /// number of bytes written.
    pub fn serialize(&self, buffer: &mut [u8]) -> Result<usize> {
        let mut w = BinaryWriter::new(buffer);
        w.write_u16(OpCode::RemapConnection.as_u16())?;
        w.write_u32(self.session_id)?;
        w.write_u32(self.crc_seed)?;
        Ok(w.offset())
    }
}

/// A packet used to acknowledge a single data sequence. Serialized without OP code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Acknowledge {
    /// The sequence number being acknowledged.
    pub sequence: u16,
}

impl Acknowledge {
    /// The serialized size of this packet (excluding OP code and CRC).
    pub const SIZE: usize = 2;

    /// Creates a new acknowledge packet.
    pub fn new(sequence: u16) -> Self {
        Self { sequence }
    }

    /// Deserializes a packet from `buffer`.
    pub fn deserialize(buffer: &[u8]) -> Result<Self> {
        let mut r = BinaryReader::new(buffer);
        Ok(Self {
            sequence: r.read_u16()?,
        })
    }

    /// Serializes this packet into `buffer`, returning the number of bytes written.
    pub fn serialize(&self, buffer: &mut [u8]) -> Result<usize> {
        let mut w = BinaryWriter::new(buffer);
        w.write_u16(self.sequence)?;
        Ok(w.offset())
    }
}

/// A packet used to acknowledge all sequences up to and including `sequence`.
/// Serialized without OP code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AcknowledgeAll {
    /// The most recent sequence number received.
    pub sequence: u16,
}

impl AcknowledgeAll {
    /// The serialized size of this packet (excluding OP code and CRC).
    pub const SIZE: usize = 2;

    /// Creates a new acknowledge-all packet.
    pub fn new(sequence: u16) -> Self {
        Self { sequence }
    }

    /// Deserializes a packet from `buffer`.
    pub fn deserialize(buffer: &[u8]) -> Result<Self> {
        let mut r = BinaryReader::new(buffer);
        Ok(Self {
            sequence: r.read_u16()?,
        })
    }

    /// Serializes this packet into `buffer`, returning the number of bytes written.
    pub fn serialize(&self, buffer: &mut [u8]) -> Result<usize> {
        let mut w = BinaryWriter::new(buffer);
        w.write_u16(self.sequence)?;
        Ok(w.offset())
    }
}

/// A packet indicating the receiver has no session for the sender's address.
/// Carries no fields beyond its OP code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnknownSender;

impl UnknownSender {
    /// The serialized size of this packet (the OP code only).
    pub const SIZE: usize = OP_CODE_SIZE;

    /// Serializes this packet (its OP code) into `buffer`, returning the number of
    /// bytes written.
    pub fn serialize(buffer: &mut [u8]) -> Result<usize> {
        let mut w = BinaryWriter::new(buffer);
        w.write_u16(OpCode::UnknownSender.as_u16())?;
        Ok(w.offset())
    }
}

/// Constructs a [`SessionRequest`] using this crate's protocol version.
pub fn session_request(session_id: u32, udp_length: u32, application_protocol: &str) -> SessionRequest {
    SessionRequest {
        soe_protocol_version: SOE_PROTOCOL_VERSION,
        session_id,
        udp_length,
        application_protocol: application_protocol.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Ported from SessionRequestTests.cs
    #[test]
    fn session_request_round_trip() {
        let pkt = SessionRequest {
            soe_protocol_version: 3,
            session_id: 5_467_392,
            udp_length: 512,
            application_protocol: "TestProtocol".to_owned(),
        };
        let mut buf = vec![0u8; pkt.size()];
        let n = pkt.serialize(&mut buf).unwrap();
        assert_eq!(n, pkt.size());
        assert_eq!(SessionRequest::deserialize(&buf, true).unwrap(), pkt);
    }

    // Ported from SessionResponseTests.cs
    #[test]
    fn session_response_round_trip() {
        let pkt = SessionResponse {
            session_id: 531_633,
            crc_seed: 34_322,
            crc_length: 2,
            is_compression_enabled: true,
            unknown_value_1: 0,
            udp_length: 512,
            soe_protocol_version: 3,
        };
        let mut buf = [0u8; SessionResponse::SIZE];
        let n = pkt.serialize(&mut buf).unwrap();
        assert_eq!(n, SessionResponse::SIZE);
        assert_eq!(SessionResponse::deserialize(&buf, true).unwrap(), pkt);
    }

    // Ported from DisconnectTests.cs
    #[test]
    fn disconnect_round_trip() {
        let pkt = Disconnect::new(5, DisconnectReason::Application);
        let mut buf = [0u8; Disconnect::SIZE];
        pkt.serialize(&mut buf).unwrap();
        assert_eq!(Disconnect::deserialize(&buf).unwrap(), pkt);
    }

    // Ported from RemapConnectionTests.cs
    #[test]
    fn remap_connection_round_trip() {
        let pkt = RemapConnection {
            session_id: 16,
            crc_seed: 32,
        };
        let mut buf = [0u8; RemapConnection::SIZE];
        pkt.serialize(&mut buf).unwrap();
        assert_eq!(RemapConnection::deserialize(&buf, true).unwrap(), pkt);
    }

    // Ported from AcknowledgeTests.cs / AcknowledgeAllTests.cs
    #[test]
    fn acknowledge_round_trip() {
        let pkt = Acknowledge::new(2);
        let mut buf = [0u8; Acknowledge::SIZE];
        pkt.serialize(&mut buf).unwrap();
        assert_eq!(Acknowledge::deserialize(&buf).unwrap(), pkt);

        let all = AcknowledgeAll::new(2);
        let mut buf = [0u8; AcknowledgeAll::SIZE];
        all.serialize(&mut buf).unwrap();
        assert_eq!(AcknowledgeAll::deserialize(&buf).unwrap(), all);
    }

    #[test]
    fn unknown_sender_serializes_opcode() {
        let mut buf = [0u8; UnknownSender::SIZE];
        UnknownSender::serialize(&mut buf).unwrap();
        assert_eq!(buf, [0x00, 0x1D]);
    }
}
