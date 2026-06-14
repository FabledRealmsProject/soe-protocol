//! Core protocol enumerations: OP codes and disconnect reasons.

/// The packet OP codes used in the SOE protocol. All packets are prefixed with a
/// big-endian `u16` OP code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum OpCode {
    /// Used to request the start of a session.
    SessionRequest = 0x01,
    /// Used to confirm the start of a session, and set connection details.
    SessionResponse = 0x02,
    /// Used to encapsulate two or more SOE protocol packets.
    MultiPacket = 0x03,
    /// Used to indicate that a party is closing the session.
    Disconnect = 0x05,
    /// Used to keep a session alive when no data has been received for some time.
    Heartbeat = 0x06,
    /// Network status request. Exact usage is not fully understood.
    NetStatusRequest = 0x07,
    /// Network status response. Exact usage is not fully understood.
    NetStatusResponse = 0x08,
    /// Used to transfer small buffers of application data.
    ReliableData = 0x09,
    /// Used to transfer large buffers of application data in multiple fragments.
    ReliableDataFragment = 0x0D,
    /// Used to acknowledge a single reliable data packet.
    Acknowledge = 0x11,
    /// Used to acknowledge all reliable data packets up to a particular sequence.
    AcknowledgeAll = 0x15,
    /// Indicates the receiver has no session associated with the sender's address.
    UnknownSender = 0x1D,
    /// Used to request that a session be remapped to another port.
    RemapConnection = 0x1E,
}

impl OpCode {
    /// Attempts to convert a raw `u16` into an [`OpCode`].
    pub fn from_u16(value: u16) -> Option<Self> {
        Some(match value {
            0x01 => Self::SessionRequest,
            0x02 => Self::SessionResponse,
            0x03 => Self::MultiPacket,
            0x05 => Self::Disconnect,
            0x06 => Self::Heartbeat,
            0x07 => Self::NetStatusRequest,
            0x08 => Self::NetStatusResponse,
            0x09 => Self::ReliableData,
            0x0D => Self::ReliableDataFragment,
            0x11 => Self::Acknowledge,
            0x15 => Self::AcknowledgeAll,
            0x1D => Self::UnknownSender,
            0x1E => Self::RemapConnection,
            _ => return None,
        })
    }

    /// Returns the raw `u16` value of this OP code.
    pub fn as_u16(self) -> u16 {
        self as u16
    }

    /// Returns `true` if this packet type is used outside of an established
    /// session context (and hence is not CRC-checked or compressed).
    pub fn is_contextless(self) -> bool {
        matches!(
            self,
            Self::SessionRequest
                | Self::SessionResponse
                | Self::NetStatusRequest
                | Self::NetStatusResponse
                | Self::UnknownSender
                | Self::RemapConnection
        )
    }
}

/// The possible session termination reasons.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum DisconnectReason {
    /// No reason can be given for the disconnect.
    None = 0,
    /// An ICMP error occurred, forcing the disconnect.
    IcmpError = 1,
    /// The other party has let the session become inactive.
    Timeout = 2,
    /// Internal: the other party has sent a disconnect.
    OtherSideTerminated = 3,
    /// The session manager has been disposed of (e.g. shutting down).
    ManagerDeleted = 4,
    /// Internal: a session request attempt has failed.
    ConnectFail = 5,
    /// The application is terminating the session.
    Application = 6,
    /// Internal: the other party is unreachable.
    UnreachableConnection = 7,
    /// A data sequence was not acknowledged quickly enough.
    UnacknowledgedTimeout = 8,
    /// A session request failed; a new attempt should be made after a short delay.
    NewConnectionAttempt = 9,
    /// The application did not accept a session request.
    ConnectionRefused = 10,
    /// The proper session negotiation flow has not been observed.
    ConnectError = 11,
    /// A session request was probably looped back to the sender.
    ConnectingToSelf = 12,
    /// Reliable data is being sent too fast to be processed.
    ReliableOverflow = 13,
    /// The session manager has been orphaned by the application.
    ApplicationReleased = 14,
    /// A corrupt packet was received.
    CorruptPacket = 15,
    /// The requested SOE protocol version or application protocol is invalid.
    ProtocolMismatch = 16,
}

impl DisconnectReason {
    /// Converts a raw `u16` into a [`DisconnectReason`], mapping unrecognized
    /// values to [`DisconnectReason::None`].
    pub fn from_u16(value: u16) -> Self {
        match value {
            1 => Self::IcmpError,
            2 => Self::Timeout,
            3 => Self::OtherSideTerminated,
            4 => Self::ManagerDeleted,
            5 => Self::ConnectFail,
            6 => Self::Application,
            7 => Self::UnreachableConnection,
            8 => Self::UnacknowledgedTimeout,
            9 => Self::NewConnectionAttempt,
            10 => Self::ConnectionRefused,
            11 => Self::ConnectError,
            12 => Self::ConnectingToSelf,
            13 => Self::ReliableOverflow,
            14 => Self::ApplicationReleased,
            15 => Self::CorruptPacket,
            16 => Self::ProtocolMismatch,
            _ => Self::None,
        }
    }

    /// Returns the raw `u16` value of this reason.
    pub fn as_u16(self) -> u16 {
        self as u16
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opcode_round_trip() {
        for raw in [
            0x01u16, 0x02, 0x03, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0D, 0x11, 0x15, 0x1D, 0x1E,
        ] {
            let op = OpCode::from_u16(raw).unwrap();
            assert_eq!(op.as_u16(), raw);
        }
        assert!(OpCode::from_u16(0x00).is_none());
        assert!(OpCode::from_u16(0xFFFF).is_none());
    }

    #[test]
    fn contextless_classification() {
        assert!(OpCode::SessionRequest.is_contextless());
        assert!(OpCode::RemapConnection.is_contextless());
        assert!(!OpCode::ReliableData.is_contextless());
        assert!(!OpCode::Disconnect.is_contextless());
    }

    #[test]
    fn disconnect_reason_round_trip() {
        for raw in 0u16..=16 {
            assert_eq!(DisconnectReason::from_u16(raw).as_u16(), raw);
        }
        assert_eq!(DisconnectReason::from_u16(999), DisconnectReason::None);
    }
}
