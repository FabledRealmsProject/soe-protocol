//! Constant values and defaults used by this implementation of the SOE protocol.

use std::time::Duration;

/// The implemented version of the SOE protocol.
pub const SOE_PROTOCOL_VERSION: u32 = 3;

/// The default number of bytes used to store the CRC check value of a packet.
pub const CRC_LENGTH: u8 = 2;

/// The default maximum packet (UDP) length.
pub const DEFAULT_UDP_LENGTH: u32 = 512;

/// The default duration after which to send a heartbeat, if no contextual packets
/// have been received within the interval.
pub const DEFAULT_SESSION_HEARTBEAT_AFTER: Duration = Duration::from_secs(25);

/// The default duration after which to consider a session inactive, if no contextual
/// packets have been received within the interval.
pub const DEFAULT_SESSION_INACTIVITY_TIMEOUT: Duration = Duration::from_secs(30);

/// The byte sequence that indicates a reliable data packet is carrying bundled
/// ("multi") data.
pub const MULTI_DATA_INDICATOR: [u8; 2] = [0x00, 0x19];
