//! The session handler: an I/O-agnostic state machine driving a single SOE session.
//!
//! This ports the reference `SoeProtocolHandler`, restructured as a pure state
//! machine. Rather than owning a socket, the handler accepts incoming datagrams via
//! [`SoeSession::process_incoming`], surfaces datagrams to be sent via
//! [`SoeSession::take_outgoing`], and surfaces received application data via
//! [`SoeSession::take_received`]. Time is supplied by the caller as [`Instant`].
//!
//! The handler negotiates a session (contextless [`SessionRequest`]/
//! [`SessionResponse`] exchange), then dispatches contextual packets: routing
//! reliable data to the input channel, acknowledgements to the output channel, and
//! handling heartbeats and disconnects.

use std::time::{Duration, Instant};

use bytes::Bytes;

use crate::channel::{
    InputConfig, OutputConfig, ReliableDataInputChannel, ReliableDataOutputChannel,
};
use crate::constants::{
    CRC_LENGTH, DEFAULT_SESSION_HEARTBEAT_AFTER, DEFAULT_SESSION_INACTIVITY_TIMEOUT,
    DEFAULT_UDP_LENGTH, SOE_PROTOCOL_VERSION,
};
use crate::crc32::Crc32;
use crate::io::{BinaryReader, BinaryWriter};
use crate::packet_utils::{
    RELIABLE_CHANNEL_COUNT, ValidationResult, append_crc, read_op_code, reliable_channel,
    validate_packet,
};
use crate::packets::{Acknowledge, AcknowledgeAll, Disconnect, SessionRequest, SessionResponse};
use crate::protocol::{DisconnectReason, OpCode};
use crate::rc4::Rc4KeyState;
use crate::varint::multi_packet;
use crate::zlib;

const OP_CODE_SIZE: usize = 2;
/// The default ACK wait used by the output channel.
const DEFAULT_ACK_WAIT: Duration = Duration::from_millis(500);

/// The mode a [`SoeSession`] operates in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionMode {
    /// The handler initiates the session (sends the [`SessionRequest`]).
    Client,
    /// The handler accepts a session (responds to a [`SessionRequest`]).
    Server,
}

/// The lifecycle state of a [`SoeSession`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    /// The session is being negotiated.
    Negotiating,
    /// The session is established and exchanging data.
    Running,
    /// The session has terminated.
    Terminated,
}

/// An event surfaced by a [`SoeSession`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionEvent {
    /// The session has been established and is ready to exchange data.
    Opened,
    /// The session has terminated for the given reason.
    Closed(DisconnectReason),
}

/// The channel a unit of application data is sent on (or was received on).
///
/// SOE multiplexes application data over several kinds of channel: up to
/// [`RELIABLE_CHANNEL_COUNT`] independent ordered, lossless **reliable** channels
/// (each acknowledged and retransmitted, with its own sequence space and cipher
/// stream), and a single best-effort **unreliable** channel (sent once, never
/// acked, may be dropped or reordered). The reliable channel index lets callers
/// fan independent reliable streams across the four channels.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Channel {
    /// Ordered, acknowledged, retransmitted delivery on the reliable channel with the
    /// given index. Each channel has its own independent sequence space and cipher
    /// stream. The index must be `< RELIABLE_CHANNEL_COUNT`; data on an out-of-range
    /// channel is dropped. RC4-encrypted if a cipher is configured.
    Reliable(usize),
    /// Best-effort delivery: sent once, never acknowledged, may be lost or reordered
    /// (the SOE unreliable channel). Application data is **not** RC4-encrypted on this
    /// channel, since a continuous stream cipher cannot tolerate loss or reordering.
    Unreliable,
}

/// A unit of application data received from the remote, tagged with the channel it
/// arrived on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceivedData {
    /// The received application data.
    pub data: Bytes,
    /// Which channel the data arrived on.
    pub channel: Channel,
}

/// Parameters controlling a session. Mutated during negotiation as the two parties
/// agree on connection details.
#[derive(Debug, Clone)]
pub struct SessionParameters {
    /// The application protocol being proxied (must match between the two parties).
    pub application_protocol: String,
    /// The maximum UDP payload length this party can receive.
    pub udp_length: u32,
    /// The maximum UDP payload length the remote party can receive.
    pub remote_udp_length: u32,
    /// The seed used to compute packet CRCs (agreed during negotiation).
    pub crc_seed: u32,
    /// The number of bytes used to store a packet CRC (0..=4).
    pub crc_length: u8,
    /// Whether contextual packets may be compressed.
    pub is_compression_enabled: bool,
    /// The maximum number of incoming reliable data packets that may be queued.
    pub max_queued_incoming_reliable: u16,
    /// The maximum number of outgoing reliable data packets in flight at once.
    pub max_queued_outgoing_reliable: u16,
    /// The acknowledgement window used by the input channel.
    pub data_ack_window: u16,
    /// The interval after which to send a heartbeat (client only). `ZERO` disables.
    pub heartbeat_after: Duration,
    /// The interval after which to terminate an inactive session. `ZERO` disables.
    pub inactivity_timeout: Duration,
    /// Whether every incoming reliable data packet is acknowledged individually.
    pub acknowledge_all_data: bool,
    /// The maximum delay before acknowledging incoming reliable data sequences.
    pub max_ack_delay: Duration,
}

impl Default for SessionParameters {
    fn default() -> Self {
        Self {
            application_protocol: String::new(),
            udp_length: DEFAULT_UDP_LENGTH,
            remote_udp_length: DEFAULT_UDP_LENGTH,
            crc_seed: 0,
            crc_length: CRC_LENGTH,
            is_compression_enabled: false,
            max_queued_incoming_reliable: 256,
            max_queued_outgoing_reliable: 196,
            data_ack_window: 32,
            heartbeat_after: DEFAULT_SESSION_HEARTBEAT_AFTER,
            inactivity_timeout: DEFAULT_SESSION_INACTIVITY_TIMEOUT,
            acknowledge_all_data: false,
            max_ack_delay: Duration::from_millis(2),
        }
    }
}

/// Application-level parameters: the optional encryption key state.
#[derive(Debug, Clone, Default)]
pub struct ApplicationParameters {
    /// The RC4 key state used to (en/de)crypt application data, if encryption is
    /// enabled.
    pub encryption_key_state: Option<Rc4KeyState>,
}

/// A small linear-congruential generator used to produce session IDs and CRC seeds.
#[derive(Debug)]
struct Lcg {
    state: u64,
}

impl Lcg {
    fn new(seed: u64) -> Self {
        Self {
            state: seed ^ 0x9E37_79B9_7F4A_7C15,
        }
    }

    fn next_u32(&mut self) -> u32 {
        self.state = self
            .state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        (self.state >> 32) as u32
    }
}

/// an I/O-agnostic handler for a single SOE protocol session.
#[derive(Debug)]
pub struct SoeSession {
    mode: SessionMode,
    state: SessionState,
    params: SessionParameters,

    /// Per-channel reliable input/output, created lazily on first use (matching the
    /// reference UdpLibrary). `cipher` is the pristine initial RC4 key state, cloned
    /// into each channel as it is created so every channel runs an independent stream
    /// seeded from the same key.
    inputs: [Option<ReliableDataInputChannel>; RELIABLE_CHANNEL_COUNT],
    outputs: [Option<ReliableDataOutputChannel>; RELIABLE_CHANNEL_COUNT],
    cipher: Option<Rc4KeyState>,

    session_id: u32,
    termination_reason: DisconnectReason,
    terminated_by_remote: bool,
    open_session_on_next_packet: bool,
    last_received: Instant,

    rng: Lcg,

    outgoing: Vec<Bytes>,
    received: Vec<ReceivedData>,
    events: Vec<SessionEvent>,
}

impl SoeSession {
    /// Creates a new session handler in the [`SessionState::Negotiating`] state.
    ///
    /// `rng_seed` seeds the generator used for the session ID (client) and CRC seed
    /// (server); pass a fixed value for deterministic behaviour, or entropy for real
    /// sessions.
    pub fn new(
        mode: SessionMode,
        params: SessionParameters,
        app: ApplicationParameters,
        rng_seed: u64,
        now: Instant,
    ) -> Self {
        let _ = now;
        Self {
            mode,
            state: SessionState::Negotiating,
            params,
            inputs: std::array::from_fn(|_| None),
            outputs: std::array::from_fn(|_| None),
            cipher: app.encryption_key_state,
            session_id: 0,
            termination_reason: DisconnectReason::None,
            terminated_by_remote: false,
            open_session_on_next_packet: false,
            last_received: now,
            rng: Lcg::new(rng_seed),
            outgoing: Vec::new(),
            received: Vec::new(),
            events: Vec::new(),
        }
    }

    /// Returns the current session state.
    pub fn state(&self) -> SessionState {
        self.state
    }

    /// Returns the session mode.
    pub fn mode(&self) -> SessionMode {
        self.mode
    }

    /// Returns the negotiated session ID.
    pub fn session_id(&self) -> u32 {
        self.session_id
    }

    /// Returns the negotiated CRC seed (meaningful once running).
    pub fn crc_seed(&self) -> u32 {
        self.params.crc_seed
    }

    /// Returns the reason the session terminated (meaningful once terminated).
    pub fn termination_reason(&self) -> DisconnectReason {
        self.termination_reason
    }

    /// Returns whether the termination was initiated by the remote party.
    pub fn terminated_by_remote(&self) -> bool {
        self.terminated_by_remote
    }

    /// Drains datagrams that the caller should send to the remote.
    pub fn take_outgoing(&mut self) -> Vec<Bytes> {
        std::mem::take(&mut self.outgoing)
    }

    /// Drains application data received from the remote, each tagged with the channel
    /// (reliable or unreliable) it arrived on.
    pub fn take_received(&mut self) -> Vec<ReceivedData> {
        std::mem::take(&mut self.received)
    }

    /// Drains session lifecycle events.
    pub fn take_events(&mut self) -> Vec<SessionEvent> {
        std::mem::take(&mut self.events)
    }

    fn max_data_length(params: &SessionParameters) -> usize {
        params.udp_length as usize
            - OP_CODE_SIZE
            - params.is_compression_enabled as usize
            - params.crc_length as usize
    }

    /// Returns a mutable reference to the reliable input channel `ch`, creating it
    /// (with a fresh clone of the initial cipher) on first use. Reliable channels are
    /// only created once the session is running, so `self.params` is fully negotiated
    /// by the time a channel is built.
    fn input_channel(&mut self, ch: usize, now: Instant) -> &mut ReliableDataInputChannel {
        if self.inputs[ch].is_none() {
            let config = InputConfig {
                max_queued_incoming: self.params.max_queued_incoming_reliable,
                acknowledge_all_data: self.params.acknowledge_all_data,
                data_ack_window: self.params.data_ack_window,
                max_ack_delay: self.params.max_ack_delay,
            };
            self.inputs[ch] = Some(ReliableDataInputChannel::new(
                config,
                self.cipher.clone(),
                now,
            ));
        }
        self.inputs[ch].as_mut().expect("input channel created")
    }

    /// Returns a mutable reference to the reliable output channel `ch`, creating it
    /// (with a fresh clone of the initial cipher) on first use.
    fn output_channel(&mut self, ch: usize, now: Instant) -> &mut ReliableDataOutputChannel {
        if self.outputs[ch].is_none() {
            let config = OutputConfig {
                max_data_length: Self::max_data_length(&self.params),
                max_queued_outgoing: self.params.max_queued_outgoing_reliable as usize,
                ack_wait: DEFAULT_ACK_WAIT,
            };
            self.outputs[ch] = Some(ReliableDataOutputChannel::new(
                config,
                self.cipher.clone(),
                now,
            ));
        }
        self.outputs[ch].as_mut().expect("output channel created")
    }

    /// Sends a [`SessionRequest`] to begin negotiation. Only valid in client mode
    /// while negotiating.
    pub fn send_session_request(&mut self) {
        if self.state != SessionState::Negotiating || self.mode != SessionMode::Client {
            return;
        }

        let id = self.rng.next_u32();
        self.session_id = id;
        let request = SessionRequest {
            soe_protocol_version: SOE_PROTOCOL_VERSION,
            session_id: id,
            udp_length: self.params.udp_length,
            application_protocol: self.params.application_protocol.clone(),
        };

        let mut buf = vec![0u8; request.size()];
        let n = request.serialize(&mut buf).expect("session request buffer");
        buf.truncate(n);
        self.outgoing.push(Bytes::from(buf));
    }

    /// Enqueues application data to be sent reliably. Returns `false` if the session
    /// is not running.
    #[must_use = "a false return means the data was dropped because the session is not running"]
    pub fn enqueue_data(&mut self, data: &[u8]) -> bool {
        self.enqueue_data_on(data, Channel::Reliable(0))
    }

    /// Enqueues application data to be sent on the given channel. Returns `false` if
    /// the session is not running, or if a [`Channel::Reliable`] index is out of range
    /// (`>= RELIABLE_CHANNEL_COUNT`); in both cases the data is dropped.
    ///
    /// [`Channel::Reliable`] data is sequenced, acknowledged and retransmitted (and
    /// RC4-encrypted if a cipher is configured), independently per channel index.
    /// [`Channel::Unreliable`] data is sent once as a raw SOE packet — no sequence, no
    /// acknowledgement, no encryption — and zero-escaped if it begins with a `0x00`
    /// byte. Unreliable data that would exceed the remote's maximum UDP payload is
    /// transparently promoted to reliable channel 0, mirroring the reference
    /// UdpLibrary.
    #[must_use = "a false return means the data was dropped because the session is not running"]
    pub fn enqueue_data_on(&mut self, data: &[u8], channel: Channel) -> bool {
        if self.state != SessionState::Running {
            return false;
        }
        match channel {
            Channel::Reliable(ch) => {
                if ch >= RELIABLE_CHANNEL_COUNT {
                    return false;
                }
                self.output_channel(ch, self.last_received)
                    .enqueue_data(data);
            }
            Channel::Unreliable => {
                if data.is_empty() {
                    return true;
                }
                // A raw unreliable packet carries no sequence; the escape byte (if any)
                // and the CRC are the only framing overhead.
                let escape = (data[0] == 0) as usize;
                let framed_len = escape + data.len() + self.params.crc_length as usize;
                if framed_len > self.params.remote_udp_length as usize {
                    // Too large to send raw; the reference library promotes it to reliable.
                    self.output_channel(0, self.last_received)
                        .enqueue_data(data);
                } else {
                    let dg = self.frame_unreliable(data);
                    self.outgoing.push(dg);
                }
            }
        }
        true
    }

    /// Terminates the session, optionally notifying the remote.
    pub fn terminate(&mut self, reason: DisconnectReason, notify_remote: bool, now: Instant) {
        self.terminate_inner(reason, notify_remote, false, now);
    }

    /// Processes a single incoming datagram from the remote.
    pub fn process_incoming(&mut self, datagram: Bytes, now: Instant) {
        if self.state == SessionState::Terminated {
            return;
        }

        let crc = Crc32::new(self.params.crc_seed);
        let (result, op) = validate_packet(
            &datagram,
            &crc,
            self.params.crc_length,
            self.params.is_compression_enabled,
        );

        if result != ValidationResult::Valid {
            // A packet with no recognised OP code may be an unreliable application
            // packet, which carries its payload raw (no OP code). Only an unknown OP
            // code is treated this way; genuine corruption (CRC/length) still
            // terminates the session.
            if result == ValidationResult::InvalidOpCode && self.handle_unreliable(&datagram, now) {
                self.flush_channels(now);
                return;
            }
            self.terminate_inner(DisconnectReason::CorruptPacket, true, false, now);
            return;
        }
        let op = op.expect("valid packet has an op code");

        if self.open_session_on_next_packet {
            self.events.push(SessionEvent::Opened);
            self.open_session_on_next_packet = false;
        }

        // Set after validation, as a primitive guard against a stream of corrupt
        // packets keeping a session alive.
        self.last_received = now;

        let body = datagram.slice(OP_CODE_SIZE..);
        if op.is_contextless() {
            self.handle_contextless(op, &body, now);
        } else {
            let raw_op = u16::from_be_bytes([datagram[0], datagram[1]]);
            let channel = reliable_channel(raw_op);
            let crc_length = self.params.crc_length as usize;
            let body = body.slice(..body.len() - crc_length);
            self.handle_contextual(op, channel, body, now);
        }

        self.flush_channels(now);
    }

    /// Runs a single tick of the session: heartbeats, inactivity timeout, and the
    /// reliable data channels.
    pub fn run_tick(&mut self, now: Instant) {
        if self.state == SessionState::Terminated {
            return;
        }

        self.send_heartbeat_if_required(now);

        if !self.params.inactivity_timeout.is_zero()
            && now.duration_since(self.last_received) > self.params.inactivity_timeout
        {
            self.terminate_inner(DisconnectReason::Timeout, false, false, now);
            return;
        }

        for ch in 0..RELIABLE_CHANNEL_COUNT {
            if let Some(input) = self.inputs[ch].as_mut() {
                input.run_tick(now);
            }
            if let Some(output) = self.outputs[ch].as_mut() {
                output.run_tick(now);
            }
        }
        self.flush_channels(now);
    }

    fn handle_contextless(&mut self, op: OpCode, body: &[u8], now: Instant) {
        match op {
            OpCode::SessionRequest => self.handle_session_request(body, now),
            OpCode::SessionResponse => self.handle_session_response(body, now),
            OpCode::UnknownSender => {
                self.terminate_inner(DisconnectReason::UnreachableConnection, false, false, now);
            }
            // Remap requests are the responsibility of a connection manager (Phase 7).
            _ => {}
        }
    }

    fn handle_session_request(&mut self, body: &[u8], now: Instant) {
        if self.mode == SessionMode::Client {
            self.terminate_inner(DisconnectReason::ConnectingToSelf, false, false, now);
            return;
        }

        let request = match SessionRequest::deserialize(body, false) {
            Ok(r) => r,
            Err(_) => {
                self.terminate_inner(DisconnectReason::CorruptPacket, true, false, now);
                return;
            }
        };

        self.params.remote_udp_length = request.udp_length;
        self.session_id = request.session_id;

        if self.state != SessionState::Negotiating {
            self.terminate_inner(DisconnectReason::ConnectError, true, false, now);
            return;
        }

        let protocols_match = request.soe_protocol_version == SOE_PROTOCOL_VERSION
            && request.application_protocol == self.params.application_protocol;
        if !protocols_match {
            self.terminate_inner(DisconnectReason::ProtocolMismatch, true, false, now);
            return;
        }

        self.params.crc_length = CRC_LENGTH;
        self.params.crc_seed = self.rng.next_u32();

        let response = SessionResponse {
            session_id: self.session_id,
            crc_seed: self.params.crc_seed,
            crc_length: self.params.crc_length,
            is_compression_enabled: self.params.is_compression_enabled,
            unknown_value_1: 0,
            udp_length: self.params.udp_length,
            soe_protocol_version: SOE_PROTOCOL_VERSION,
        };

        let mut buf = [0u8; SessionResponse::SIZE];
        let n = response
            .serialize(&mut buf)
            .expect("session response buffer");
        self.outgoing.push(Bytes::copy_from_slice(&buf[..n]));

        self.state = SessionState::Running;
        self.open_session_on_next_packet = true;
    }

    fn handle_session_response(&mut self, body: &[u8], now: Instant) {
        if self.mode == SessionMode::Server {
            self.terminate_inner(DisconnectReason::ConnectingToSelf, false, false, now);
            return;
        }

        let response = match SessionResponse::deserialize(body, false) {
            Ok(r) => r,
            Err(_) => {
                self.terminate_inner(DisconnectReason::CorruptPacket, true, false, now);
                return;
            }
        };

        if self.state != SessionState::Negotiating {
            self.terminate_inner(DisconnectReason::ConnectError, true, false, now);
            return;
        }

        if response.soe_protocol_version != SOE_PROTOCOL_VERSION {
            self.terminate_inner(DisconnectReason::ProtocolMismatch, true, false, now);
            return;
        }

        self.params.remote_udp_length = response.udp_length;
        self.params.crc_length = response.crc_length;
        self.params.crc_seed = response.crc_seed;
        self.params.is_compression_enabled = response.is_compression_enabled;
        self.session_id = response.session_id;

        self.state = SessionState::Running;
        self.events.push(SessionEvent::Opened);
    }

    fn handle_contextual(&mut self, op: OpCode, channel: usize, body: Bytes, now: Instant) {
        let body = if self.params.is_compression_enabled {
            if body.is_empty() {
                return;
            }
            let is_compressed = body[0] > 0;
            let rest = body.slice(1..);
            if is_compressed {
                match zlib::inflate(&rest) {
                    Ok(d) => Bytes::from(d),
                    Err(_) => {
                        self.terminate_inner(DisconnectReason::CorruptPacket, true, false, now);
                        return;
                    }
                }
            } else {
                rest
            }
        } else {
            body
        };

        self.handle_contextual_inner(op, channel, body, now);
    }

    fn handle_contextual_inner(&mut self, op: OpCode, channel: usize, body: Bytes, now: Instant) {
        match op {
            OpCode::MultiPacket => {
                let mut offset = 0;
                while offset < body.len() {
                    let mut reader = BinaryReader::new(&body[offset..]);
                    let len = match multi_packet::read(&mut reader) {
                        Ok(l) => l as usize,
                        Err(_) => {
                            self.terminate_inner(DisconnectReason::CorruptPacket, true, false, now);
                            return;
                        }
                    };
                    // Advance past the length varint by however many bytes it used.
                    offset += reader.offset();

                    if len < OP_CODE_SIZE || len > body.len() - offset {
                        self.terminate_inner(DisconnectReason::CorruptPacket, true, false, now);
                        return;
                    }

                    let sub = body.slice(offset..offset + len);
                    let sub_raw = u16::from_be_bytes([sub[0], sub[1]]);
                    let sub_op = match read_op_code(&sub) {
                        Some(o) => o,
                        None => {
                            self.terminate_inner(DisconnectReason::CorruptPacket, true, false, now);
                            return;
                        }
                    };
                    let sub_channel = reliable_channel(sub_raw);
                    self.handle_contextual_inner(
                        sub_op,
                        sub_channel,
                        sub.slice(OP_CODE_SIZE..),
                        now,
                    );
                    offset += len;

                    // A sub-packet may have terminated the session (e.g. a corrupt
                    // fragment or an embedded Disconnect). Stop draining the bundle
                    // rather than processing data on a dead session.
                    if self.state == SessionState::Terminated {
                        return;
                    }
                }
            }
            OpCode::Disconnect => {
                if let Ok(disconnect) = Disconnect::deserialize(&body) {
                    self.terminate_inner(disconnect.reason, false, true, now);
                }
            }
            OpCode::Heartbeat if self.mode == SessionMode::Server => {
                let dg = self.frame_contextual(OpCode::Heartbeat, &[]);
                self.outgoing.push(dg);
            }
            OpCode::ReliableData => {
                let outcome = self
                    .input_channel(channel, now)
                    .handle_reliable_data(body, now);
                if outcome.is_err() {
                    self.terminate_inner(DisconnectReason::CorruptPacket, true, false, now);
                }
            }
            OpCode::ReliableDataFragment => {
                let outcome = self
                    .input_channel(channel, now)
                    .handle_reliable_data_fragment(body, now);
                if outcome.is_err() {
                    self.terminate_inner(DisconnectReason::CorruptPacket, true, false, now);
                }
            }
            OpCode::Acknowledge => {
                if let Ok(ack) = Acknowledge::deserialize(&body) {
                    self.output_channel(channel, now)
                        .notify_of_acknowledge(ack.sequence, now);
                }
            }
            OpCode::AcknowledgeAll => {
                if let Ok(ack) = AcknowledgeAll::deserialize(&body) {
                    self.output_channel(channel, now)
                        .notify_of_acknowledge_all(ack.sequence, now);
                }
            }
            _ => {}
        }
    }

    fn send_heartbeat_if_required(&mut self, now: Instant) {
        let may_send = self.mode == SessionMode::Client
            && self.state == SessionState::Running
            && !self.params.heartbeat_after.is_zero()
            && now.duration_since(self.last_received) > self.params.heartbeat_after;

        if may_send {
            let dg = self.frame_contextual(OpCode::Heartbeat, &[]);
            self.outgoing.push(dg);
        }
    }

    fn flush_channels(&mut self, _now: Instant) {
        for ch in 0..RELIABLE_CHANNEL_COUNT {
            // Acknowledgements emitted by the input channel, framed with this
            // channel's opcode (base kind + channel index).
            let acks = self.inputs[ch]
                .as_mut()
                .map(|input| input.take_outgoing())
                .unwrap_or_default();
            for ack in acks {
                let payload = ack.sequence.to_be_bytes();
                let raw = ack.op_code.as_u16() + ch as u16;
                let dg = self.frame_contextual_raw(raw, &payload);
                self.outgoing.push(dg);
            }

            let packets = self.outputs[ch]
                .as_mut()
                .map(|output| output.take_outgoing())
                .unwrap_or_default();
            for packet in packets {
                let raw = packet.op_code.as_u16() + ch as u16;
                let dg = self.frame_contextual_raw(raw, &packet.payload);
                self.outgoing.push(dg);
            }

            let app_data = self.inputs[ch]
                .as_mut()
                .map(|input| input.take_app_data())
                .unwrap_or_default();
            for data in app_data {
                self.received.push(ReceivedData {
                    data,
                    channel: Channel::Reliable(ch),
                });
            }
        }
    }

    /// Attempts to handle `datagram` as an unreliable application packet (one whose
    /// leading byte is non-zero, or a zero-escaped packet). Returns `true` if it was
    /// consumed (delivered or dropped as a best-effort packet), or `false` if it is
    /// not a valid unreliable packet and the caller should treat it as corruption.
    fn handle_unreliable(&mut self, datagram: &Bytes, now: Instant) -> bool {
        // Unreliable data is only meaningful on a running session; during negotiation
        // an unknown OP code is genuine corruption.
        if self.state != SessionState::Running {
            return false;
        }

        let crc_length = self.params.crc_length as usize;
        // Need at least one body byte plus the trailing CRC.
        if datagram.len() < crc_length + 1 {
            return false;
        }

        // The CRC covers the whole datagram. A mismatch on a best-effort packet is
        // dropped rather than fatal (it may be wire corruption or a stray datagram),
        // so report it as consumed.
        if crc_length > 0 {
            let split = datagram.len() - crc_length;
            let crc = Crc32::new(self.params.crc_seed);
            let expected = crc.hash(&datagram[..split]).to_be_bytes();
            if expected[4 - crc_length..] != datagram[split..] {
                return true;
            }
        }

        let body = datagram.slice(..datagram.len() - crc_length);
        let payload = if body[0] == 0 {
            // The only unreliable packet whose first byte is zero is a zero-escaped
            // one: a single 0x00 escape byte prefixing a payload that itself began
            // with 0x00. Anything else with a zero lead byte is an unknown control
            // packet, i.e. corruption.
            if body.len() < 2 || body[1] != 0 {
                return false;
            }
            body.slice(1..)
        } else {
            body
        };

        self.last_received = now;
        if self.open_session_on_next_packet {
            self.events.push(SessionEvent::Opened);
            self.open_session_on_next_packet = false;
        }
        self.received.push(ReceivedData {
            data: payload,
            channel: Channel::Unreliable,
        });
        true
    }

    /// Frames an unreliable packet: the raw payload (zero-escaped if it begins with a
    /// `0x00` byte) followed by the CRC. Unreliable data carries no OP code, sequence,
    /// compression flag or encryption.
    fn frame_unreliable(&self, payload: &[u8]) -> Bytes {
        let escape = payload[0] == 0;
        let crc_length = self.params.crc_length as usize;
        let capacity = escape as usize + payload.len() + crc_length;

        let mut buf = vec![0u8; capacity];
        let written = {
            let mut w = BinaryWriter::new(&mut buf);
            if escape {
                w.write_u8(0).expect("escape byte");
            }
            w.write_bytes(payload).expect("payload");
            w.offset()
        };

        let crc = Crc32::new(self.params.crc_seed);
        let total = append_crc(&mut buf, written, &crc, self.params.crc_length).expect("crc");
        buf.truncate(total);
        Bytes::from(buf)
    }

    /// Frames a contextual packet: OP code, optional compression flag, payload, and
    /// CRC.
    fn frame_contextual(&self, op: OpCode, payload: &[u8]) -> Bytes {
        self.frame_contextual_raw(op.as_u16(), payload)
    }

    /// Frames a contextual packet from a raw 16-bit opcode. Used by the per-channel
    /// flush path, where the wire opcode is the base kind plus the channel index and
    /// so cannot be expressed as a single [`OpCode`] variant.
    fn frame_contextual_raw(&self, raw_op: u16, payload: &[u8]) -> Bytes {
        let compression = self.params.is_compression_enabled as usize;
        let crc_length = self.params.crc_length as usize;
        let capacity = OP_CODE_SIZE + compression + payload.len() + crc_length;

        let mut buf = vec![0u8; capacity];
        let written = {
            let mut w = BinaryWriter::new(&mut buf);
            w.write_u16(raw_op).expect("op code");
            if self.params.is_compression_enabled {
                w.write_bool(false).expect("compression flag");
            }
            w.write_bytes(payload).expect("payload");
            w.offset()
        };

        let crc = Crc32::new(self.params.crc_seed);
        let total = append_crc(&mut buf, written, &crc, self.params.crc_length).expect("crc");
        buf.truncate(total);
        Bytes::from(buf)
    }

    fn terminate_inner(
        &mut self,
        reason: DisconnectReason,
        notify_remote: bool,
        terminated_by_remote: bool,
        now: Instant,
    ) {
        if self.state == SessionState::Terminated {
            return;
        }

        // Naive flush of the output channels.
        for ch in 0..RELIABLE_CHANNEL_COUNT {
            if let Some(output) = self.outputs[ch].as_mut() {
                output.run_tick(now);
            }
        }
        self.flush_channels(now);
        self.termination_reason = reason;

        if notify_remote && self.state == SessionState::Running {
            let disconnect = Disconnect::new(self.session_id, reason);
            let mut payload = [0u8; Disconnect::SIZE];
            let n = disconnect
                .serialize(&mut payload)
                .expect("disconnect buffer");
            let dg = self.frame_contextual(OpCode::Disconnect, &payload[..n]);
            self.outgoing.push(dg);
        }

        self.state = SessionState::Terminated;
        self.terminated_by_remote = terminated_by_remote;
        self.events.push(SessionEvent::Closed(reason));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn params(protocol: &str) -> SessionParameters {
        SessionParameters {
            application_protocol: protocol.to_owned(),
            // Keep the window small so fragmentation/windowing is exercised.
            max_queued_incoming_reliable: 32,
            max_queued_outgoing_reliable: 32,
            // Disable heartbeats/timeouts for deterministic tests.
            heartbeat_after: Duration::ZERO,
            inactivity_timeout: Duration::ZERO,
            ..SessionParameters::default()
        }
    }

    /// Drives a full negotiation handshake, returning the two running sessions.
    fn negotiate(now: Instant) -> (SoeSession, SoeSession) {
        let mut client = SoeSession::new(
            SessionMode::Client,
            params("TestProtocol"),
            ApplicationParameters::default(),
            1,
            now,
        );
        let mut server = SoeSession::new(
            SessionMode::Server,
            params("TestProtocol"),
            ApplicationParameters::default(),
            2,
            now,
        );

        client.send_session_request();
        pump(&mut client, &mut server, now);

        (client, server)
    }

    /// Moves all queued datagrams between the two sessions until neither has any
    /// more to send.
    fn pump(a: &mut SoeSession, b: &mut SoeSession, now: Instant) {
        loop {
            let from_a = a.take_outgoing();
            let from_b = b.take_outgoing();
            if from_a.is_empty() && from_b.is_empty() {
                break;
            }
            for dg in from_a {
                b.process_incoming(dg, now);
            }
            for dg in from_b {
                a.process_incoming(dg, now);
            }
        }
    }

    fn generate(size: usize) -> Vec<u8> {
        let mut state: u32 = 0x1234_5678 ^ size as u32;
        (0..size)
            .map(|_| {
                state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                (state >> 24) as u8
            })
            .collect()
    }

    #[test]
    fn negotiation_establishes_running_session() {
        let now = Instant::now();
        let (mut client, mut server) = negotiate(now);

        assert_eq!(client.state(), SessionState::Running);
        assert_eq!(server.state(), SessionState::Running);
        assert_eq!(client.session_id(), server.session_id());
        // Both parties agreed on the server's CRC seed.
        assert_ne!(server.params.crc_seed, 0);
        assert_eq!(client.params.crc_seed, server.params.crc_seed);

        assert!(client.take_events().contains(&SessionEvent::Opened));
        // The server only opens the session once it receives its first packet after
        // sending the response (matching the C# reference). Drive one more packet.
        assert!(client.enqueue_data(b"hi"));
        client.run_tick(now);
        pump(&mut client, &mut server, now);
        assert!(server.take_events().contains(&SessionEvent::Opened));
    }

    #[test]
    fn protocol_mismatch_terminates() {
        let now = Instant::now();
        let mut client = SoeSession::new(
            SessionMode::Client,
            params("ClientProtocol"),
            ApplicationParameters::default(),
            1,
            now,
        );
        let mut server = SoeSession::new(
            SessionMode::Server,
            params("ServerProtocol"),
            ApplicationParameters::default(),
            2,
            now,
        );

        client.send_session_request();
        pump(&mut client, &mut server, now);

        assert_eq!(server.state(), SessionState::Terminated);
        assert_eq!(
            server.termination_reason(),
            DisconnectReason::ProtocolMismatch
        );
        // The server rejects before a CRC seed is agreed, so it cannot send a valid
        // contextual Disconnect; the client stays in negotiation and would later time
        // out (matching the C# reference, which only notifies the remote when Running).
        assert_eq!(client.state(), SessionState::Negotiating);
    }

    #[test]
    fn round_trips_small_and_large_data() {
        let now = Instant::now();
        let (mut client, mut server) = negotiate(now);

        let small = generate(5);
        let large = generate(2000); // forces fragmentation

        assert!(client.enqueue_data(&small));
        assert!(client.enqueue_data(&large));

        client.run_tick(now);
        pump(&mut client, &mut server, now);

        let received = server.take_received();
        assert_eq!(received.len(), 2);
        assert_eq!(&received[0].data[..], &small[..]);
        assert_eq!(&received[1].data[..], &large[..]);
    }

    #[test]
    fn round_trips_data_both_directions() {
        let now = Instant::now();
        let (mut client, mut server) = negotiate(now);

        let to_server = generate(1500);
        let to_client = generate(800);

        assert!(client.enqueue_data(&to_server));
        assert!(server.enqueue_data(&to_client));
        client.run_tick(now);
        server.run_tick(now);
        pump(&mut client, &mut server, now);

        assert_eq!(&server.take_received()[0].data[..], &to_server[..]);
        assert_eq!(&client.take_received()[0].data[..], &to_client[..]);
    }

    #[test]
    fn round_trips_unreliable_data() {
        let now = Instant::now();
        let (mut client, mut server) = negotiate(now);

        // A payload whose first byte is non-zero is sent raw, with no OP code.
        let payload = [0x42u8, 1, 2, 3, 4];
        assert!(client.enqueue_data_on(&payload, Channel::Unreliable));
        pump(&mut client, &mut server, now);

        let received = server.take_received();
        assert_eq!(received.len(), 1);
        assert_eq!(&received[0].data[..], &payload[..]);
        assert_eq!(received[0].channel, Channel::Unreliable);
        // An unreliable packet is never acknowledged, so nothing flows back.
        assert!(client.take_received().is_empty());
        assert_eq!(server.state(), SessionState::Running);
    }

    #[test]
    fn round_trips_zero_escaped_unreliable_data() {
        let now = Instant::now();
        let (mut client, mut server) = negotiate(now);

        // A payload that begins with 0x00 must be zero-escaped on the wire, then
        // reconstructed exactly on receipt.
        let payload = [0x00u8, 0x09, 0xff, 0x00];
        assert!(client.enqueue_data_on(&payload, Channel::Unreliable));
        pump(&mut client, &mut server, now);

        let received = server.take_received();
        assert_eq!(received.len(), 1);
        assert_eq!(&received[0].data[..], &payload[..]);
        assert_eq!(received[0].channel, Channel::Unreliable);
        assert_eq!(server.state(), SessionState::Running);
    }

    #[test]
    fn inbound_unreliable_does_not_terminate_session() {
        let now = Instant::now();
        let (mut client, mut server) = negotiate(now);

        // Before this change, an inbound packet with no recognised OP code (a non-zero
        // lead byte) tore the session down with CorruptPacket. It must now be delivered.
        assert!(client.enqueue_data_on(b"\x05hello world", Channel::Unreliable));
        pump(&mut client, &mut server, now);

        assert_eq!(server.state(), SessionState::Running);
        assert_eq!(server.take_received().len(), 1);
        // The only event is the session opening on first contact; crucially, no
        // CorruptPacket-driven Closed event.
        assert!(
            server
                .take_events()
                .iter()
                .all(|e| matches!(e, SessionEvent::Opened))
        );
    }

    #[test]
    fn oversized_unreliable_is_promoted_to_reliable() {
        let now = Instant::now();
        let (mut client, mut server) = negotiate(now);

        // Larger than the remote's UDP payload: must fall back to the reliable channel
        // (which fragments) rather than be dropped, and must still be acknowledged.
        let payload = generate(2000);
        assert!(client.enqueue_data_on(&payload, Channel::Unreliable));
        client.run_tick(now);
        pump(&mut client, &mut server, now);

        let received = server.take_received();
        assert_eq!(received.len(), 1);
        assert_eq!(&received[0].data[..], &payload[..]);
        // Promotion means it travelled reliably.
        assert_eq!(received[0].channel, Channel::Reliable(0));
    }

    #[test]
    fn round_trips_data_on_multiple_reliable_channels() {
        let now = Instant::now();
        // Use an encrypted session so the test also proves each channel runs an
        // independent RC4 stream cloned from the same initial key: output[ch] on the
        // client stays in sync with input[ch] on the server only if the per-channel
        // ciphers are seeded identically and advanced independently.
        let key = Rc4KeyState::new(&[9, 8, 7, 6, 5]);
        let app = ApplicationParameters {
            encryption_key_state: Some(key),
        };
        let mut client = SoeSession::new(
            SessionMode::Client,
            params("TestProtocol"),
            app.clone(),
            1,
            now,
        );
        let mut server = SoeSession::new(SessionMode::Server, params("TestProtocol"), app, 2, now);
        client.send_session_request();
        pump(&mut client, &mut server, now);

        // Each reliable channel has its own sequence space and cipher stream; data sent
        // on different channels must each arrive intact and be tagged with the channel
        // it travelled on.
        let on_zero = generate(1500);
        let on_one = generate(800);
        let on_three = generate(1200);

        assert!(client.enqueue_data_on(&on_zero, Channel::Reliable(0)));
        assert!(client.enqueue_data_on(&on_one, Channel::Reliable(1)));
        assert!(client.enqueue_data_on(&on_three, Channel::Reliable(3)));
        client.run_tick(now);
        pump(&mut client, &mut server, now);

        let mut received = server.take_received();
        // Order across channels is not guaranteed; index by the channel tag.
        received.sort_by_key(|r| match r.channel {
            Channel::Reliable(ch) => ch,
            Channel::Unreliable => usize::MAX,
        });
        assert_eq!(received.len(), 3);
        assert_eq!(received[0].channel, Channel::Reliable(0));
        assert_eq!(&received[0].data[..], &on_zero[..]);
        assert_eq!(received[1].channel, Channel::Reliable(1));
        assert_eq!(&received[1].data[..], &on_one[..]);
        assert_eq!(received[2].channel, Channel::Reliable(3));
        assert_eq!(&received[2].data[..], &on_three[..]);
        assert_eq!(server.state(), SessionState::Running);
    }

    #[test]
    fn enqueue_on_out_of_range_reliable_channel_is_dropped() {
        let now = Instant::now();
        let (mut client, _server) = negotiate(now);

        // Channel indices are bounded by RELIABLE_CHANNEL_COUNT; an out-of-range index
        // drops the data (reported via a `false` return) rather than panicking.
        assert!(!client.enqueue_data_on(b"nope", Channel::Reliable(RELIABLE_CHANNEL_COUNT)));
        client.run_tick(now);
        assert!(client.take_outgoing().is_empty());
    }

    /// A `MultiPacket` bundle whose first sub-packet corrupts the session must not
    /// have its remaining sub-packets processed: once a sub-packet terminates the
    /// session, the bundle loop short-circuits rather than delivering data on a dead
    /// session.
    #[test]
    fn multi_packet_stops_after_sub_packet_terminates() {
        let now = Instant::now();
        let (_client, mut server) = negotiate(now);
        assert_eq!(server.state(), SessionState::Running);

        // Build a MultiPacket body with two sub-packets:
        //   1. a corrupt master ReliableDataFragment (only 2 of the required 4
        //      total-length bytes) -> terminates the session as CorruptPacket;
        //   2. an otherwise-valid ReliableData carrying "hi".
        // Each sub-packet is `[length][op-code (2 BE)][sub-payload]`; lengths < 256
        // encode as a single byte.
        let mut body = Vec::new();

        // Sub-packet 1: ReliableDataFragment, sequence 0, truncated length prefix.
        let sub1 = [0x00, 0x0D, 0x00, 0x00, 0xAB, 0xCD];
        body.push(sub1.len() as u8);
        body.extend_from_slice(&sub1);

        // Sub-packet 2: ReliableData, sequence 0, payload "hi".
        let sub2 = [0x00, 0x09, 0x00, 0x00, b'h', b'i'];
        body.push(sub2.len() as u8);
        body.extend_from_slice(&sub2);

        server.handle_contextual_inner(OpCode::MultiPacket, 0, Bytes::from(body), now);

        assert_eq!(server.state(), SessionState::Terminated);
        assert_eq!(server.termination_reason(), DisconnectReason::CorruptPacket);
        // The second sub-packet must never have reached the input channel.
        assert!(
            server.inputs[0]
                .as_mut()
                .map(|c| c.take_app_data().is_empty())
                .unwrap_or(true),
            "data after a terminating sub-packet was processed"
        );
    }

    #[test]
    fn disconnect_notifies_remote() {
        let now = Instant::now();
        let (mut client, mut server) = negotiate(now);

        client.terminate(DisconnectReason::Application, true, now);
        assert_eq!(client.state(), SessionState::Terminated);

        pump(&mut client, &mut server, now);
        assert_eq!(server.state(), SessionState::Terminated);
        assert_eq!(server.termination_reason(), DisconnectReason::Application);
        assert!(server.terminated_by_remote());
    }

    #[test]
    fn encrypted_data_round_trips() {
        let now = Instant::now();
        let key = Rc4KeyState::new(&[1, 2, 3, 4, 5]);
        let app = ApplicationParameters {
            encryption_key_state: Some(key),
        };

        let mut client = SoeSession::new(
            SessionMode::Client,
            params("TestProtocol"),
            app.clone(),
            1,
            now,
        );
        let mut server = SoeSession::new(SessionMode::Server, params("TestProtocol"), app, 2, now);

        client.send_session_request();
        pump(&mut client, &mut server, now);

        let data = generate(1200);
        assert!(client.enqueue_data(&data));
        client.run_tick(now);
        pump(&mut client, &mut server, now);

        assert_eq!(&server.take_received()[0].data[..], &data[..]);
    }
}
