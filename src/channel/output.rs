//! The reliable data output channel: converts application data into ordered,
//! fragmented reliable data packets, and resends them until acknowledged.
//!
//! This is a port of the reference implementation's simplified
//! `ReliableDataOutputChannel2`, which trades the original's multi-packet bundling
//! for a much simpler (and less bug-prone) go-back-N style window.
//!
//! Like the input channel, this is an I/O-agnostic component: enqueued data is fragmented
//! into outgoing packets which accumulate in an internal queue. Calling
//! [`ReliableDataOutputChannel::run_tick`] moves due packets into the outgoing buffer
//! (drained via [`ReliableDataOutputChannel::take_outgoing`]). Acknowledgements are
//! fed back in via [`ReliableDataOutputChannel::notify_of_acknowledge`] /
//! [`ReliableDataOutputChannel::notify_of_acknowledge_all`]. Time is supplied by the
//! caller as [`Instant`] values.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

use bytes::{BufMut, Bytes, BytesMut};

use crate::protocol::OpCode;
use crate::rc4::Rc4KeyState;

use super::true_incoming_sequence;

/// The size of a reliable data packet's sequence prefix.
const SEQUENCE_SIZE: usize = 2;
/// The size of a master fragment's total-length prefix.
const FRAGMENT_LENGTH_SIZE: usize = 4;

/// Adaptive retransmit-timeout (RTO) tuning. Uses the Jacobson/Karels SRTT/RTTVAR
/// estimator (SIGCOMM '88, "Congestion Avoidance and Control"), as later standardized
/// for TCP in RFC 6298.
/// `RTO = SRTT + max(RTO_GRANULARITY, RTT_K * RTTVAR)`, clamped to [RTO_MIN, RTO_MAX].
const RTT_K: u32 = 4;
/// Floor on the variance term so the RTO keeps headroom above a perfectly steady RTT
/// (otherwise RTTVAR -> 0 makes RTO == RTT and the timer fires right as acks arrive).
const RTO_GRANULARITY: Duration = Duration::from_millis(100);
/// Lower clamp on the computed RTO; avoids spurious resends on very low-RTT links.
const RTO_MIN: Duration = Duration::from_millis(200);
/// Upper clamp on the computed RTO (also the ceiling for exponential backoff).
const RTO_MAX: Duration = Duration::from_secs(8);

/// Statistics gathered while sending reliable data.
#[derive(Debug, Default, Clone)]
pub struct DataOutputStats {
    /// Total reliable data packets dispatched, including re-sends.
    pub total_sent: u64,
    /// Total reliable data packets that were re-sent.
    pub total_resent: u64,
    /// Total acknowledgement packets received (including ack-alls).
    pub incoming_acknowledge_count: u64,
    /// Total reliable data packets acknowledged (including via ack-all).
    pub actual_acknowledge_count: u64,
}

/// Configuration controlling the output channel's behaviour.
#[derive(Debug, Clone)]
pub struct OutputConfig {
    /// The maximum length, in bytes, of the data portion (sequence + data) of a
    /// single reliable data packet. This is the remote UDP length minus the OP code
    /// and CRC.
    pub max_data_length: usize,
    /// The maximum number of unacknowledged reliable data packets that may be in
    /// flight at once (the send window).
    pub max_queued_outgoing: usize,
    /// The INITIAL retransmit timeout, used before any round-trip time has been
    /// measured. Once acknowledgements start arriving the channel derives an adaptive
    /// RTO from the measured RTT (see `RTT_K`/`RTO_MIN`/`RTO_MAX`), so this value only
    /// governs the very first window.
    pub ack_wait: Duration,
}

impl Default for OutputConfig {
    fn default() -> Self {
        Self {
            max_data_length: 508,
            max_queued_outgoing: 196,
            ack_wait: Duration::from_millis(500),
        }
    }
}

/// A reliable data packet the channel wishes to send (without OP code or CRC
/// framing, which the session layer applies).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutgoingReliable {
    /// The OP code of the packet ([`OpCode::ReliableData`] or
    /// [`OpCode::ReliableDataFragment`]).
    pub op_code: OpCode,
    /// The packet payload: a big-endian `u16` sequence, an optional big-endian `u32`
    /// total-length prefix (master fragments only), and the data chunk.
    pub payload: Bytes,
}

#[derive(Debug)]
struct StashedOutputPacket {
    is_fragment: bool,
    data: Bytes,
    sent: bool,
    /// When this packet was most recently (re)sent, for RTT measurement and per-packet
    /// retransmit timing. `None` until first dispatched.
    sent_at: Option<Instant>,
    /// Set once the packet has been retransmitted: its RTT becomes ambiguous, so it must
    /// not be used as a round-trip sample (Karn's algorithm).
    resent: bool,
}

/// Converts application data into ordered, fragmented reliable data packets.
#[derive(Debug)]
pub struct ReliableDataOutputChannel {
    config: OutputConfig,
    cipher: Option<Rc4KeyState>,

    dispatch_queue: VecDeque<(i64, StashedOutputPacket)>,

    /// The total number of sequences that have been output.
    total_sequence: i64,
    /// The maximum sequence number that the client is known to have received.
    max_client_sequence: i64,
    /// The index into `dispatch_queue` of the next packet to dispatch.
    current_dispatch_index: usize,

    /// Smoothed round-trip time estimate (`None` until the first RTT sample).
    srtt: Option<Duration>,
    /// Round-trip time variation estimate (the RTTVAR term of the Jacobson/Karels estimator).
    rttvar: Duration,
    /// Current retransmit timeout: adaptive once RTT is known, else `config.ack_wait`.
    rto: Duration,

    outgoing: Vec<OutgoingReliable>,
    stats: DataOutputStats,
}

impl ReliableDataOutputChannel {
    /// Creates a new output channel. `cipher` is the initial RC4 key state; pass
    /// `Some(..)` to enable RC4 encryption of the proxied application data, or `None`
    /// to pass it through unencrypted.
    pub fn new(config: OutputConfig, cipher: Option<Rc4KeyState>, _now: Instant) -> Self {
        let initial_rto = config.ack_wait;
        Self {
            config,
            cipher,
            dispatch_queue: VecDeque::new(),
            total_sequence: 0,
            max_client_sequence: 0,
            current_dispatch_index: 0,
            srtt: None,
            rttvar: Duration::ZERO,
            rto: initial_rto,
            outgoing: Vec::new(),
            stats: DataOutputStats::default(),
        }
    }

    /// Returns the gathered output statistics.
    pub fn stats(&self) -> &DataOutputStats {
        &self.stats
    }

    /// Drains the outgoing reliable data packets accumulated so far.
    pub fn take_outgoing(&mut self) -> Vec<OutgoingReliable> {
        std::mem::take(&mut self.outgoing)
    }

    /// Returns the number of reliable data packets currently awaiting acknowledgement.
    pub fn queued_len(&self) -> usize {
        self.dispatch_queue.len()
    }

    /// Sets the maximum length of the data portion (sequence + data) of a single
    /// packet. Should not be called after data has been enqueued.
    pub fn set_max_data_length(&mut self, max_data_length: usize) {
        self.config.max_data_length = max_data_length;
    }

    fn max_chunk(&self) -> usize {
        self.config.max_data_length - SEQUENCE_SIZE
    }

    /// Enqueues application data to be sent on the reliable channel. The data is
    /// fragmented as required to fit within the configured maximum packet length.
    pub fn enqueue_data(&mut self, data: &[u8]) {
        if data.is_empty() {
            return;
        }

        let mut remaining: Bytes = match &mut self.cipher {
            Some(_) => self.encrypt(data),
            None => Bytes::copy_from_slice(data),
        };

        let is_fragment = remaining.len() > self.max_chunk();
        self.stash_fragment(&mut remaining, true, is_fragment);
        while !remaining.is_empty() {
            self.stash_fragment(&mut remaining, false, true);
        }
    }

    /// Runs a tick of the output channel, moving due packets into the outgoing
    /// buffer. If the oldest in-flight packet has gone unacknowledged for longer than
    /// the current (adaptive) retransmit timeout, dispatch restarts from the front of
    /// the window (go-back-N) and the RTO is backed off exponentially (Karn).
    pub fn run_tick(&mut self, now: Instant) {
        // Retransmission timeout is keyed off the OLDEST in-flight packet's own send time
        // (not a single global timer), so a long quiet period before the first ack can't
        // make every tick resend the whole window.
        let timed_out = match self.dispatch_queue.front() {
            Some((_, front)) if front.sent => front
                .sent_at
                .is_some_and(|sent_at| now.duration_since(sent_at) > self.rto),
            _ => false,
        };
        if timed_out {
            self.current_dispatch_index = 0;
            // Karn's exponential backoff; a fresh (unambiguous) RTT sample resets this.
            self.rto = (self.rto * 2).min(RTO_MAX);
        }

        let max_index = self
            .dispatch_queue
            .len()
            .min(self.config.max_queued_outgoing);

        while self.current_dispatch_index < max_index {
            let (_, packet) = &mut self.dispatch_queue[self.current_dispatch_index];
            let op_code = if packet.is_fragment {
                OpCode::ReliableDataFragment
            } else {
                OpCode::ReliableData
            };

            self.stats.total_sent += 1;
            if packet.sent {
                self.stats.total_resent += 1;
                // A retransmitted packet's RTT is ambiguous; exclude it from sampling.
                packet.resent = true;
            }
            packet.sent = true;
            packet.sent_at = Some(now);

            let payload = packet.data.clone();
            self.outgoing.push(OutgoingReliable { op_code, payload });
            self.current_dispatch_index += 1;
        }
    }

    /// Folds a fresh, unambiguous round-trip sample into the smoothed RTT/variance
    /// estimates and recomputes the adaptive retransmit timeout (Jacobson/Karels estimator).
    fn update_rto(&mut self, sample: Duration) {
        match self.srtt {
            None => {
                self.srtt = Some(sample);
                self.rttvar = sample / 2;
            }
            Some(srtt) => {
                let diff = srtt.abs_diff(sample);
                // RTTVAR = 3/4 * RTTVAR + 1/4 * |SRTT - sample|
                self.rttvar = (self.rttvar * 3 + diff) / 4;
                // SRTT = 7/8 * SRTT + 1/8 * sample
                self.srtt = Some((srtt * 7 + sample) / 8);
            }
        }
        let srtt = self.srtt.unwrap_or(sample);
        let rto = srtt + std::cmp::max(RTO_GRANULARITY, self.rttvar * RTT_K);
        self.rto = rto.clamp(RTO_MIN, RTO_MAX);
    }

    /// Notifies the channel that the remote has acknowledged a single sequence.
    pub fn notify_of_acknowledge(&mut self, sequence: u16, now: Instant) {
        let seq = self.true_incoming(sequence);
        self.stats.incoming_acknowledge_count += 1;

        if let Some(pos) = self.dispatch_queue.iter().position(|(s, _)| *s == seq) {
            let (_, pkt) = &self.dispatch_queue[pos];
            let sample = (pkt.sent && !pkt.resent)
                .then(|| pkt.sent_at.map(|sent_at| now.duration_since(sent_at)))
                .flatten();
            self.dispatch_queue.remove(pos);
            self.current_dispatch_index = self.current_dispatch_index.saturating_sub(1);
            self.stats.actual_acknowledge_count += 1;
            if let Some(sample) = sample {
                self.update_rto(sample);
            }
        }

        if seq > self.max_client_sequence {
            self.max_client_sequence = seq;
        }
    }

    /// Notifies the channel that the remote has acknowledged all sequences up to and
    /// including the given one.
    pub fn notify_of_acknowledge_all(&mut self, sequence: u16, now: Instant) {
        let seq = self.true_incoming(sequence);
        self.stats.incoming_acknowledge_count += 1;

        let mut sample: Option<Duration> = None;
        loop {
            let (pop, this_sample) = match self.dispatch_queue.front() {
                Some((s, pkt)) if *s <= seq => {
                    let smp = (pkt.sent && !pkt.resent)
                        .then(|| pkt.sent_at.map(|sent_at| now.duration_since(sent_at)))
                        .flatten();
                    (true, smp)
                }
                _ => (false, None),
            };
            if !pop {
                break;
            }
            // Keep the freshest (most recently sent) unambiguous sample in this batch.
            if this_sample.is_some() {
                sample = this_sample;
            }
            self.dispatch_queue.pop_front();
            self.current_dispatch_index = self.current_dispatch_index.saturating_sub(1);
            self.stats.actual_acknowledge_count += 1;
        }

        if let Some(sample) = sample {
            self.update_rto(sample);
        }

        if seq > self.max_client_sequence {
            self.max_client_sequence = seq;
        }
    }

    fn stash_fragment(&mut self, data: &mut Bytes, is_master: bool, is_fragment: bool) {
        let mut amount = data.len().min(self.max_chunk());

        let mut buf = BytesMut::with_capacity(SEQUENCE_SIZE + FRAGMENT_LENGTH_SIZE + amount);
        buf.put_u16(self.total_sequence as u16);

        if is_master && is_fragment {
            buf.put_u32(data.len() as u32);
            amount -= FRAGMENT_LENGTH_SIZE;
        }

        buf.extend_from_slice(&data[..amount]);

        self.dispatch_queue.push_back((
            self.total_sequence,
            StashedOutputPacket {
                is_fragment,
                data: buf.freeze(),
                sent: false,
                sent_at: None,
                resent: false,
            },
        ));

        self.total_sequence += 1;
        *data = data.slice(amount..);
    }

    /// Encrypts `data` with the channel's RC4 cipher. A leading zero byte is
    /// prepended when the ciphertext itself begins with a zero, mirroring the input
    /// channel's padding-strip logic.
    fn encrypt(&mut self, data: &[u8]) -> Bytes {
        let cipher = self
            .cipher
            .as_mut()
            .expect("encrypt called without a cipher");

        let mut buf = BytesMut::with_capacity(data.len() + 1);
        buf.put_u8(0);
        buf.extend_from_slice(data);
        cipher.transform_in_place(&mut buf[1..]);

        let frozen = buf.freeze();
        if frozen[1] == 0 {
            frozen
        } else {
            frozen.slice(1..)
        }
    }

    fn true_incoming(&self, packet_sequence: u16) -> i64 {
        true_incoming_sequence(
            packet_sequence,
            self.max_client_sequence,
            self.config.max_queued_outgoing as i64,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MAX_DATA_LENGTH: usize = 506; // 512 (udp) - 2 (op) - 2 (seq) - 2 (crc)
    const FRAGMENT_WINDOW_SIZE: usize = 8;

    struct Clock {
        now: Instant,
    }

    impl Clock {
        fn new() -> Self {
            Self {
                now: Instant::now(),
            }
        }
        fn advance(&mut self, by: Duration) -> Instant {
            self.now += by;
            self.now
        }
    }

    fn new_channel(clock: &Clock) -> ReliableDataOutputChannel {
        let config = OutputConfig {
            max_data_length: MAX_DATA_LENGTH + SEQUENCE_SIZE,
            max_queued_outgoing: FRAGMENT_WINDOW_SIZE,
            ack_wait: Duration::from_millis(500),
        };
        ReliableDataOutputChannel::new(config, None, clock.now)
    }

    /// A deterministic pseudo-random byte buffer.
    fn generate_packet(size: usize) -> Vec<u8> {
        let mut state: u32 = 0x1234_5678 ^ size as u32;
        (0..size)
            .map(|_| {
                state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                (state >> 24) as u8
            })
            .collect()
    }

    /// Asserts that the data carried by `packets` (stripping the sequence and, for
    /// the first packet if `expect_master_fragment`, the length prefix) concatenates
    /// to exactly `buffer`.
    fn assert_packets_equal_buffer(
        packets: &[OutgoingReliable],
        buffer: &[u8],
        mut expect_master_fragment: bool,
    ) {
        let mut position = 0;
        for packet in packets {
            let data_offset = SEQUENCE_SIZE
                + if expect_master_fragment {
                    FRAGMENT_LENGTH_SIZE
                } else {
                    0
                };
            expect_master_fragment = false;

            let data = &packet.payload[data_offset..];
            assert!(
                position + data.len() <= buffer.len(),
                "received more data than expected"
            );
            assert_eq!(&buffer[position..position + data.len()], data);
            position += data.len();
        }
        assert_eq!(position, buffer.len(), "did not receive the whole buffer");
    }

    #[test]
    fn repeats_data_on_ack_failure() {
        let mut clock = Clock::new();
        let mut ch = new_channel(&clock);

        let fragment_count = 4;
        let packet_length = MAX_DATA_LENGTH - 4 + MAX_DATA_LENGTH * (fragment_count - 1);
        let packet = generate_packet(packet_length);

        ch.enqueue_data(&packet);
        ch.run_tick(clock.advance(Duration::from_millis(1)));
        assert_packets_equal_buffer(&ch.take_outgoing(), &packet, true);

        // Don't acknowledge; after the ack wait elapses the data is resent in full.
        ch.run_tick(clock.advance(Duration::from_millis(600)));
        assert_packets_equal_buffer(&ch.take_outgoing(), &packet, true);
    }

    #[test]
    fn repeats_data_from_arbitrary_position_on_ack_delay() {
        let mut clock = Clock::new();
        let mut ch = new_channel(&clock);

        let fragment_count = 4;
        let packet_length = MAX_DATA_LENGTH - 4 + MAX_DATA_LENGTH * (fragment_count - 1);
        let packet = generate_packet(packet_length);

        ch.enqueue_data(&packet);
        ch.run_tick(clock.advance(Duration::from_millis(1)));
        assert_packets_equal_buffer(&ch.take_outgoing(), &packet, true);

        ch.notify_of_acknowledge_all(1, clock.advance(Duration::from_millis(1)));

        ch.run_tick(clock.advance(Duration::from_millis(600)));
        // The master fragment (MAX-4) and the next fragment (MAX) were acknowledged.
        let expected_consumed = MAX_DATA_LENGTH - 4 + MAX_DATA_LENGTH;
        assert_packets_equal_buffer(&ch.take_outgoing(), &packet[expected_consumed..], false);
    }

    #[test]
    fn repeats_full_window_from_arbitrary_position_on_ack_delay() {
        let mut clock = Clock::new();
        let mut ch = new_channel(&clock);

        let fragment_count = FRAGMENT_WINDOW_SIZE * 2;
        let packet_length = MAX_DATA_LENGTH - 4 + MAX_DATA_LENGTH * (fragment_count - 1);
        let packet = generate_packet(packet_length);

        ch.enqueue_data(&packet);
        ch.run_tick(clock.advance(Duration::from_millis(1)));

        // Only a full window of packets is sent initially.
        let expected_receive_length =
            MAX_DATA_LENGTH - 4 + MAX_DATA_LENGTH * (FRAGMENT_WINDOW_SIZE - 1);
        assert_packets_equal_buffer(
            &ch.take_outgoing(),
            &packet[..expected_receive_length],
            true,
        );

        ch.notify_of_acknowledge_all(
            (FRAGMENT_WINDOW_SIZE - 2) as u16,
            clock.advance(Duration::from_millis(1)),
        );
        ch.run_tick(clock.advance(Duration::from_millis(600)));

        let expected_consumed = MAX_DATA_LENGTH - 4 + MAX_DATA_LENGTH * (FRAGMENT_WINDOW_SIZE - 2);
        let expected_repeat_length = MAX_DATA_LENGTH * FRAGMENT_WINDOW_SIZE;
        assert_packets_equal_buffer(
            &ch.take_outgoing(),
            &packet[expected_consumed..expected_consumed + expected_repeat_length],
            false,
        );
    }

    #[test]
    fn single_small_packet_is_not_fragmented() {
        let mut clock = Clock::new();
        let mut ch = new_channel(&clock);

        let data = generate_packet(32);
        ch.enqueue_data(&data);
        ch.run_tick(clock.advance(Duration::from_millis(1)));

        let outgoing = ch.take_outgoing();
        assert_eq!(outgoing.len(), 1);
        assert_eq!(outgoing[0].op_code, OpCode::ReliableData);
        // No length prefix: payload is [seq u16][data].
        assert_eq!(&outgoing[0].payload[SEQUENCE_SIZE..], &data[..]);
    }

    #[test]
    fn single_ack_removes_specific_packet() {
        let mut clock = Clock::new();
        let mut ch = new_channel(&clock);

        let packet_length = MAX_DATA_LENGTH - 4 + MAX_DATA_LENGTH * 3;
        let packet = generate_packet(packet_length);
        ch.enqueue_data(&packet);
        assert_eq!(ch.queued_len(), 4);

        ch.run_tick(clock.advance(Duration::from_millis(1)));
        let _ = ch.take_outgoing();

        ch.notify_of_acknowledge(2, clock.advance(Duration::from_millis(1)));
        assert_eq!(ch.queued_len(), 3);
        assert_eq!(ch.stats().actual_acknowledge_count, 1);
    }

    /// Across consecutive ticks WITHOUT acknowledgement, the number of unacknowledged
    /// packets in flight must never exceed `max_queued_outgoing`. (Regression: the window
    /// ceiling was computed relative to the already-advanced dispatch index, so each tick
    /// admitted another full window -> unbounded in-flight growth -> client RCVBUF overflow.)
    #[test]
    fn window_does_not_grow_across_ticks_without_ack() {
        let mut clock = Clock::new();
        let mut ch = new_channel(&clock);

        // Enqueue far more than one window's worth of fragments.
        let fragment_count = FRAGMENT_WINDOW_SIZE * 4;
        let packet_length = MAX_DATA_LENGTH - 4 + MAX_DATA_LENGTH * (fragment_count - 1);
        let packet = generate_packet(packet_length);
        ch.enqueue_data(&packet);

        // Tick 1: a full window goes out.
        ch.run_tick(clock.advance(Duration::from_millis(1)));
        let mut in_flight = ch.take_outgoing().len();
        assert_eq!(
            in_flight, FRAGMENT_WINDOW_SIZE,
            "first tick should send exactly one window"
        );

        // Several more ticks, no ack, well within ack_wait: nothing new may be sent
        // because the window is still full of unacknowledged packets.
        for _ in 0..5 {
            ch.run_tick(clock.advance(Duration::from_millis(10)));
            in_flight += ch.take_outgoing().len();
            assert!(
                in_flight <= FRAGMENT_WINDOW_SIZE,
                "in-flight unacked packets ({in_flight}) exceeded the window ({FRAGMENT_WINDOW_SIZE})",
            );
        }
    }

    /// Once a real round-trip time has been measured, the retransmit timeout must adapt
    /// upward so a quiet gap LONGER than the initial `ack_wait` no longer triggers a
    /// spurious resend. A fixed RTO (== ack_wait) would resend here; the adaptive RTO
    /// (SRTT + 4*RTTVAR after a ~500ms sample => ~1.5s) must not.
    #[test]
    fn adaptive_rto_suppresses_resend_after_learning_high_rtt() {
        let mut clock = Clock::new();
        let mut ch = new_channel(&clock); // ack_wait = 500ms

        // Send one window.
        let fragment_count = FRAGMENT_WINDOW_SIZE + 4;
        let packet_length = MAX_DATA_LENGTH - 4 + MAX_DATA_LENGTH * (fragment_count - 1);
        let packet = generate_packet(packet_length);
        ch.enqueue_data(&packet);
        ch.run_tick(clock.advance(Duration::from_millis(1)));
        let _ = ch.take_outgoing();

        // Acknowledge the whole first window after a ~500ms round trip: this feeds the
        // RTO estimator a 500ms sample, raising the RTO well above the 500ms ack_wait.
        ch.notify_of_acknowledge_all(
            (FRAGMENT_WINDOW_SIZE - 1) as u16,
            clock.advance(Duration::from_millis(500)),
        );

        // The newly admitted window is now in flight. Advance 600ms (> the old fixed
        // ack_wait) with no further ack. With a fixed RTO this resends the window; with
        // the adaptive RTO (~1.5s) it must NOT.
        ch.run_tick(clock.advance(Duration::from_millis(1)));
        let _ = ch.take_outgoing();
        ch.run_tick(clock.advance(Duration::from_millis(600)));
        let resent = ch.take_outgoing();

        assert!(
            resent.is_empty(),
            "adaptive RTO must not resend within the learned RTT, but resent {} packets",
            resent.len()
        );
        assert_eq!(
            ch.stats().total_resent,
            0,
            "no packet should have been retransmitted after the RTO adapted to the RTT"
        );
    }

    /// End-to-end drain at RTT ~= the initial `ack_wait`: the channel must deliver every
    /// packet while keeping in-flight within ~1 window and the on-wire datagram count close
    /// to the unique count (no resend storm). Models a delayed pipe with cumulative acks.
    #[test]
    fn adaptive_rto_bounds_inflight_at_high_rtt() {
        let mut clock = Clock::new();
        let mut ch = new_channel(&clock);

        let one_way = Duration::from_millis(250); // RTT ~= ack_wait (500ms)
        let tick = Duration::from_millis(5);

        let fragment_count = 30;
        let packet_length = MAX_DATA_LENGTH - 4 + MAX_DATA_LENGTH * (fragment_count - 1);
        let packet = generate_packet(packet_length);
        ch.enqueue_data(&packet);
        let unique = ch.queued_len();

        let mut to_client: Vec<(Instant, u16)> = Vec::new();
        let mut to_server: Vec<(Instant, u16)> = Vec::new();
        let mut received = vec![false; unique];

        let mut total_on_wire = 0usize;
        let mut highest_sent: i64 = -1;
        let mut last_ack: i64 = -1;
        let mut max_in_flight: i64 = 0;

        for _ in 0..800 {
            let now = clock.advance(tick);

            // Deliver acks that have arrived back at the server.
            to_server.retain(|&(at, ack)| {
                if at <= now {
                    ch.notify_of_acknowledge_all(ack, now);
                    last_ack = last_ack.max(ack as i64);
                    false
                } else {
                    true
                }
            });

            // Deliver datagrams that have arrived at the client; ack the highest
            // contiguous sequence seen so far.
            let mut delivered_any = false;
            to_client.retain(|&(at, seq)| {
                if at <= now {
                    received[seq as usize] = true;
                    delivered_any = true;
                    false
                } else {
                    true
                }
            });
            if delivered_any {
                let mut hw: i64 = -1;
                for (seq, got) in received.iter().enumerate() {
                    if *got {
                        hw = seq as i64;
                    } else {
                        break;
                    }
                }
                if hw >= 0 {
                    to_server.push((now + one_way, hw as u16));
                }
            }

            ch.run_tick(now);
            for out in ch.take_outgoing() {
                let seq = u16::from_be_bytes([out.payload[0], out.payload[1]]);
                total_on_wire += 1;
                highest_sent = highest_sent.max(seq as i64);
                to_client.push((now + one_way, seq));
            }

            max_in_flight = max_in_flight.max(highest_sent - last_ack);

            if last_ack >= 0 && last_ack as usize + 1 == unique {
                break;
            }
        }

        assert!(
            last_ack >= 0 && last_ack as usize + 1 == unique,
            "channel did not drain all {unique} packets (acked through {last_ack})"
        );
        assert!(
            max_in_flight <= FRAGMENT_WINDOW_SIZE as i64 + 2,
            "in-flight ({max_in_flight}) far exceeded the window ({FRAGMENT_WINDOW_SIZE}) -> resend storm",
        );
        assert!(
            total_on_wire <= unique + unique / 4,
            "sent {total_on_wire} datagrams for {unique} unique packets (>1.25x = resend storm)",
        );
    }
}
