//! Reliable data channels: reassembly/ordering of incoming data, and
//! fragmentation/sequencing of outgoing data.

mod input;
mod output;

pub use input::{
    CorruptData, DataInputStats, InputConfig, OutgoingContextual, ReliableDataInputChannel,
};
pub use output::{DataOutputStats, OutgoingReliable, OutputConfig, ReliableDataOutputChannel};

/// Computes the "true" (un-wrapped, monotonically increasing) sequence number for
/// an incoming packet, given the embedded 16-bit packet sequence and the expected
/// window position. Mirrors `DataUtils.GetTrueIncomingSequence`.
pub(crate) fn true_incoming_sequence(
    packet_sequence: u16,
    current_sequence: i64,
    max_queued_reliable_data_packets: i64,
) -> i64 {
    // Zero out the low two bytes of the last known sequence and insert the packet
    // sequence in that space.
    let mut sequence = packet_sequence as i64 | (current_sequence & (i64::MAX ^ 0xFFFF));

    // If larger than our possible window, we wrapped back to the previous block.
    if sequence > current_sequence + max_queued_reliable_data_packets {
        sequence -= 0x1_0000;
    }
    // If smaller than our possible window, we wrapped forward to the next block.
    if sequence < current_sequence - max_queued_reliable_data_packets {
        sequence += 0x1_0000;
    }
    sequence
}

#[cfg(test)]
mod sequence_tests {
    use super::true_incoming_sequence;

    #[test]
    fn in_window_is_identity() {
        assert_eq!(true_incoming_sequence(5, 5, 256), 5);
        assert_eq!(true_incoming_sequence(300, 256, 256), 300);
    }

    #[test]
    fn wraps_forward_past_u16_boundary() {
        // current just below a block boundary, packet sequence wrapped to 0.
        let current = 0x1_0000 - 1; // 65535
        assert_eq!(true_incoming_sequence(0, current, 256), 0x1_0000);
    }

    #[test]
    fn wraps_backward() {
        // current just past a block boundary; a late packet from the previous block.
        let current = 0x1_0000 + 10;
        assert_eq!(true_incoming_sequence(0xFFFF, current, 256), 0xFFFF);
    }
}
