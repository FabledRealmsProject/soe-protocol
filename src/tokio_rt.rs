//! A [Tokio](https://tokio.rs)-based async adapter driving a [`SoeMultiplexer`]
//! over a UDP socket. Enabled by the `tokio` feature.
//!
//! The sans-I/O [`SoeMultiplexer`] is runtime-agnostic; this module is a thin,
//! optional convenience layer for users who want a ready-made async driver. It owns
//! a [`tokio::net::UdpSocket`] and interleaves socket reads with periodic ticks
//! (for heartbeats, timeouts, and reliable-data resends), flushing outgoing
//! datagrams after each step.

use std::io;
use std::net::SocketAddr;
use std::time::Instant;

use bytes::Bytes;
use tokio::net::UdpSocket;
use tokio::time::{Duration, Interval, MissedTickBehavior, interval};

use crate::protocol::DisconnectReason;
use crate::socket::{SocketConfig, SocketEvent, SoeMultiplexer, SoeSocket};

/// Buffer size for a single received datagram. SOE UDP lengths default to 512 and
/// rarely exceed it.
const RECV_BUFFER_SIZE: usize = 2048;

/// An async SOE socket: a [`SoeMultiplexer`] driven over a Tokio UDP socket.
///
/// Drive it by repeatedly awaiting [`step`](TokioSoeSocket::step), which performs a
/// single read-or-tick cycle and returns any [`SocketEvent`]s produced. Sessions are
/// initiated with [`connect`](TokioSoeSocket::connect) and data is sent with
/// [`enqueue_data`](TokioSoeSocket::enqueue_data).
pub struct TokioSoeSocket {
    mux: SoeMultiplexer<SocketAddr>,
    socket: UdpSocket,
    tick: Interval,
    buf: Box<[u8]>,
}

impl TokioSoeSocket {
    /// Binds a UDP socket to `local` and prepares to drive sessions, ticking every
    /// `tick_period`. A period of 1–10ms is typical.
    pub async fn bind(
        local: SocketAddr,
        config: SocketConfig,
        tick_period: Duration,
    ) -> io::Result<Self> {
        let socket = UdpSocket::bind(local).await?;
        let mut tick = interval(tick_period);
        // If we fall behind (e.g. while awaiting a send), don't fire a burst of
        // catch-up ticks; a single delayed tick is enough.
        tick.set_missed_tick_behavior(MissedTickBehavior::Delay);

        Ok(Self {
            mux: SoeMultiplexer::new(config),
            socket,
            tick,
            buf: vec![0u8; RECV_BUFFER_SIZE].into_boxed_slice(),
        })
    }

    /// Returns the local address the socket is bound to.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    /// Performs a single drive cycle: awaits either an incoming datagram or the next
    /// tick, runs a session tick, flushes outgoing datagrams, and returns any events.
    pub async fn step(&mut self) -> io::Result<Vec<SocketEvent<SocketAddr>>> {
        tokio::select! {
            result = self.socket.recv_from(&mut self.buf) => {
                let (len, from) = result?;
                let datagram = Bytes::copy_from_slice(&self.buf[..len]);
                self.mux.process_incoming(from, datagram, Instant::now());
            }
            _ = self.tick.tick() => {}
        }

        self.mux.run_tick(Instant::now());

        for (addr, datagram) in self.mux.take_outgoing() {
            self.socket.send_to(&datagram, addr).await?;
        }

        Ok(self.mux.take_events())
    }
}

impl SoeSocket for TokioSoeSocket {
    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    fn session_count(&self) -> usize {
        self.mux.session_count()
    }

    fn connect(&mut self, remote: SocketAddr) {
        self.mux.connect(remote, Instant::now());
    }

    fn enqueue_data(&mut self, remote: &SocketAddr, data: &[u8]) -> bool {
        self.mux.enqueue_data(remote, data)
    }

    fn terminate(&mut self, remote: &SocketAddr, reason: DisconnectReason) {
        self.mux.terminate(remote, reason, Instant::now());
    }
}
