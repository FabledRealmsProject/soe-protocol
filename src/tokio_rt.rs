//! A [Tokio](https://tokio.rs)-based async adapter driving a [`SoeMultiplexer`]
//! over a UDP socket. Enabled by the `tokio` feature.
//!
//! The I/O-agnostic [`SoeMultiplexer`] is runtime-agnostic; this module is a thin,
//! optional convenience layer for users who want a ready-made async driver. It owns
//! a [`tokio::net::UdpSocket`] and interleaves socket reads with periodic ticks
//! (for heartbeats, timeouts, and reliable-data resends), flushing outgoing
//! datagrams after each step.

use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Instant;

use bytes::Bytes;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::time::{Duration, Interval, MissedTickBehavior, interval};

use crate::protocol::DisconnectReason;
use crate::session::Channel;
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
#[derive(Debug)]
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

    fn enqueue_data_on(&mut self, remote: &SocketAddr, data: &[u8], channel: Channel) -> bool {
        self.mux.enqueue_data_on(remote, data, channel)
    }

    fn terminate(&mut self, remote: &SocketAddr, reason: DisconnectReason) {
        self.mux.terminate(remote, reason, Instant::now());
    }
}

/// A command sent from a [`SoeHandle`] to the [`TokioSoeServer`] driver loop.
enum Command {
    Connect(SocketAddr),
    EnqueueData {
        remote: SocketAddr,
        data: Bytes,
        channel: Channel,
    },
    Terminate {
        remote: SocketAddr,
        reason: DisconnectReason,
    },
}

/// A cloneable handle for interacting with a [`TokioSoeServer`] from any task.
///
/// All methods are non-blocking: they post a command to the server's driver loop,
/// which owns the socket and the [`SoeMultiplexer`]. This lets per-client game-logic
/// tasks send reliable data and manage sessions without sharing the (necessarily
/// single-owner) protocol state.
///
/// Each method returns `false` if the server's driver loop has stopped (e.g. the
/// [`TokioSoeServer`] was dropped), in which case the command was not delivered.
#[derive(Clone, Debug)]
pub struct SoeHandle {
    commands: mpsc::UnboundedSender<Command>,
}

impl SoeHandle {
    /// Opens a client session to `remote`. The session request is sent by the driver
    /// loop on its next cycle.
    pub fn connect(&self, remote: SocketAddr) -> bool {
        self.commands.send(Command::Connect(remote)).is_ok()
    }

    /// Enqueues application data to be sent reliably to `remote`.
    ///
    /// Returns `false` only if the driver loop has stopped; it does **not** report
    /// whether a session for `remote` exists (that is determined asynchronously by
    /// the loop).
    pub fn enqueue_data(&self, remote: SocketAddr, data: impl Into<Bytes>) -> bool {
        self.enqueue_data_on(remote, data, Channel::Reliable(0))
    }

    /// Enqueues application data to be sent to `remote` on the given channel.
    ///
    /// Returns `false` only if the driver loop has stopped; it does **not** report
    /// whether a session for `remote` exists (that is determined asynchronously by
    /// the loop).
    pub fn enqueue_data_on(
        &self,
        remote: SocketAddr,
        data: impl Into<Bytes>,
        channel: Channel,
    ) -> bool {
        self.commands
            .send(Command::EnqueueData {
                remote,
                data: data.into(),
                channel,
            })
            .is_ok()
    }

    /// Terminates the session with `remote`, notifying the remote party.
    pub fn terminate(&self, remote: SocketAddr, reason: DisconnectReason) -> bool {
        self.commands
            .send(Command::Terminate { remote, reason })
            .is_ok()
    }
}

/// An actor-style SOE server: a [`SoeMultiplexer`] driven on its own Tokio task,
/// reachable from any task via a cloneable [`SoeHandle`].
///
/// This is the recommended shape for a game server. The driver task owns the UDP
/// socket and all protocol state (sequence numbers, ciphers, reassembly), which is
/// inherently single-owner. Application code interacts with it asynchronously:
///
/// * Obtain a cloneable [`SoeHandle`] with [`handle`](TokioSoeServer::handle) and
///   share it with per-client game-logic tasks to send data or manage sessions.
/// * Receive [`SocketEvent`]s with [`recv_event`](TokioSoeServer::recv_event) and
///   route them (e.g. fan `DataReceived` out to the matching per-client task).
///
/// Because each server owns one socket and one multiplexer, scaling UDP I/O across
/// cores later is a matter of running several servers — one per `SO_REUSEPORT`
/// socket — and routing by client address; no change to the core is required.
///
/// The driver task runs until the [`TokioSoeServer`] **and** every [`SoeHandle`] are
/// dropped, or until the event receiver is dropped.
#[derive(Debug)]
pub struct TokioSoeServer {
    handle: SoeHandle,
    events: mpsc::UnboundedReceiver<SocketEvent<SocketAddr>>,
    local_addr: SocketAddr,
    driver: JoinHandle<()>,
}

impl TokioSoeServer {
    /// Binds a UDP socket to `local` and spawns the driver loop, ticking every
    /// `tick_period`. A period of 1–10ms is typical.
    pub async fn bind(
        local: SocketAddr,
        config: SocketConfig,
        tick_period: Duration,
    ) -> io::Result<Self> {
        let socket = UdpSocket::bind(local).await?;
        let local_addr = socket.local_addr()?;

        let (command_tx, command_rx) = mpsc::unbounded_channel();
        let (event_tx, event_rx) = mpsc::unbounded_channel();

        let driver = tokio::spawn(drive_loop(
            socket,
            config,
            tick_period,
            command_rx,
            event_tx,
        ));

        Ok(Self {
            handle: SoeHandle {
                commands: command_tx,
            },
            events: event_rx,
            local_addr,
            driver,
        })
    }

    /// Returns the local address the server is bound to.
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Returns a cloneable handle for sending commands to the server from any task.
    pub fn handle(&self) -> SoeHandle {
        self.handle.clone()
    }

    /// Awaits the next event from the driver loop, or `None` once the loop has
    /// stopped.
    pub async fn recv_event(&mut self) -> Option<SocketEvent<SocketAddr>> {
        self.events.recv().await
    }

    /// Aborts the driver task, stopping the server.
    pub fn abort(&self) {
        self.driver.abort();
    }
}

/// The actor driver loop: owns the socket and multiplexer, interleaving socket
/// reads, periodic ticks, and commands from [`SoeHandle`]s, flushing outgoing
/// datagrams and forwarding events after each cycle.
async fn drive_loop(
    socket: UdpSocket,
    config: SocketConfig,
    tick_period: Duration,
    mut commands: mpsc::UnboundedReceiver<Command>,
    events: mpsc::UnboundedSender<SocketEvent<SocketAddr>>,
) {
    let mut mux = SoeMultiplexer::new(config);
    let mut tick = interval(tick_period);
    tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
    let mut buf = vec![0u8; RECV_BUFFER_SIZE].into_boxed_slice();

    loop {
        tokio::select! {
            result = socket.recv_from(&mut buf) => {
                match result {
                    Ok((len, from)) => {
                        let datagram = Bytes::copy_from_slice(&buf[..len]);
                        mux.process_incoming(from, datagram, Instant::now());
                    }
                    // A transient receive error (e.g. ICMP port-unreachable surfaced
                    // on some platforms) shouldn't kill the server; skip and continue.
                    Err(_) => continue,
                }
            }
            _ = tick.tick() => {
                mux.run_tick(Instant::now());
            }
            command = commands.recv() => {
                match command {
                    Some(Command::Connect(remote)) => mux.connect(remote, Instant::now()),
                    Some(Command::EnqueueData { remote, data, channel }) => {
                        // Fire-and-forget: if no running session exists for `remote`
                        // the data is dropped (the handle API is intentionally async
                        // and can't synchronously report this).
                        let _ = mux.enqueue_data_on(&remote, &data, channel);
                    }
                    Some(Command::Terminate { remote, reason }) => {
                        mux.terminate(&remote, reason, Instant::now());
                    }
                    // All handles dropped: nothing more can drive the server.
                    None => break,
                }
            }
        }

        for (addr, datagram) in mux.take_outgoing() {
            // A send failure for one datagram shouldn't tear down every session.
            let _ = socket.send_to(&datagram, addr).await;
        }
        for event in mux.take_events() {
            // The event receiver was dropped: no one is listening, so shut down.
            if events.send(event).is_err() {
                return;
            }
        }
    }
}

/// A command sent from a [`SoeClientHandle`] to the [`TokioSoeClient`] driver loop.
enum ClientCommand {
    EnqueueData { data: Bytes, channel: Channel },
    Terminate { reason: DisconnectReason },
}

/// An event surfaced by a [`TokioSoeClient`].
///
/// This mirrors [`SocketEvent`] but drops the remote address: a client talks to a
/// single server, so every event implicitly concerns that one session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientEvent {
    /// The session with the server has been established. This is always the first
    /// event, and data may only be sent once it has been observed.
    Connected,
    /// Application data was received from the server.
    DataReceived {
        /// The received application data.
        data: Bytes,
        /// Whether the data arrived on the reliable or unreliable channel.
        channel: Channel,
    },
    /// The session with the server has terminated for the given reason.
    Disconnected {
        /// The reason the session terminated.
        reason: DisconnectReason,
    },
}

/// A cloneable handle for sending data to a [`TokioSoeClient`]'s server from any task.
///
/// All methods are non-blocking: they post a command to the client's driver loop,
/// which owns the socket and the single [`SoeSession`](crate::session::SoeSession).
/// Like [`SoeHandle`], this lets game-logic tasks send reliable data without sharing
/// the (necessarily single-owner) protocol state.
///
/// Each method returns `false` if the driver loop has stopped (e.g. the
/// [`TokioSoeClient`] was dropped), in which case the command was not delivered.
#[derive(Clone, Debug)]
pub struct SoeClientHandle {
    commands: mpsc::UnboundedSender<ClientCommand>,
}

impl SoeClientHandle {
    /// Enqueues application data to be sent reliably to the server.
    ///
    /// Returns `false` only if the driver loop has stopped; it does **not** report
    /// whether the session is established (that is determined asynchronously by the
    /// loop). Data enqueued before the session opens is dropped.
    pub fn enqueue_data(&self, data: impl Into<Bytes>) -> bool {
        self.enqueue_data_on(data, Channel::Reliable(0))
    }

    /// Enqueues application data to be sent to the server on the given channel.
    ///
    /// Returns `false` only if the driver loop has stopped; it does **not** report
    /// whether the session is established (that is determined asynchronously by the
    /// loop). Data enqueued before the session opens is dropped.
    pub fn enqueue_data_on(&self, data: impl Into<Bytes>, channel: Channel) -> bool {
        self.commands
            .send(ClientCommand::EnqueueData {
                data: data.into(),
                channel,
            })
            .is_ok()
    }

    /// Terminates the session with the server, notifying it of the disconnect.
    pub fn terminate(&self, reason: DisconnectReason) -> bool {
        self.commands
            .send(ClientCommand::Terminate { reason })
            .is_ok()
    }
}

/// An actor-style SOE client: a single session to one server, driven on its own
/// Tokio task and reachable from any task via a cloneable [`SoeClientHandle`].
///
/// This is the client counterpart to [`TokioSoeServer`]. The driver task owns the
/// UDP socket and all protocol state (sequence numbers, ciphers, reassembly), which
/// is inherently single-owner. Application code interacts with it asynchronously:
///
/// * Obtain a cloneable [`SoeClientHandle`] with [`handle`](TokioSoeClient::handle)
///   and share it with tasks that send data to the server.
/// * Receive [`ClientEvent`]s with [`recv_event`](TokioSoeClient::recv_event). The
///   first event is always [`ClientEvent::Connected`]; data may only be sent once it
///   has been observed.
///
/// The bound socket is connected to the server, so datagrams from any other address
/// are ignored by the OS.
///
/// The driver task runs until the [`TokioSoeClient`] **and** every
/// [`SoeClientHandle`] are dropped, or until the event receiver is dropped.
#[derive(Debug)]
pub struct TokioSoeClient {
    handle: SoeClientHandle,
    events: mpsc::UnboundedReceiver<ClientEvent>,
    local_addr: SocketAddr,
    server_addr: SocketAddr,
    driver: JoinHandle<()>,
}

impl TokioSoeClient {
    /// Connects to `server`, binding the local socket to an OS-chosen ephemeral port
    /// on the unspecified address of the server's IP family (`0.0.0.0` for IPv4,
    /// `::` for IPv6).
    ///
    /// This is the convenient default for a client that doesn't care which local
    /// interface or port it uses. To pin a specific local address (e.g. on a
    /// multi-homed host), use [`connect`](TokioSoeClient::connect) instead.
    ///
    /// Like [`connect`](TokioSoeClient::connect), this returns as soon as the socket
    /// is bound and does **not** wait for the session to be established.
    pub async fn connect_to(
        server: SocketAddr,
        config: SocketConfig,
        tick_period: Duration,
    ) -> io::Result<Self> {
        let local = match server {
            SocketAddr::V4(_) => SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 0),
            SocketAddr::V6(_) => SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), 0),
        };
        Self::connect(local, server, config, tick_period).await
    }

    /// Binds a UDP socket to `local`, connects it to `server`, and spawns the driver
    /// loop, which immediately sends the session request and ticks every
    /// `tick_period`. A period of 1–10ms is typical.
    ///
    /// Most clients don't care about the local address and can use
    /// [`connect_to`](TokioSoeClient::connect_to), which picks one automatically.
    ///
    /// This returns as soon as the socket is bound; it does **not** wait for the
    /// session to be established. Await [`recv_event`](TokioSoeClient::recv_event)
    /// for the first [`ClientEvent::Connected`] before sending data.
    pub async fn connect(
        local: SocketAddr,
        server: SocketAddr,
        config: SocketConfig,
        tick_period: Duration,
    ) -> io::Result<Self> {
        let socket = UdpSocket::bind(local).await?;
        socket.connect(server).await?;
        let local_addr = socket.local_addr()?;

        let (command_tx, command_rx) = mpsc::unbounded_channel();
        let (event_tx, event_rx) = mpsc::unbounded_channel();

        let driver = tokio::spawn(client_drive_loop(
            socket,
            server,
            config,
            tick_period,
            command_rx,
            event_tx,
        ));

        Ok(Self {
            handle: SoeClientHandle {
                commands: command_tx,
            },
            events: event_rx,
            local_addr,
            server_addr: server,
            driver,
        })
    }

    /// Returns the local address the client socket is bound to.
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Returns the server address this client is connected to.
    pub fn server_addr(&self) -> SocketAddr {
        self.server_addr
    }

    /// Returns a cloneable handle for sending data to the server from any task.
    pub fn handle(&self) -> SoeClientHandle {
        self.handle.clone()
    }

    /// Awaits the next event from the driver loop, or `None` once the loop has
    /// stopped.
    pub async fn recv_event(&mut self) -> Option<ClientEvent> {
        self.events.recv().await
    }

    /// Aborts the driver task, stopping the client.
    pub fn abort(&self) {
        self.driver.abort();
    }
}

/// The client driver loop: owns the socket and a single-session multiplexer,
/// interleaving socket reads, periodic ticks, and commands from
/// [`SoeClientHandle`]s, flushing outgoing datagrams and forwarding events after
/// each cycle.
async fn client_drive_loop(
    socket: UdpSocket,
    server: SocketAddr,
    config: SocketConfig,
    tick_period: Duration,
    mut commands: mpsc::UnboundedReceiver<ClientCommand>,
    events: mpsc::UnboundedSender<ClientEvent>,
) {
    let mut mux = SoeMultiplexer::new(config);
    let mut tick = interval(tick_period);
    tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
    let mut buf = vec![0u8; RECV_BUFFER_SIZE].into_boxed_slice();

    // Initiate the session and flush the request immediately, rather than waiting for
    // the first tick.
    mux.connect(server, Instant::now());
    for (_addr, datagram) in mux.take_outgoing() {
        let _ = socket.send(&datagram).await;
    }

    loop {
        tokio::select! {
            result = socket.recv(&mut buf) => {
                match result {
                    Ok(len) => {
                        let datagram = Bytes::copy_from_slice(&buf[..len]);
                        mux.process_incoming(server, datagram, Instant::now());
                    }
                    // A transient receive error (e.g. ICMP port-unreachable surfaced
                    // on some platforms) shouldn't kill the client; skip and continue.
                    Err(_) => continue,
                }
            }
            _ = tick.tick() => {
                mux.run_tick(Instant::now());
            }
            command = commands.recv() => {
                match command {
                    Some(ClientCommand::EnqueueData { data, channel }) => {
                        // Fire-and-forget: if the session isn't established the data
                        // is dropped (the handle API is intentionally async and can't
                        // synchronously report this).
                        let _ = mux.enqueue_data_on(&server, &data, channel);
                    }
                    Some(ClientCommand::Terminate { reason }) => {
                        mux.terminate(&server, reason, Instant::now());
                    }
                    // All handles dropped: nothing more can drive the client.
                    None => break,
                }
            }
        }

        for (_addr, datagram) in mux.take_outgoing() {
            // A send failure for one datagram shouldn't tear down the session.
            let _ = socket.send(&datagram).await;
        }
        for event in mux.take_events() {
            // A client has a single session, so the remote address each event carries
            // is always the server; drop it for the simpler client-facing event.
            let client_event = match event {
                SocketEvent::SessionOpened { .. } => ClientEvent::Connected,
                SocketEvent::DataReceived { data, channel, .. } => {
                    ClientEvent::DataReceived { data, channel }
                }
                SocketEvent::SessionClosed { reason, .. } => ClientEvent::Disconnected { reason },
            };
            // The event receiver was dropped: no one is listening, so shut down.
            if events.send(client_event).is_err() {
                return;
            }
        }
    }
}
