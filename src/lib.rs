//! A Rust implementation of version 3 of the SOE (Sony Online Entertainment) network protocol.
//!
//! The SOE protocol is a UDP transport layer used by various games (Free Realms, H1Z1,
//! Landmark, PlanetSide 2, etc.). It provides sessions, packet verification (CRC32),
//! optional compression (zlib), reliable/ordered data transmission, and optional
//! encryption (RC4).
//!
//! # Design
//!
//! This crate is structured as an **I/O-agnostic core**: the protocol logic is a pure state
//! machine that never touches the network or the clock directly. [`SoeSession`] (a
//! single connection) and [`SoeMultiplexer`] (many connections demultiplexed by remote
//! address) consume incoming datagrams and the current [`Instant`](std::time::Instant),
//! and produce outgoing datagrams plus [`SocketEvent`]s. You drive them from whatever
//! runtime you like.
//!
//! Ready-made adapters are provided over that core:
//!
//! * [`SyncSoeSocket`] — a blocking, dependency-free driver over [`std::net::UdpSocket`].
//! * `TokioSoeSocket` / `TokioSoeServer` — async drivers behind the `tokio` feature.
//!
//! See the `examples/` directory for runnable client/server pairs in both styles.
//!
//! # Cargo features
//!
//! * `tokio` *(off by default)* — enables the Tokio adapters (`TokioSoeSocket`,
//!   `TokioSoeServer`, `SoeHandle`). With default features the crate has no async
//!   runtime dependency.
//!
//! # Quick start
//!
//! A minimal synchronous client that connects, sends one message, and prints replies:
//!
//! ```no_run
//! use std::net::SocketAddr;
//! use std::time::Duration;
//!
//! use soe_protocol::SessionParameters;
//! use soe_protocol::socket::{SocketConfig, SocketEvent, SoeSocket};
//! use soe_protocol::sync_rt::SyncSoeSocket;
//!
//! # fn main() -> std::io::Result<()> {
//! let server: SocketAddr = "127.0.0.1:20260".parse().unwrap();
//!
//! // Both peers must agree on the application-protocol string.
//! let config = SocketConfig {
//!     default_session_params: SessionParameters {
//!         application_protocol: "MyGame".to_owned(),
//!         ..SessionParameters::default()
//!     },
//!     ..SocketConfig::default()
//! };
//!
//! let mut socket = SyncSoeSocket::bind(
//!     "127.0.0.1:0".parse().unwrap(),
//!     config,
//!     Duration::from_millis(5),
//! )?;
//! socket.connect(server);
//!
//! loop {
//!     for event in socket.step()? {
//!         match event {
//!             SocketEvent::SessionOpened { remote } => {
//!                 let _ = socket.enqueue_data(&remote, b"hello");
//!             }
//!             SocketEvent::DataReceived { data, .. } => {
//!                 println!("received {} bytes", data.len());
//!             }
//!             SocketEvent::SessionClosed { .. } => return Ok(()),
//!         }
//!     }
//! }
//! # }
//! ```

#![warn(missing_docs)]

pub mod channel;
pub mod constants;
pub(crate) mod crc32;
pub mod error;
pub(crate) mod io;
pub(crate) mod packet_utils;
pub mod packets;
pub mod protocol;
pub(crate) mod rc4;
pub mod session;
pub mod socket;
pub mod sync_rt;
#[cfg(feature = "tokio")]
pub mod tokio_rt;
pub(crate) mod varint;
pub(crate) mod zlib;

pub use error::{Error, Result};
pub use protocol::{DisconnectReason, OpCode};
pub use rc4::Rc4KeyState;
pub use session::{
    ApplicationParameters, SessionEvent, SessionMode, SessionParameters, SessionState, SoeSession,
};
pub use socket::{RemoteAddr, SocketConfig, SocketEvent, SoeMultiplexer, SoeSocket, UdpTransport};
pub use sync_rt::SyncSoeSocket;
#[cfg(feature = "tokio")]
pub use tokio_rt::{SoeHandle, TokioSoeServer, TokioSoeSocket};
