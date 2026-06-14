//! A minimal SOE echo server using the synchronous, dependency-free
//! [`SyncSoeSocket`] driver (no async runtime).
//!
//! Run with: `cargo run --example server-sync -- 127.0.0.1:20260`
//!
//! It listens for SOE sessions and echoes any reliable data back to the sender.

use std::net::SocketAddr;
use std::time::Duration;

use soe_protocol::SessionParameters;
use soe_protocol::socket::{SocketConfig, SocketEvent, SoeSocket};
use soe_protocol::sync_rt::SyncSoeSocket;

const APP_PROTOCOL: &str = "SoePingPong";

fn main() -> std::io::Result<()> {
    let bind_addr: SocketAddr = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:20260".to_owned())
        .parse()
        .expect("a valid bind address");

    let config = SocketConfig {
        default_session_params: SessionParameters {
            application_protocol: APP_PROTOCOL.to_owned(),
            ..SessionParameters::default()
        },
        ..SocketConfig::default()
    };

    let mut socket = SyncSoeSocket::bind(bind_addr, config, Duration::from_millis(5))?;
    println!("server: listening on {}", socket.local_addr()?);

    loop {
        for event in socket.step()? {
            match event {
                SocketEvent::SessionOpened { remote } => {
                    println!("server: session opened with {remote}");
                }
                SocketEvent::SessionClosed { remote, reason } => {
                    println!("server: session with {remote} closed ({reason:?})");
                }
                SocketEvent::DataReceived { remote, data } => {
                    let text = String::from_utf8_lossy(&data);
                    println!("server: received {:?} from {remote}, echoing", text);
                    socket.enqueue_data(&remote, &data);
                }
            }
        }
    }
}
