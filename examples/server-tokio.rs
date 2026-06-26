//! A minimal SOE echo server built on the `tokio` adapter.
//!
//! Run with: `cargo run --features tokio --example server-tokio -- 127.0.0.1:20260`
//!
//! It listens for SOE sessions and echoes any reliable data back to the sender.

use std::net::SocketAddr;
use std::time::Duration;

use soe_protocol::SessionParameters;
use soe_protocol::socket::{SocketConfig, SocketEvent, SoeSocket};
use soe_protocol::tokio_rt::TokioSoeSocket;

const APP_PROTOCOL: &str = "SoePingPong";

#[tokio::main]
async fn main() -> std::io::Result<()> {
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

    let mut socket = TokioSoeSocket::bind(bind_addr, config, Duration::from_millis(5)).await?;
    println!("server: listening on {}", socket.local_addr()?);

    loop {
        for event in socket.step().await? {
            match event {
                SocketEvent::SessionOpened { remote } => {
                    println!("server: session opened with {remote}");
                }
                SocketEvent::SessionClosed { remote, reason } => {
                    println!("server: session with {remote} closed ({reason:?})");
                }
                SocketEvent::DataReceived { remote, data, .. } => {
                    let text = String::from_utf8_lossy(&data);
                    println!("server: received {:?} from {remote}, echoing", text);
                    socket.enqueue_data(&remote, &data);
                }
            }
        }
    }
}
