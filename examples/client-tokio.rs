//! A minimal SOE ping client built on the `tokio` adapter.
//!
//! Run with: `cargo run --features tokio --example client-tokio -- 127.0.0.1:20260`
//! (after starting the `server-tokio` example).
//!
//! It connects to the server, sends a "ping", and replies to each echo with the
//! next ping after a short pause — a simple ping-pong.

use std::net::SocketAddr;
use std::time::Duration;

use soe_protocol::SessionParameters;
use soe_protocol::socket::{SocketConfig, SocketEvent, SoeSocket};
use soe_protocol::tokio_rt::TokioSoeSocket;

const APP_PROTOCOL: &str = "SoePingPong";

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let server_addr: SocketAddr = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:20260".to_owned())
        .parse()
        .expect("a valid server address");

    let config = SocketConfig {
        default_session_params: SessionParameters {
            application_protocol: APP_PROTOCOL.to_owned(),
            ..SessionParameters::default()
        },
        ..SocketConfig::default()
    };

    let mut socket =
        TokioSoeSocket::bind("127.0.0.1:0".parse().unwrap(), config, Duration::from_millis(5))
            .await?;
    println!("client: bound to {}, connecting to {server_addr}", socket.local_addr()?);
    socket.connect(server_addr);

    let mut ping_count: u64 = 0;

    loop {
        for event in socket.step().await? {
            match event {
                SocketEvent::SessionOpened { remote } => {
                    println!("client: session opened with {remote}, sending first ping");
                    ping_count += 1;
                    socket.enqueue_data(&remote, format!("ping {ping_count}").as_bytes());
                }
                SocketEvent::SessionClosed { remote, reason } => {
                    println!("client: session with {remote} closed ({reason:?})");
                    return Ok(());
                }
                SocketEvent::DataReceived { remote, data } => {
                    let text = String::from_utf8_lossy(&data);
                    println!("client: received echo {:?}", text);
                    tokio::time::sleep(Duration::from_secs(1)).await;
                    ping_count += 1;
                    socket.enqueue_data(&remote, format!("ping {ping_count}").as_bytes());
                }
            }
        }
    }
}
