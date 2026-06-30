//! A SOE ping client built on the actor-style [`TokioSoeClient`].
//!
//! Run with: `cargo run --features tokio --example client-actor -- 127.0.0.1:20260`
//! (after starting the `server-tokio` or `server-actor` example).
//!
//! This demonstrates the recommended client topology: one driver task (owned by
//! [`TokioSoeClient`]) owns the socket and all protocol state, while application
//! logic interacts with it asynchronously — receiving events and sending data back
//! through a cloneable [`SoeClientHandle`]. Here a background task replies to each
//! echo with the next ping after a short pause, a simple ping-pong.

use std::net::SocketAddr;
use std::time::Duration;

use soe_protocol::SessionParameters;
use soe_protocol::socket::SocketConfig;
use soe_protocol::tokio_rt::{ClientEvent, TokioSoeClient};

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

    let mut client = TokioSoeClient::connect(
        "127.0.0.1:0".parse().unwrap(),
        server_addr,
        config,
        Duration::from_millis(5),
    )
    .await?;
    println!(
        "client: bound to {}, connecting to {}",
        client.local_addr(),
        client.server_addr()
    );

    let handle = client.handle();
    let mut ping_count: u64 = 0;

    while let Some(event) = client.recv_event().await {
        match event {
            ClientEvent::Connected => {
                println!("client: session opened, sending first ping");
                ping_count += 1;
                handle.enqueue_data(format!("ping {ping_count}"));
            }
            ClientEvent::DataReceived { data, .. } => {
                let text = String::from_utf8_lossy(&data);
                println!("client: received echo {text:?}");
                tokio::time::sleep(Duration::from_secs(1)).await;
                ping_count += 1;
                handle.enqueue_data(format!("ping {ping_count}"));
            }
            ClientEvent::Disconnected { reason } => {
                println!("client: session closed ({reason:?})");
                return Ok(());
            }
        }
    }

    Ok(())
}
