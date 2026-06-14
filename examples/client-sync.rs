//! A minimal SOE ping client using only the synchronous, dependency-free
//! `SoeMultiplexer::drive` loop over a `std::net::UdpSocket` (no async runtime).
//!
//! Run with: `cargo run --example client-sync -- 127.0.0.1:20260`
//! (after starting the `server-sync` example).
//!
//! It connects to the server, sends a "ping", and replies to each echo with the
//! next ping after a short pause — a simple ping-pong.

use std::net::{SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

use soe_protocol::SessionParameters;
use soe_protocol::socket::{SocketConfig, SocketEvent, SoeMultiplexer};

const APP_PROTOCOL: &str = "SoePingPong";
const TICK: Duration = Duration::from_millis(5);
const PING_INTERVAL: Duration = Duration::from_secs(1);

fn main() -> std::io::Result<()> {
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

    let mut socket = UdpSocket::bind("127.0.0.1:0")?;
    socket.set_nonblocking(true)?;
    let mut mux = SoeMultiplexer::<SocketAddr>::new(config);
    println!("client: bound to {}, connecting to {server_addr}", socket.local_addr()?);
    mux.connect(server_addr, Instant::now());

    let mut ping_count: u64 = 0;
    // When set, the time at which to send the next ping.
    let mut next_ping_at: Option<Instant> = None;

    loop {
        let now = Instant::now();
        mux.drive(&mut socket, now)?;

        for event in mux.take_events() {
            match event {
                SocketEvent::SessionOpened { remote } => {
                    println!("client: session opened with {remote}, sending first ping");
                    ping_count += 1;
                    mux.enqueue_data(&remote, format!("ping {ping_count}").as_bytes());
                }
                SocketEvent::SessionClosed { remote, reason } => {
                    println!("client: session with {remote} closed ({reason:?})");
                    return Ok(());
                }
                SocketEvent::DataReceived { data, .. } => {
                    let text = String::from_utf8_lossy(&data);
                    println!("client: received echo {:?}", text);
                    next_ping_at = Some(Instant::now() + PING_INTERVAL);
                }
            }
        }

        if let Some(at) = next_ping_at
            && Instant::now() >= at
        {
            next_ping_at = None;
            ping_count += 1;
            mux.enqueue_data(&server_addr, format!("ping {ping_count}").as_bytes());
        }

        std::thread::sleep(TICK);
    }
}
