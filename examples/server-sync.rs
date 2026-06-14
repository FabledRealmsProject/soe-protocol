//! A minimal SOE echo server using only the synchronous, dependency-free
//! `SoeMultiplexer::drive` loop over a `std::net::UdpSocket` (no async runtime).
//!
//! Run with: `cargo run --example server-sync -- 127.0.0.1:20260`
//!
//! It listens for SOE sessions and echoes any reliable data back to the sender.

use std::net::{SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

use soe_protocol::SessionParameters;
use soe_protocol::socket::{SocketConfig, SocketEvent, SoeMultiplexer};

const APP_PROTOCOL: &str = "SoePingPong";
const TICK: Duration = Duration::from_millis(5);

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

    let mut socket = UdpSocket::bind(bind_addr)?;
    socket.set_nonblocking(true)?;
    let mut mux = SoeMultiplexer::<SocketAddr>::new(config);
    println!("server: listening on {}", socket.local_addr()?);

    loop {
        mux.drive(&mut socket, Instant::now())?;

        for event in mux.take_events() {
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
                    mux.enqueue_data(&remote, &data);
                }
            }
        }

        std::thread::sleep(TICK);
    }
}
