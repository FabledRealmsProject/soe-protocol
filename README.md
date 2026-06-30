# soe-protocol

[![Build and Check](https://github.com/yungcomputerchair/soe-protocol/actions/workflows/rust.yml/badge.svg?branch=main)](https://github.com/yungcomputerchair/soe-protocol/actions/workflows/rust.yml)

A Rust implementation of the **SOE** (Sony Online Entertainment) network protocol.

SOE is a UDP transport layer used by a number of games (Free Realms, H1Z1, Landmark,
PlanetSide 2, and others). On top of raw UDP it adds:

- **Sessions** with a negotiated handshake, heartbeats, and inactivity timeouts.
- **Packet verification** via CRC32.
- **Reliable, ordered delivery** with fragmentation and reassembly (a sliding-window
  reliable data channel in each direction).
- **Optional compression** (zlib) of contextual packets.
- **Optional encryption** (RC4) of application data.

This implementation is an AI-assisted port informed by the public v3 C# and Zig implementations in
[Sanctuary.SoeProtocol](https://github.com/PS2Sanctuary/Sanctuary.SoeProtocol).

While porting, the protocol behaviour was re-derived from the reference rather than
copied, which surfaced a few improvements over it:

- **Runtime-agnostic core:** The protocol logic is a pure state machine with
  no I/O or runtime dependency. Time is passed in explicitly, datagrams are fed and
  drained as buffers, and runtime adapters (Tokio, blocking, or your own) sit on top.
  The reference couples the protocol to its host runtime.
- **Sequence-wraparound fix:** The reliable-data ack-all throttle compared a truncated
  16-bit wire sequence against a full-width counter, so after 65,536 packets the
  throttle broke and the channel spammed acknowledgements every tick. This bug is
  present in both the C# and Zig references; here sequences are tracked at full width
  and truncated only on the wire.
- **Hardened fragment reassembly:** Master-fragment parsing is guarded against hostile
  input: short fragments no longer panic, and the attacker-controlled reassembly length
  can no longer trigger a multi-gigabyte preallocation (both are bounded and answered
  with a `CorruptPacket` disconnect). The reference shares this gap.
- **Multi-packet short-circuit:** Processing a bundled multi-packet now stops as soon as
  a sub-packet terminates the session, instead of continuing to act on later sub-packets
  of an already-closed session.
- **Idiomatic, defensive Rust API:** Public types implement `Debug` (with the RC4 key
  state redacted), data-enqueue calls are `#[must_use]` so dropped payloads can't pass
  silently, and the parse paths are exercised by an end-to-end fuzz suite and the ported
  regression tests.

On top of that, this crate adds some v2 protocol features for backwards compatibility with older games,
with [SWG-Source](https://github.com/SWG-Source/src/tree/master/external/3rd/library/soePlatform/ChatAPI/utils/UdpLibrary)
and [OSFR Sanctuary](https://github.com/Open-Source-Free-Realms/Sanctuary/tree/main/src/Sanctuary.UdpLibrary) used as references:

- Opt-in unreliable data channel for lossy, unordered delivery of non-critical packets (e.g. movement updates).
- Multiple (4) reliable data channels per session.

## Design: an I/O-agnostic core

The crate is structured as an **I/O-agnostic core**: all protocol logic is a pure state
machine that performs no I/O and reads no clock. Time is supplied by the caller as a
`std::time::Instant`, and bytes are handed in and out explicitly. This keeps the core
runtime-agnostic, deterministic, and easy to test, with thin adapters layered on top
for real-world I/O.

```
        ┌─────────────────────────── adapters (opt-in) ───────────────────────────┐
        │  SyncSoeSocket (std)   TokioSoeSocket (feature = "tokio")                 │
        │                        TokioSoeServer + SoeHandle (feature = "tokio")     │
        └──────────────────────────────────┬───────────────────────────────────────┘
                                            │ drives
        ┌───────────────────────────────────▼──────────────────────────────────────┐
        │  SoeMultiplexer<A>   — demultiplexes many sessions by remote address       │
        │  SoeSession          — one session's state machine                         │
        │  channels / packets / crc32 / rc4 / zlib / varint — protocol primitives    │
        └───────────────────────────────────────────────────────────────────────────┘
```

- **`SoeSession`** — the state machine for a single session: handshake, reliable
  channels, heartbeats, and termination.
- **`SoeMultiplexer<A>`** — demultiplexes datagrams from many remotes (generic over
  the address type `A`) into per-session `SoeSession`s. You feed it incoming datagrams
  and ticks; it surfaces datagrams to send and lifecycle/data events.
- **Adapters** — optional convenience drivers that own a real socket and pump the
  core. The default build pulls in **zero** async dependencies; the Tokio adapters are
  gated behind the `tokio` feature.

## Installation

In your project:

```
cargo add soe-protocol
```

or, for the Tokio adapters:

```
cargo add soe-protocol --features tokio
```

Requires Rust 1.88+ (edition 2024).

## Quick start

Configure a socket with the application protocol both peers agree on, then drive it.
The synchronous adapter needs no extra dependencies:

```rust
use std::time::Duration;
use soe_protocol::{SessionParameters, SyncSoeSocket};
use soe_protocol::socket::{SocketConfig, SocketEvent, SoeSocket};

let config = SocketConfig {
    default_session_params: SessionParameters {
        application_protocol: "MyGame".to_owned(),
        ..SessionParameters::default()
    },
    ..SocketConfig::default()
};

// Bind and tick every 5ms.
let mut socket = SyncSoeSocket::bind("0.0.0.0:20260".parse().unwrap(), config, Duration::from_millis(5))?;

loop {
    // One read-or-tick cycle; returns any events produced.
    for event in socket.step()? {
        match event {
            SocketEvent::SessionOpened { remote } => println!("opened {remote}"),
            SocketEvent::DataReceived { remote, data, channel } => {
                socket.enqueue_data_on(&remote, &data, channel); // echo it back
            }
            SocketEvent::SessionClosed { remote, reason } => println!("closed {remote}: {reason:?}"),
        }
    }
}
# Ok::<(), std::io::Error>(())
```

To act as a client, call `socket.connect(server_addr)` instead of waiting for an
inbound session.

## Channels: reliable and unreliable delivery

`enqueue_data` sends on reliable channel 0 — ordered, acknowledged, retransmitted, and
(if a cipher is configured) encrypted. That is the right default for anything that must
arrive, but games also carry a firehose of state that is only useful if it is _fresh_:
position, camera, and animation updates where a dropped packet should be discarded, not
resent behind a head-of-line stall.

For that, select the channel explicitly with `enqueue_data_on` (here `socket` is the
`SoeMultiplexer`/adapter from the quick start, and `Channel` comes from the crate root):

```rust
use soe_protocol::Channel;

// Best-effort: sent once, never acked, may be dropped or reordered, never encrypted.
socket.enqueue_data_on(&remote, b"position update", Channel::Unreliable);

// One of up to four independent reliable channels (0..=3), each with its own
// sequence space and cipher stream. `Reliable(0)` is what `enqueue_data` uses.
socket.enqueue_data_on(&remote, b"chat message", Channel::Reliable(1));
```

Received data is tagged with the channel it arrived on, so a peer can route or
prioritise by delivery class:

```rust
SocketEvent::DataReceived { remote, data, channel } => match channel {
    Channel::Reliable(n) => { /* ordered application data on channel n */ }
    Channel::Unreliable => { /* best-effort; safe to drop if stale */ }
}
```

Unreliable data that would exceed the remote's maximum UDP payload is transparently
promoted to reliable channel 0 (matching the reference UdpLibrary), so a large "best
effort" message is never silently dropped for being too big. The four reliable channels
are created lazily on first use; most sessions only ever touch channel 0.

## Writing a game server

UDP has no per-connection socket: every client's datagrams arrive on the one bound
socket, and a SOE session is inherently single-owner (sequence numbers, RC4 cipher
state, and fragment reassembly must be mutated by one task at a time). So rather than a
socket-per-client task as you might use with TCP, the recommended shape is **one driver
task that owns the socket and all protocol state, with per-client game logic running on
its own tasks**, talking to the driver over channels.

The `tokio` feature provides this out of the box via **`TokioSoeServer`** and its
cloneable **`SoeHandle`**:

```rust
use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::Duration;
use bytes::Bytes;
use soe_protocol::SessionParameters;
use soe_protocol::socket::{SocketConfig, SocketEvent};
use soe_protocol::tokio_rt::{SoeHandle, TokioSoeServer};
use tokio::sync::mpsc;

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let config = SocketConfig {
        default_session_params: SessionParameters {
            application_protocol: "MyGame".to_owned(),
            ..SessionParameters::default()
        },
        ..SocketConfig::default()
    };

    // The driver task owns the socket and all protocol state.
    let mut server = TokioSoeServer::bind("0.0.0.0:20260".parse().unwrap(), config, Duration::from_millis(5)).await?;

    // One inbound channel per connected client; each client task owns its receiver.
    let mut clients: HashMap<SocketAddr, mpsc::UnboundedSender<Bytes>> = HashMap::new();

    while let Some(event) = server.recv_event().await {
        match event {
            SocketEvent::SessionOpened { remote } => {
                let (tx, rx) = mpsc::unbounded_channel();
                clients.insert(remote, tx);
                tokio::spawn(client_task(remote, server.handle(), rx));
            }
            SocketEvent::DataReceived { remote, data, .. } => {
                if let Some(tx) = clients.get(&remote) {
                    let _ = tx.send(data); // route to that client's task
                }
            }
            SocketEvent::SessionClosed { remote, .. } => {
                clients.remove(&remote);
            }
        }
    }
    Ok(())
}

// Per-client game logic runs concurrently and replies via the shared handle.
async fn client_task(remote: SocketAddr, handle: SoeHandle, mut inbound: mpsc::UnboundedReceiver<Bytes>) {
    while let Some(data) = inbound.recv().await {
        handle.enqueue_data(remote, data); // echo
    }
}
```

`SoeHandle` is `Clone`/`Send` and exposes `connect`, `enqueue_data`,
`enqueue_data_on` (to pick a channel, as above), and `terminate`; all are non-blocking
and simply post a command to the driver loop. Events are received in an order that
guarantees a session's `SessionOpened` is surfaced **before** any of its
`DataReceived`, and `SessionClosed` **after** — so per-session state (like the task
spawned above) is always in place before that session's data arrives.

### Scaling across cores

A single UDP receive loop comfortably dispatches far more packets per second than a
game simulation typically consumes, so one `TokioSoeServer` is usually plenty. If
profiling ever shows the I/O task saturating a core, scale out by running several
servers — one per `SO_REUSEPORT` socket — and routing by client address. Because each
server owns its own socket and `SoeMultiplexer`, this requires no changes to the core.

## Writing a game client

A client talks to a single server, so it needs neither the per-remote routing of a
server nor a raw step loop. The `tokio` feature provides **`TokioSoeClient`**: an
actor-style client whose driver task owns the socket and the one session, reachable
from any task via a cloneable **`SoeClientHandle`**.

```rust
use std::net::SocketAddr;
use std::time::Duration;
use soe_protocol::SessionParameters;
use soe_protocol::socket::SocketConfig;
use soe_protocol::tokio_rt::{ClientEvent, TokioSoeClient};

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let server: SocketAddr = "127.0.0.1:20260".parse().unwrap();

    let config = SocketConfig {
        default_session_params: SessionParameters {
            application_protocol: "MyGame".to_owned(),
            ..SessionParameters::default()
        },
        ..SocketConfig::default()
    };

    // Binds an ephemeral local port, connects the socket to the server, and sends
    // the session request. Use `connect` to pin a specific local address.
    let mut client = TokioSoeClient::connect_to(
        server,
        config,
        Duration::from_millis(5),
    )
    .await?;

    // A cloneable handle can send data from any task.
    let handle = client.handle();

    while let Some(event) = client.recv_event().await {
        match event {
            ClientEvent::Connected => {
                handle.enqueue_data(b"hello".to_vec()); // first event; safe to send now
            }
            ClientEvent::DataReceived { data, .. } => {
                println!("received {} bytes", data.len());
            }
            ClientEvent::Disconnected { reason } => {
                println!("disconnected: {reason:?}");
                break;
            }
        }
    }
    Ok(())
}
```

`connect` returns as soon as the socket is bound; the first `ClientEvent` is always
`Connected`, after which it is safe to send. `SoeClientHandle` is `Clone`/`Send` and
exposes `enqueue_data`, `enqueue_data_on` (to pick a channel), and `terminate` — all
non-blocking, and none requiring a remote address since the server is implied.

## Examples

Runnable examples live in [`examples/`](examples/):

| Example                         | Feature | Description                                     |
| ------------------------------- | ------- | ----------------------------------------------- |
| `server-sync` / `client-sync`   | —       | Blocking, std-only echo server and ping client. |
| `server-tokio` / `client-tokio` | `tokio` | Async echo server and ping client.              |
| `server-actor` / `client-actor` | `tokio` | Actor-style skeletons: per-client-task fan-out (server) and a driver-task client. |

Run a ping-pong over real UDP:

```sh
# std-only
cargo run --example server-sync -- 127.0.0.1:20260
cargo run --example client-sync -- 127.0.0.1:20260

# Tokio
cargo run --features tokio --example server-tokio -- 127.0.0.1:20260
cargo run --features tokio --example client-tokio -- 127.0.0.1:20260

# Actor-style game server
cargo run --features tokio --example server-actor -- 127.0.0.1:20260
cargo run --features tokio --example client-tokio -- 127.0.0.1:20260

# Actor-style client
cargo run --features tokio --example server-tokio -- 127.0.0.1:20260
cargo run --features tokio --example client-actor -- 127.0.0.1:20260
```

## Bring your own runtime

You don't need either bundled adapter. The core, `SoeMultiplexer`, has no I/O
dependency: feed it incoming datagrams with `process_incoming(remote, datagram, now)`,
call `run_tick(now)` periodically, and flush whatever `take_outgoing()` returns over
your own socket, reading events from `take_events()`. The `UdpTransport` trait and
`SoeMultiplexer::drive` offer a minimal, dependency-free seam for any non-blocking UDP
socket (with a blanket impl for `std::net::UdpSocket`).

## License

Licensed under GPL-3.0-or-later. See [LICENSE](LICENSE).
