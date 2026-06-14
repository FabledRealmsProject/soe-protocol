//! A Rust implementation of version 3 of the SOE (Sony Online Entertainment) network protocol.
//!
//! The SOE protocol is a UDP transport layer used by various games (Free Realms, H1Z1,
//! Landmark, PlanetSide 2, etc.). It provides sessions, packet verification (CRC32),
//! optional compression (zlib), reliable/ordered data transmission, and optional
//! encryption (RC4).
//!
//! This crate is structured as a sans-I/O core: the protocol logic is a pure state
//! machine, with runtime-agnostic adapters layered on top.

pub mod channel;
pub mod constants;
pub mod crc32;
pub mod error;
pub mod io;
pub mod packet_utils;
pub mod packets;
pub mod protocol;
pub mod rc4;
pub mod varint;
pub mod zlib;

pub use error::{Error, Result};
pub use protocol::{DisconnectReason, OpCode};
