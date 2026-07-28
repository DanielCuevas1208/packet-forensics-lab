//! Packet Forensics Lab library.
//!
//! The library reads bundled packet captures, decodes the Ethernet/IPv4/UDP/TCP
//! and DNS layers, and explains DNS, connection, and timing anomalies. It never
//! performs active scanning and never opens a socket.

pub mod analysis;
pub mod error;
pub mod fixtures;
pub mod loader;
pub mod packet;
pub mod pcap;
pub mod render;
pub mod tui;
pub mod wire;
