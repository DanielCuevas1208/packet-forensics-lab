//! Error types for the packet-forensics lab.

use std::fmt;

/// A failure that occurs while a capture is read or decoded.
#[derive(Debug)]
pub enum ForensicsError {
    /// A file could not be opened or read.
    Io(String, std::io::Error),
    /// The pcap container held bytes that do not match the format.
    BadPcap(&'static str),
    /// A single packet was truncated past a protocol boundary.
    Truncated(&'static str),
    /// A supported link type was not present in the capture.
    UnsupportedLink(u32),
}

impl ForensicsError {
    pub fn io(path: impl Into<String>, e: std::io::Error) -> Self {
        Self::Io(path.into(), e)
    }
}

impl fmt::Display for ForensicsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(p, e) => write!(f, "read failed for {p}: {e}"),
            Self::BadPcap(msg) => write!(f, "invalid pcap container: {msg}"),
            Self::Truncated(msg) => write!(f, "truncated packet: {msg}"),
            Self::UnsupportedLink(l) => write!(f, "unsupported link type {l}"),
        }
    }
}

impl std::error::Error for ForensicsError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(_, e) => Some(e),
            _ => None,
        }
    }
}

pub type Result<T> = std::result::Result<T, ForensicsError>;
