//! Minimal classic-libpcap parser.
//!
//! The module reads the legacy pcap container used by tcpdump and Wireshark.
//! It supports Ethernet (link type 1) only, which the bundled fixtures use.
//! PCAPNG is intentionally out of scope for the first release.

use crate::error::{ForensicsError, Result};

/// A single captured packet with its wall-clock timestamp.
#[derive(Debug, Clone)]
pub struct Record {
    /// Seconds since the Unix epoch.
    pub ts_secs: u64,
    /// Microseconds (or nanoseconds when `nano` is set) within the second.
    pub ts_frac: u32,
    /// The captured payload follows the link-layer header.
    pub data: Vec<u8>,
}

impl Record {
    /// Time in microseconds since the Unix epoch.
    pub fn micros(&self, nano: bool) -> u64 {
        let frac = if nano {
            self.ts_frac / 1000
        } else {
            self.ts_frac
        };
        self.ts_secs
            .saturating_mul(1_000_000)
            .saturating_add(frac as u64)
    }
}

/// The parsed container.
#[derive(Debug)]
pub struct Capture {
    pub link_type: u32,
    pub nano: bool,
    pub records: Vec<Record>,
}

impl Capture {
    /// Span of the capture in microseconds. Returns zero for empty input.
    pub fn span_micros(&self) -> u64 {
        let Some(first) = self.records.first() else {
            return 0;
        };
        let Some(last) = self.records.last() else {
            return 0;
        };
        last.micros(self.nano)
            .saturating_sub(first.micros(self.nano))
    }
}

const MAGIC_BE: u32 = 0xA1B2_C3D4;
const MAGIC_LE: u32 = 0xD4C3_B2A1;
const MAGIC_NANO_BE: u32 = 0xA1B2_3C4D;
const MAGIC_NANO_LE: u32 = 0x4D3C_B2A1;

const LINK_ETHERNET: u32 = 1;

/// Parse a complete pcap byte buffer into a [`Capture`].
pub fn parse(bytes: &[u8]) -> Result<Capture> {
    if bytes.len() < 24 {
        return Err(ForensicsError::BadPcap("file shorter than global header"));
    }
    let magic = u32::from_le_bytes(bytes[0..4].try_into().unwrap());
    let (swap, nano) = match magic {
        MAGIC_LE => (false, false),
        MAGIC_BE => (true, false),
        MAGIC_NANO_LE => (false, true),
        MAGIC_NANO_BE => (true, true),
        _ => return Err(ForensicsError::BadPcap("unknown magic number")),
    };

    let read_u16 = |b: &[u8]| -> u16 {
        let a: [u8; 2] = b.try_into().unwrap();
        if swap {
            u16::from_be_bytes(a)
        } else {
            u16::from_le_bytes(a)
        }
    };
    let read_u32 = |b: &[u8]| -> u32 {
        let a: [u8; 4] = b.try_into().unwrap();
        if swap {
            u32::from_be_bytes(a)
        } else {
            u32::from_le_bytes(a)
        }
    };

    let _version_major = read_u16(&bytes[4..6]);
    let _version_minor = read_u16(&bytes[6..8]);
    let _thiszone = read_u32(&bytes[8..12]);
    let _sigfigs = read_u32(&bytes[12..16]);
    let _snaplen = read_u32(&bytes[16..20]);
    let link_type = read_u32(&bytes[20..24]);

    if link_type != LINK_ETHERNET {
        return Err(ForensicsError::UnsupportedLink(link_type));
    }

    let mut off = 24usize;
    let mut records = Vec::new();
    while off + 16 <= bytes.len() {
        let ts_secs = read_u32(&bytes[off..off + 4]) as u64;
        let ts_frac = read_u32(&bytes[off + 4..off + 8]);
        let incl_len = read_u32(&bytes[off + 8..off + 12]) as usize;
        let _orig_len = read_u32(&bytes[off + 12..off + 16]);
        off += 16;
        if off + incl_len > bytes.len() {
            return Err(ForensicsError::BadPcap("record length exceeds file"));
        }
        let data = bytes[off..off + incl_len].to_vec();
        off += incl_len;
        records.push(Record {
            ts_secs,
            ts_frac,
            data,
        });
    }
    if off != bytes.len() {
        return Err(ForensicsError::BadPcap("trailing bytes after final record"));
    }

    Ok(Capture {
        link_type,
        nano,
        records,
    })
}

/// Writer that emits a little-endian pcap stream. Used by the fixture generator.
pub fn write(records: &[WriteRecord], link_type: u32) -> Vec<u8> {
    let mut out = Vec::with_capacity(24 + records.len() * 40);
    out.extend_from_slice(&MAGIC_LE.to_le_bytes());
    out.extend_from_slice(&2u16.to_le_bytes()); // major
    out.extend_from_slice(&4u16.to_le_bytes()); // minor
    out.extend_from_slice(&0i32.to_le_bytes()); // thiszone
    out.extend_from_slice(&0u32.to_le_bytes()); // sigfigs
    out.extend_from_slice(&65_535u32.to_le_bytes()); // snaplen
    out.extend_from_slice(&link_type.to_le_bytes());
    for r in records {
        let secs = r.ts_secs;
        let usec = r.ts_usec;
        out.extend_from_slice(&secs.to_le_bytes());
        out.extend_from_slice(&usec.to_le_bytes());
        out.extend_from_slice(&(r.data.len() as u32).to_le_bytes());
        out.extend_from_slice(&(r.data.len() as u32).to_le_bytes());
        out.extend_from_slice(&r.data);
    }
    out
}

/// Input record for the pcap writer.
#[derive(Debug, Clone)]
pub struct WriteRecord {
    pub ts_secs: u32,
    pub ts_usec: u32,
    pub data: Vec<u8>,
}
