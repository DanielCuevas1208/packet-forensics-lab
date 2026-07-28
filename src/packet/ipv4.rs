//! IPv4 header decoder (no options, no fragmentation reassembly).

use std::net::Ipv4Addr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Protocol {
    Udp,
    Tcp,
    Other(u8),
}

pub struct Header<'a> {
    pub src: Ipv4Addr,
    pub dst: Ipv4Addr,
    pub ttl: u8,
    pub protocol: Protocol,
    pub payload: &'a [u8],
}

/// Decode an IPv4 packet. Returns `None` if truncated or if the
/// Internet Header Length is invalid.
pub fn decode(data: &[u8]) -> Option<Header<'_>> {
    if data.len() < 20 {
        return None;
    }
    let ver_ihl = data[0];
    if (ver_ihl >> 4) != 4 {
        return None;
    }
    let ihl = (ver_ihl & 0x0F) as usize * 4;
    if ihl < 20 || data.len() < ihl {
        return None;
    }
    let protocol = match data[9] {
        17 => Protocol::Udp,
        6 => Protocol::Tcp,
        other => Protocol::Other(other),
    };
    let src = Ipv4Addr::new(data[12], data[13], data[14], data[15]);
    let dst = Ipv4Addr::new(data[16], data[17], data[18], data[19]);
    Some(Header {
        src,
        dst,
        ttl: data[8],
        protocol,
        payload: &data[ihl..],
    })
}
