//! Protocol decoders used by the forensics analysis.
//!
//! Each decoder accepts the raw bytes for its layer and returns a header
//! borrow plus the remaining payload. The parsers never allocate beyond
//! the returned structures and never touch the network.

pub mod dns;
pub mod ethernet;
pub mod ipv4;
pub mod tcp;
pub mod udp;

use crate::error::Result;
use std::net::Ipv4Addr;

/// A decoded packet flow.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Flow {
    pub src: Ipv4Addr,
    pub dst: Ipv4Addr,
    pub src_port: u16,
    pub dst_port: u16,
    pub proto: Proto,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Proto {
    Udp,
    Tcp,
}

/// A decoded packet pulled out of a capture record.
#[derive(Debug, Clone)]
pub struct Frame {
    pub flow: Flow,
    /// TCP flags observed. Zero for UDP.
    pub tcp_flags: u16,
    /// Transport-layer payload (DNS, application bytes).
    pub payload: Vec<u8>,
    pub ts_micros: u64,
    /// Capture size in bytes including the link header.
    pub wire_len: usize,
}

/// Decode the ethernet framing for one record.
pub fn decode_record(data: &[u8], ts_micros: u64) -> Result<Option<Frame>> {
    let wire_len = data.len();
    let Some(eth) = ethernet::decode(data) else {
        return Ok(None);
    };
    if eth.ethertype != ethernet::ETH_IPV4 {
        return Ok(None);
    }
    let Some(ipv4) = ipv4::decode(eth.payload) else {
        return Ok(None);
    };
    let proto;
    let (src_port, dst_port, tcp_flags, payload) = match ipv4.protocol {
        ipv4::Protocol::Udp => {
            let Some(u) = udp::decode(ipv4.payload) else {
                return Ok(None);
            };
            proto = Proto::Udp;
            (u.src_port, u.dst_port, 0, u.payload.to_vec())
        }
        ipv4::Protocol::Tcp => {
            let Some(t) = tcp::decode(ipv4.payload) else {
                return Ok(None);
            };
            proto = Proto::Tcp;
            (t.src_port, t.dst_port, t.flags, t.payload.to_vec())
        }
        _ => return Ok(None),
    };
    Ok(Some(Frame {
        flow: Flow {
            src: ipv4.src,
            dst: ipv4.dst,
            src_port,
            dst_port,
            proto,
        },
        tcp_flags,
        payload,
        ts_micros,
        wire_len,
    }))
}

/// True when `b` is a SYN flag combination without payload.
pub fn is_syn(flags: u16) -> bool {
    flags & tcp::FLAG_SYN != 0 && flags & tcp::FLAG_ACK == 0
}
