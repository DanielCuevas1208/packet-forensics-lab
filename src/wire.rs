//! Wire-format encoders used to craft deterministic fixtures.
//!
//! Checksums are written as zeros because the bundled parser never verifies
//! them. The encoders keep the produced bytes small and readable.

use crate::packet::dns;
use std::net::Ipv4Addr;

/// Build an Ethernet/IPv4/UDP datagram.
#[allow(clippy::too_many_arguments)]
pub fn udp_packet(
    dst_mac: [u8; 6],
    src_mac: [u8; 6],
    src: Ipv4Addr,
    dst: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    let udp = udp_datagram(src_port, dst_port, payload);
    let ipv4 = ipv4_packet(src, dst, 17, &udp);
    ethernet_frame(dst_mac, src_mac, 0x0800, &ipv4)
}

/// Build an Ethernet/IPv4/TCP segment with chosen flags and no payload.
#[allow(clippy::too_many_arguments)]
pub fn tcp_segment_packet(
    dst_mac: [u8; 6],
    src_mac: [u8; 6],
    src: Ipv4Addr,
    dst: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    flags: u16,
    payload: &[u8],
) -> Vec<u8> {
    let tcp = tcp_segment(src_port, dst_port, flags, payload);
    let ipv4 = ipv4_packet(src, dst, 6, &tcp);
    ethernet_frame(dst_mac, src_mac, 0x0800, &ipv4)
}

pub fn ethernet_frame(dst: [u8; 6], src: [u8; 6], ethertype: u16, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(14 + payload.len());
    out.extend_from_slice(&dst);
    out.extend_from_slice(&src);
    out.extend_from_slice(&ethertype.to_be_bytes());
    out.extend_from_slice(payload);
    out
}

pub fn ipv4_packet(src: Ipv4Addr, dst: Ipv4Addr, protocol: u8, payload: &[u8]) -> Vec<u8> {
    let total = 20 + payload.len();
    let mut out = Vec::with_capacity(total);
    out.push(0x45); // version 4, IHL 5
    out.push(0x00); // DSCP/ECN
    out.extend_from_slice(&(total as u16).to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes()); // identification
    out.extend_from_slice(&0x4000u16.to_be_bytes()); // flags: DF, frag offset 0
    out.push(64); // TTL
    out.push(protocol);
    out.extend_from_slice(&0u16.to_be_bytes()); // checksum (not verified)
    out.extend_from_slice(&src.octets());
    out.extend_from_slice(&dst.octets());
    out.extend_from_slice(payload);
    out
}

pub fn udp_datagram(src_port: u16, dst_port: u16, payload: &[u8]) -> Vec<u8> {
    let length = 8 + payload.len();
    let mut out = Vec::with_capacity(length);
    out.extend_from_slice(&src_port.to_be_bytes());
    out.extend_from_slice(&dst_port.to_be_bytes());
    out.extend_from_slice(&(length as u16).to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes()); // checksum (not verified)
    out.extend_from_slice(payload);
    out
}

pub fn tcp_segment(src_port: u16, dst_port: u16, flags: u16, payload: &[u8]) -> Vec<u8> {
    let offset = 5u16;
    let mut out = Vec::with_capacity(20 + payload.len());
    out.extend_from_slice(&src_port.to_be_bytes());
    out.extend_from_slice(&dst_port.to_be_bytes());
    out.extend_from_slice(&0u32.to_be_bytes()); // sequence
    out.extend_from_slice(&0u32.to_be_bytes()); // ack
    let data_off_flags = (offset << 12) | (flags & 0x01FF);
    out.extend_from_slice(&data_off_flags.to_be_bytes());
    out.extend_from_slice(&0xFFFFu16.to_be_bytes()); // window
    out.extend_from_slice(&0u16.to_be_bytes()); // checksum
    out.extend_from_slice(&0u16.to_be_bytes()); // urgent pointer
    out.extend_from_slice(payload);
    out
}

/// Encode a DNS query for the given name and type.
pub fn dns_query(id: u16, name: &str, qtype: u16) -> Vec<u8> {
    let mut out = Vec::with_capacity(32);
    out.extend_from_slice(&id.to_be_bytes());
    out.extend_from_slice(&0x0100u16.to_be_bytes()); // recursion desired
    out.extend_from_slice(&1u16.to_be_bytes()); // qdcount
    out.extend_from_slice(&0u16.to_be_bytes()); // ancount
    out.extend_from_slice(&0u16.to_be_bytes()); // nscount
    out.extend_from_slice(&0u16.to_be_bytes()); // arcount
    encode_name(&mut out, name);
    out.extend_from_slice(&qtype.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes()); // IN
    out
}

/// Encode a DNS response with one answer of the given type and rdata.
pub fn dns_response(id: u16, name: &str, qtype: u16, flags: u16, answers: &[DnsAnswer]) -> Vec<u8> {
    let mut out = Vec::with_capacity(64);
    out.extend_from_slice(&id.to_be_bytes());
    let flags = flags | 0x8000; // QR response
    out.extend_from_slice(&flags.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes()); // qdcount
    out.extend_from_slice(&(answers.len() as u16).to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    encode_name(&mut out, name);
    out.extend_from_slice(&qtype.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes());
    for a in answers {
        encode_name(&mut out, &a.name);
        out.extend_from_slice(&a.rtype.to_be_bytes());
        out.extend_from_slice(&1u16.to_be_bytes()); // IN
        out.extend_from_slice(&a.ttl.to_be_bytes());
        out.extend_from_slice(&(a.rdata.len() as u16).to_be_bytes());
        out.extend_from_slice(&a.rdata);
    }
    out
}

/// One answer populated by callers of [`dns_response`].
#[derive(Debug, Clone)]
pub struct DnsAnswer {
    pub name: String,
    pub rtype: u16,
    pub ttl: u32,
    pub rdata: Vec<u8>,
}

impl DnsAnswer {
    pub fn a(name: &str, addr: Ipv4Addr) -> Self {
        Self {
            name: name.to_string(),
            rtype: dns::rtype::A,
            ttl: 300,
            rdata: addr.octets().to_vec(),
        }
    }
    pub fn txt(name: &str, text: &str) -> Self {
        let mut rdata = Vec::with_capacity(text.len() + 1);
        rdata.push(text.len() as u8);
        rdata.extend_from_slice(text.as_bytes());
        Self {
            name: name.to_string(),
            rtype: dns::rtype::TXT,
            ttl: 300,
            rdata,
        }
    }
    pub fn cname(name: &str, target: &str) -> Self {
        let mut rdata = Vec::new();
        encode_name(&mut rdata, target);
        Self {
            name: name.to_string(),
            rtype: dns::rtype::CNAME,
            ttl: 300,
            rdata,
        }
    }
}

/// Encode a domain name in DNS wire format without compression.
pub fn encode_name(out: &mut Vec<u8>, name: &str) {
    for label in name.split('.') {
        if label.is_empty() {
            continue;
        }
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
}
