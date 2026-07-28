//! Protocol decoders exercised against crafted wire bytes.

use packet_forensics_lab::packet::{self, dns, tcp, Proto};
use packet_forensics_lab::wire;
use std::net::Ipv4Addr;

#[test]
fn decodes_udp_dns_query_flow() {
    let src = Ipv4Addr::new(10, 0, 0, 5);
    let dst = Ipv4Addr::new(10, 0, 0, 1);
    let payload = wire::dns_query(0x42, "mail.example.com", dns::rtype::A);
    let frame = wire::udp_packet([1; 6], [2; 6], src, dst, 50_000, 53, &payload);
    let parsed = packet::decode_record(&frame, 0).unwrap().unwrap();
    assert_eq!(parsed.flow.proto, Proto::Udp);
    assert_eq!(parsed.flow.src, src);
    assert_eq!(parsed.flow.dst, dst);
    assert_eq!(parsed.flow.dst_port, 53);
    let msg = dns::parse(&parsed.payload).unwrap();
    assert!(!msg.is_response());
    assert_eq!(msg.qname(), Some("mail.example.com"));
    assert_eq!(msg.qtype(), Some(dns::rtype::A));
}

#[test]
fn decodes_tcp_syn_segment_flow() {
    let frame = wire::tcp_segment_packet(
        [0; 6],
        [0; 6],
        Ipv4Addr::new(10, 0, 0, 5),
        Ipv4Addr::new(192, 0, 2, 9),
        40_000,
        22,
        0x0002,
        &[],
    );
    let parsed = packet::decode_record(&frame, 1).unwrap().unwrap();
    assert_eq!(parsed.flow.proto, Proto::Tcp);
    assert!(packet::is_syn(parsed.tcp_flags));
    assert_eq!(parsed.flow.dst_port, 22);
}

#[test]
fn dns_response_extracts_txt_and_cname() {
    let resp = wire::dns_response(
        0x10,
        "stage.tunnel.example.com",
        dns::rtype::TXT,
        0x8180,
        &[
            DnsAnswer::cname("stage.tunnel.example.com", "edge.tunnel.example.com"),
            DnsAnswer::txt("edge.tunnel.example.com", "secret"),
        ],
    );
    let msg = dns::parse(&resp).unwrap();
    assert!(msg.is_response());
    assert_eq!(msg.answers.len(), 2);
    assert_eq!(msg.answers[0].rtype, dns::rtype::CNAME);
    assert_eq!(msg.answers[1].rtype, dns::rtype::TXT);
    let txt = dns::txt_string(&msg.answers[1].rdata).unwrap();
    assert_eq!(txt, "secret");
}

#[test]
fn truncated_ipv4_header_returns_none() {
    let frame = wire::ethernet_frame([0; 6], [0; 6], 0x0800, &[0x45, 0x00, 0x00]);
    assert!(packet::decode_record(&frame, 0).unwrap().is_none());
}

#[test]
fn non_ipv4_ethertype_is_filtered() {
    let frame = wire::ethernet_frame([0; 6], [0; 6], 0x0806, &[0u8; 30]);
    assert!(packet::decode_record(&frame, 0).unwrap().is_none());
}

// Pull `DnsAnswer` into scope for the test helpers above.
use packet_forensics_lab::wire::DnsAnswer;
// Touch tcp constants so the module is exercised.
#[test]
fn tcp_flag_constants_have_expected_bits() {
    assert_eq!(tcp::FLAG_SYN, 0x0002);
    assert_eq!(tcp::FLAG_ACK, 0x0010);
}
