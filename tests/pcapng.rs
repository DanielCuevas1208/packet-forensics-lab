//! PCAPNG container behavior and loader integration.

use packet_forensics_lab::{loader, pcapng, wire};
use std::net::Ipv4Addr;

#[derive(Clone, Copy)]
enum Order {
    Little,
    Big,
}

fn put16(out: &mut Vec<u8>, value: u16, order: Order) {
    let bytes = match order {
        Order::Little => value.to_le_bytes(),
        Order::Big => value.to_be_bytes(),
    };
    out.extend_from_slice(&bytes);
}

fn put32(out: &mut Vec<u8>, value: u32, order: Order) {
    let bytes = match order {
        Order::Little => value.to_le_bytes(),
        Order::Big => value.to_be_bytes(),
    };
    out.extend_from_slice(&bytes);
}

fn put64(out: &mut Vec<u8>, value: u64, order: Order) {
    let bytes = match order {
        Order::Little => value.to_le_bytes(),
        Order::Big => value.to_be_bytes(),
    };
    out.extend_from_slice(&bytes);
}

fn block(block_type: u32, mut body: Vec<u8>, order: Order) -> Vec<u8> {
    while (body.len() + 12) % 4 != 0 {
        body.push(0);
    }
    let total_len = (body.len() + 12) as u32;
    let mut out = Vec::with_capacity(total_len as usize);
    put32(&mut out, block_type, order);
    put32(&mut out, total_len, order);
    out.extend_from_slice(&body);
    put32(&mut out, total_len, order);
    out
}

fn section(order: Order) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(match order {
        Order::Little => &[0x4D, 0x3C, 0x2B, 0x1A],
        Order::Big => &[0x1A, 0x2B, 0x3C, 0x4D],
    });
    put16(&mut body, 1, order);
    put16(&mut body, 0, order);
    put64(&mut body, u64::MAX, order);
    block(0x0A0D_0D0A, body, order)
}

fn interface(order: Order, link_type: u16, timestamp_resolution: Option<u8>) -> Vec<u8> {
    let mut body = Vec::new();
    put16(&mut body, link_type, order);
    put16(&mut body, 0, order);
    put32(&mut body, 65_535, order);
    if let Some(resolution) = timestamp_resolution {
        put16(&mut body, 9, order);
        put16(&mut body, 1, order);
        body.push(resolution);
        body.extend_from_slice(&[0, 0, 0]);
    }
    put16(&mut body, 0, order);
    put16(&mut body, 0, order);
    block(1, body, order)
}

fn enhanced_packet(order: Order, interface_id: u32, timestamp: u64, data: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    put32(&mut body, interface_id, order);
    put32(&mut body, (timestamp >> 32) as u32, order);
    put32(&mut body, timestamp as u32, order);
    put32(&mut body, data.len() as u32, order);
    put32(&mut body, data.len() as u32, order);
    body.extend_from_slice(data);
    block(6, body, order)
}

fn simple_packet(order: Order, data: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    put32(&mut body, data.len() as u32, order);
    body.extend_from_slice(data);
    block(3, body, order)
}

fn udp_frame() -> Vec<u8> {
    wire::udp_packet(
        [1; 6],
        [2; 6],
        Ipv4Addr::new(10, 0, 0, 5),
        Ipv4Addr::new(10, 0, 0, 1),
        50_000,
        53,
        &[],
    )
}

#[test]
fn enhanced_packets_flow_through_loader_and_keep_timestamps() {
    let order = Order::Little;
    let frame = udp_frame();
    let mut bytes = section(order);
    bytes.extend(interface(order, 1, None));
    bytes.extend(enhanced_packet(order, 0, 1_250_000, &frame));
    bytes.extend(enhanced_packet(order, 0, 1_500_000, &frame));

    let (frames, span) = loader::parse_capture(&bytes).unwrap();
    assert_eq!(frames.len(), 2);
    assert_eq!(frames[0].ts_micros, 1_250_000);
    assert_eq!(span, 250_000);
    assert!(pcapng::is_pcapng(&bytes));
}

#[test]
fn big_endian_binary_resolution_is_converted_to_microseconds() {
    let order = Order::Big;
    let frame = udp_frame();
    let mut bytes = section(order);
    bytes.extend(interface(order, 1, Some(0x8A)));
    bytes.extend(enhanced_packet(order, 0, 1024, &frame));

    let (frames, _) = loader::parse_capture(&bytes).unwrap();
    assert_eq!(frames.len(), 1);
    assert_eq!(frames[0].ts_micros, 1_000_000);
}

#[test]
fn simple_packet_uses_the_first_ethernet_interface() {
    let order = Order::Little;
    let frame = udp_frame();
    let mut bytes = section(order);
    bytes.extend(interface(order, 1, None));
    bytes.extend(simple_packet(order, &frame));

    let (frames, span) = loader::parse_capture(&bytes).unwrap();
    assert_eq!(frames.len(), 1);
    assert_eq!(frames[0].ts_micros, 0);
    assert_eq!(span, 0);
}

#[test]
fn malformed_block_trailer_is_rejected() {
    let order = Order::Little;
    let mut bytes = section(order);
    let last = bytes.len() - 1;
    bytes[last] ^= 1;
    assert!(pcapng::parse(&bytes).is_err());
}

#[test]
fn unsupported_interface_link_type_is_rejected() {
    let order = Order::Little;
    let mut bytes = section(order);
    bytes.extend(interface(order, 105, None));
    assert!(pcapng::parse(&bytes).is_err());
}

#[test]
fn unknown_enhanced_packet_interface_is_rejected() {
    let order = Order::Little;
    let frame = udp_frame();
    let mut bytes = section(order);
    bytes.extend(interface(order, 1, None));
    bytes.extend(enhanced_packet(order, 1, 0, &frame));
    assert!(pcapng::parse(&bytes).is_err());
}
