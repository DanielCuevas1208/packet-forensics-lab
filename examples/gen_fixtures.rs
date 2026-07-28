//! Generate the bundled pcap fixtures.
//!
//! Run with `cargo run --example gen_fixtures`. The script writes deterministic
//! captures into the `fixtures/` directory. The output is committed so that the
//! lab binary ships with the sample data and the tests stay reproducible.

use packet_forensics_lab::pcap::{write, WriteRecord};
use packet_forensics_lab::wire::{self, DnsAnswer};
use std::net::Ipv4Addr;
use std::path::PathBuf;

const CLIENT: Ipv4Addr = Ipv4Addr::new(10, 10, 0, 21);
const RESOLVER: Ipv4Addr = Ipv4Addr::new(10, 10, 0, 1);
const SERVER: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 50);
const MAC_CLIENT: [u8; 6] = [0x00, 0x0B, 0xBE, 0xEF, 0x00, 0x21];
const MAC_RESOLVER: [u8; 6] = [0x00, 0x0B, 0xBE, 0xEF, 0x00, 0x01];
const MAC_SERVER: [u8; 6] = [0x00, 0x0B, 0xBE, 0xEF, 0x00, 0x50];

fn synth(secs: u32, usec: u32, frame: Vec<u8>) -> WriteRecord {
    WriteRecord {
        ts_secs: secs,
        ts_usec: usec,
        data: frame,
    }
}

fn main() -> std::io::Result<()> {
    let dir = PathBuf::from("fixtures");
    std::fs::create_dir_all(&dir)?;

    write_pcap(&dir.join("baseline.pcap"), baseline());
    write_pcap(&dir.join("dns_tunnel.pcap"), dns_tunnel());
    write_pcap(&dir.join("port_scan.pcap"), port_scan());
    write_pcap(&dir.join("beacon.pcap"), beacon());

    println!("fixtures written to {}", dir.display());
    Ok(())
}

fn write_pcap(path: &std::path::Path, records: Vec<WriteRecord>) {
    let bytes = write(&records, 1);
    std::fs::write(path, bytes).expect("write fixture");
}

/// Eight unremarkable resolver queries with normal names and irregular timing.
fn baseline() -> Vec<WriteRecord> {
    let names = [
        "mail.example.com",
        "www.example.com",
        "cdn.example.com",
        "api.example.com",
        "login.example.org",
        "docs.example.org",
        "repo.example.net",
        "status.example.net",
    ];
    // Irregular offsets in microseconds so the timing analyzer does not flag
    // a clean resolver session as a beacon.
    let deltas = [
        0u32, 2_100_000, 740_000, 3_900_000, 1_200_000, 5_500_000, 600_000, 2_800_000,
    ];
    let base = 1_700_000_000u32;
    let mut out = Vec::new();
    let mut acc = 0u32;
    for (i, name) in names.iter().enumerate() {
        acc += deltas[i];
        let t = base + acc / 1_000_000;
        let usec = acc % 1_000_000;
        let q = wire::udp_packet(
            MAC_CLIENT,
            MAC_RESOLVER,
            CLIENT,
            RESOLVER,
            49_152 + i as u16,
            53,
            &wire::dns_query(0x100 + i as u16, name, 1),
        );
        let r = wire::udp_packet(
            MAC_RESOLVER,
            MAC_CLIENT,
            RESOLVER,
            CLIENT,
            53,
            49_152 + i as u16,
            &wire::dns_response(
                0x100 + i as u16,
                name,
                1,
                0x8180,
                &[DnsAnswer::a(name, Ipv4Addr::new(203, 0, 113, 10 + i as u8))],
            ),
        );
        out.push(synth(t, usec, q));
        out.push(synth(t, usec + 47_000, r));
    }
    out
}

/// Many noisy high-entropy queries under one suffix, plus NXDOMAIN floods.
fn dns_tunnel() -> Vec<WriteRecord> {
    let mut out = Vec::new();
    let mut id = 0x200u16;
    let alphabet = b"abcdefghijklmnopqrstuvwxyz0123456789";
    for i in 0..12 {
        let mut label = String::new();
        let mut s = (i * 7 + 1) as u64;
        for _ in 0..30 {
            s = s.wrapping_mul(1103515245).wrapping_add(12345);
            label.push(alphabet[(s >> 16) as usize % alphabet.len()] as char);
        }
        let name = format!("{label}.tunnel.example.com");
        let payload = wire::dns_query(id, &name, 16);
        out.push(synth(1_700_001_000, i as u32 * 100, udp_dns(&payload)));
        // NXDOMAIN responses for half of them.
        if i % 2 == 0 {
            let resp = wire::dns_response(id, &name, 16, 0x8183, &[]);
            out.push(synth(
                1_700_001_000,
                i as u32 * 100 + 50_000,
                udp_dns_reverse(&resp),
            ));
        }
        id = id.wrapping_add(1);
    }
    // One oversized TXT answer.
    let txt = "D".repeat(80);
    let resp = wire::dns_response(
        id,
        "stage.tunnel.example.com",
        16,
        0x8180,
        &[DnsAnswer::txt("stage.tunnel.example.com", &txt)],
    );
    out.push(synth(1_700_001_000, 900_000, udp_dns_reverse(&resp)));
    out
}

/// A SYN sweep across 12 ports on one host.
fn port_scan() -> Vec<WriteRecord> {
    let mut out = Vec::new();
    for (i, port) in [22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 8080, 9090]
        .iter()
        .enumerate()
    {
        let syn = wire::tcp_segment_packet(
            MAC_CLIENT,
            MAC_SERVER,
            CLIENT,
            SERVER,
            50_000 + i as u16,
            *port,
            0x0002,
            &[],
        );
        out.push(synth(1_700_002_000, i as u32 * 5_000, syn));
    }
    out
}

/// Regular beacon every 5 s to one host on port 443.
fn beacon() -> Vec<WriteRecord> {
    let mut out = Vec::new();
    for i in 0..8u32 {
        let frame = wire::tcp_segment_packet(
            MAC_CLIENT,
            MAC_SERVER,
            CLIENT,
            SERVER,
            (51_000 + i) as u16,
            443,
            0x0018, // PSH + ACK
            b"ping",
        );
        out.push(synth(1_700_003_000 + i * 5, (i % 3) * 1_000, frame));
    }
    out
}

fn udp_dns(payload: &[u8]) -> Vec<u8> {
    wire::udp_packet(
        MAC_CLIENT,
        MAC_RESOLVER,
        CLIENT,
        RESOLVER,
        53_000,
        53,
        payload,
    )
}

fn udp_dns_reverse(payload: &[u8]) -> Vec<u8> {
    wire::udp_packet(
        MAC_RESOLVER,
        MAC_CLIENT,
        RESOLVER,
        CLIENT,
        53,
        53_000,
        payload,
    )
}
