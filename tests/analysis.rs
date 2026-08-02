//! Analyzer behavior against bundled fixtures.

use packet_forensics_lab::analysis::{self, Category, Report, Severity};
use packet_forensics_lab::loader;
use packet_forensics_lab::packet::{Flow, Frame, Proto};
use std::net::Ipv4Addr;

fn load(name: &str) -> Report {
    let bytes = std::fs::read(format!("fixtures/{name}.pcap")).expect("read fixture");
    loader::report_for(name, &bytes).expect("analyze")
}

fn has(report: &Report, cat: Category, title_contains: &str) -> bool {
    report
        .findings
        .iter()
        .any(|f| f.category == cat && f.title.contains(title_contains))
}

#[test]
fn baseline_is_clean() {
    let report = load("baseline");
    assert!(
        report.max_severity() <= Severity::Info,
        "baseline should not raise HIGH/MEDIUM/LOW, got {:?}",
        report.max_severity()
    );
}

#[test]
fn dns_tunnel_flags_all_dns_categories() {
    let report = load("dns_tunnel");
    assert!(report.max_severity() == Severity::High);
    assert!(has(&report, Category::Dns, "DNS tunneling"));
    assert!(has(&report, Category::Dns, "NXDOMAIN flood"));
    assert!(has(&report, Category::Dns, "Large TXT"));
    assert!(has(&report, Category::Dns, "Query concentration"));
}

#[test]
fn port_scan_flags_connection_finding() {
    let report = load("port_scan");
    assert!(has(&report, Category::Connection, "port scan"));
    let scan = report
        .findings
        .iter()
        .find(|f| f.category == Category::Connection)
        .unwrap();
    assert_eq!(scan.severity, Severity::High);
    assert!(scan.detail.contains("12 ports"));
}

#[test]
fn beacon_flags_timing_finding() {
    let report = load("beacon");
    assert!(has(&report, Category::Timing, "Beaconing"));
    let beacon = report
        .findings
        .iter()
        .find(|f| f.category == Category::Timing && f.title == "Beaconing pattern")
        .unwrap();
    assert_eq!(beacon.severity, Severity::High);
    assert!(beacon.detail.contains("192.0.2.50"));
}

#[test]
fn findings_are_sorted_by_severity_desc() {
    let report = load("dns_tunnel");
    let mut sorted = true;
    for w in report.findings.windows(2) {
        if w[0].severity < w[1].severity {
            sorted = false;
            break;
        }
    }
    assert!(sorted, "findings must be sorted high to low");
}

#[test]
fn summary_counts_match_decoded_frames() {
    let report = load("port_scan");
    assert_eq!(report.summary.frames, 12);
    assert_eq!(report.summary.tcp_syns, 12);
    assert_eq!(report.summary.dns_queries, 0);
}

#[test]
fn entropy_helpers_are_consistent() {
    use packet_forensics_lab::analysis::entropy;
    assert!(entropy::shannon_entropy(b"aaaaaaaa") < 0.1);
    assert!(entropy::shannon_entropy(b"abcdefghij") > 2.0);
    assert_eq!(entropy::registered_domain("a.b.example.com"), "example.com");
    assert_eq!(entropy::registered_domain("example.com"), "example.com");
}

#[test]
fn flow_stats_group_packets_and_keep_first_seen_order() {
    let client = Flow {
        src: Ipv4Addr::new(10, 0, 0, 5),
        dst: Ipv4Addr::new(192, 0, 2, 50),
        src_port: 40_000,
        dst_port: 443,
        proto: Proto::Tcp,
    };
    let reverse = Flow {
        src: client.dst,
        dst: client.src,
        src_port: client.dst_port,
        dst_port: client.src_port,
        proto: Proto::Tcp,
    };
    let frames = vec![
        Frame {
            flow: client.clone(),
            tcp_flags: packet_forensics_lab::packet::tcp::FLAG_SYN,
            payload: vec![0; 5],
            ts_micros: 20,
            wire_len: 75,
        },
        Frame {
            flow: reverse.clone(),
            tcp_flags: packet_forensics_lab::packet::tcp::FLAG_ACK,
            payload: Vec::new(),
            ts_micros: 25,
            wire_len: 54,
        },
        Frame {
            flow: client.clone(),
            tcp_flags: packet_forensics_lab::packet::tcp::FLAG_ACK,
            payload: Vec::new(),
            ts_micros: 30,
            wire_len: 60,
        },
        Frame {
            flow: client.clone(),
            tcp_flags: packet_forensics_lab::packet::tcp::FLAG_ACK,
            payload: Vec::new(),
            ts_micros: 10,
            wire_len: 64,
        },
    ];

    let stats = analysis::flow_stats(&frames);
    assert_eq!(stats.len(), 2);
    assert_eq!(stats[0].flow, client);
    assert_eq!(stats[0].packets, 3);
    assert_eq!(stats[0].bytes, 199);
    assert_eq!(stats[0].first_ts_micros, 10);
    assert_eq!(stats[0].last_ts_micros, 30);
    assert_eq!(stats[0].duration_micros(), 20);
    assert_eq!(stats[0].tcp_syns, 1);
    assert_eq!(stats[1].flow, reverse);
    assert_eq!(stats[1].packets, 1);
    assert_eq!(stats[1].bytes, 54);
    assert_eq!(stats[1].duration_micros(), 0);
}
