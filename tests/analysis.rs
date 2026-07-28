//! Analyzer behavior against bundled fixtures.

use packet_forensics_lab::analysis::{Category, Report, Severity};
use packet_forensics_lab::loader;

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
