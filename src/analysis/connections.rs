//! Connection anomaly analysis: port scans and broad reachability.

use super::{Category, Finding, Severity};
use crate::packet::{is_syn, Frame, Proto};
use std::collections::HashMap;
use std::net::Ipv4Addr;

const PORT_SCAN_PORTS: usize = 8;

struct HostScan {
    distinct_ports: std::collections::HashSet<u16>,
}

pub fn analyze(frames: &[Frame]) -> Vec<Finding> {
    let mut by_pair: HashMap<(Ipv4Addr, Ipv4Addr), HostScan> = HashMap::new();
    let mut destinations: HashMap<Ipv4Addr, std::collections::HashSet<Ipv4Addr>> = HashMap::new();

    for f in frames {
        if f.flow.proto != Proto::Tcp {
            continue;
        }
        destinations
            .entry(f.flow.src)
            .or_default()
            .insert(f.flow.dst);
        if is_syn(f.tcp_flags) {
            by_pair
                .entry((f.flow.src, f.flow.dst))
                .or_insert_with(|| HostScan {
                    distinct_ports: Default::default(),
                })
                .distinct_ports
                .insert(f.flow.dst_port);
        }
    }

    let mut out = Vec::new();
    for ((src, dst), scan) in by_pair {
        if scan.distinct_ports.len() >= PORT_SCAN_PORTS {
            let mut ports: Vec<u16> = scan.distinct_ports.iter().copied().collect();
            ports.sort_unstable();
            let sample: Vec<String> = ports.iter().take(8).map(|p| p.to_string()).collect();
            out.push(Finding::new(
                Category::Connection,
                Severity::High,
                "TCP SYN port scan",
                format!(
                    "{src} sent SYN segments to {n} ports on {dst}. First ports observed: {p}. This pattern matches a port sweep.",
                    n = scan.distinct_ports.len(),
                    p = sample.join(", "),
                ),
            ));
        }
    }
    out.extend(broad_reachability(destinations));
    out
}

fn broad_reachability(
    destinations: HashMap<Ipv4Addr, std::collections::HashSet<Ipv4Addr>>,
) -> Vec<Finding> {
    let mut out = Vec::new();
    if let Some((src, hosts)) = destinations.into_iter().max_by_key(|(_, h)| h.len()) {
        if hosts.len() >= 10 {
            out.push(Finding::new(
                Category::Connection,
                Severity::Low,
                "Broad host reachability",
                format!(
                    "{src} contacted {n} distinct hosts. Confirm that the contact list matches a service policy.",
                    n = hosts.len(),
                ),
            ));
        }
    }
    out
}
