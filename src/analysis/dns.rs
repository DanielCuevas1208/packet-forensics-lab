//! DNS anomaly analysis: tunneling, NXDOMAIN floods, TXT exfiltration.

use super::{Category, Finding, Severity};
use crate::analysis::entropy;
use crate::packet::{dns as dns_proto, Frame};
use std::collections::HashMap;
use std::net::Ipv4Addr;

const PORT_DNS: u16 = 53;
const TUNNEL_QUERY_LEN: usize = 48;
const TUNNEL_LABEL_LEN: usize = 12;
const TUNNEL_ENTROPY: f64 = 3.5;
const NXDOMAIN_FLOOD: usize = 3;
const TXT_EXFIL_BYTES: usize = 64;
const QUERY_CONCENTRATION: usize = 12;

/// True when the frame carries a DNS query (request).
pub fn is_query(frame: &Frame) -> bool {
    if frame.flow.dst_port != PORT_DNS && frame.flow.src_port != PORT_DNS {
        return false;
    }
    dns_proto::parse(&frame.payload)
        .map(|m| !m.is_response())
        .unwrap_or(false)
}

/// True when the frame carries a DNS response.
pub fn is_response(frame: &Frame) -> bool {
    if frame.flow.dst_port != PORT_DNS && frame.flow.src_port != PORT_DNS {
        return false;
    }
    dns_proto::parse(&frame.payload)
        .map(|m| m.is_response())
        .unwrap_or(false)
}

struct Query {
    src: Ipv4Addr,
    name: String,
    wire_len: usize,
    max_label_len: usize,
    noisy: bool,
}

struct QueryData {
    queries: Vec<Query>,
    responses: Vec<(u8, usize, usize, bool, usize)>,
}

fn collect(frames: &[Frame]) -> QueryData {
    let mut queries = Vec::new();
    let mut responses = Vec::new();
    for f in frames {
        if f.flow.dst_port != PORT_DNS && f.flow.src_port != PORT_DNS {
            continue;
        }
        let Some(msg) = dns_proto::parse(&f.payload) else {
            continue;
        };
        if msg.is_response() {
            let rcode = msg.rcode();
            let has_txt = msg.answers.iter().any(|r| r.rtype == dns_proto::rtype::TXT);
            let txt_len = msg
                .answers
                .iter()
                .filter(|r| r.rtype == dns_proto::rtype::TXT)
                .map(|r| r.rdata.len())
                .max()
                .unwrap_or(0);
            let qname_len = msg.qname().map(|n| n.len()).unwrap_or(0);
            responses.push((rcode, qname_len, f.wire_len, has_txt, txt_len));
        } else {
            let qname = msg.qname().unwrap_or("").to_string();
            let labels = entropy::labels(&qname);
            let max_label_len = labels.iter().map(|s| s.len()).max().unwrap_or(0);
            let noisy = labels.iter().any(|l| {
                l.len() >= TUNNEL_LABEL_LEN
                    && entropy::shannon_entropy(l.as_bytes()) >= TUNNEL_ENTROPY
            });
            queries.push(Query {
                src: f.flow.src,
                name: qname,
                wire_len: f.wire_len,
                max_label_len,
                noisy,
            });
        }
    }
    QueryData { queries, responses }
}

pub fn analyze(frames: &[Frame]) -> Vec<Finding> {
    let data = collect(frames);
    let mut out = Vec::new();
    out.extend(dns_tunneling(&data));
    out.extend(nxdomain_flood(&data));
    out.extend(txt_exfiltration(&data));
    out.extend(query_concentration(&data));
    out
}

fn dns_tunneling(data: &QueryData) -> Vec<Finding> {
    let mut by_domain: HashMap<String, (usize, Ipv4Addr, usize)> = HashMap::new();
    for q in &data.queries {
        if !q.noisy && q.wire_len < TUNNEL_QUERY_LEN {
            continue;
        }
        let suffix = entropy::registered_domain(&q.name);
        let entry = by_domain.entry(suffix).or_insert((0, q.src, 0));
        entry.0 += 1;
        entry.2 = entry.2.max(q.max_label_len);
    }
    let mut out = Vec::new();
    for (suffix, (count, src, max_label)) in by_domain {
        if count >= 5 {
            out.push(Finding::new(
                Category::Dns,
                Severity::High,
                "DNS tunneling indicator",
                format!(
                    "{count} queries to {suffix} from {src} carry noisy labels. The longest label is {max_label} bytes. Inspect the longest sublabels for encoded data.",
                ),
            ));
        }
    }
    out
}

fn nxdomain_flood(data: &QueryData) -> Vec<Finding> {
    let mut nxdomain_count = 0usize;
    let mut worst_qname_len = 0usize;
    for (rcode, qname_len, _, _, _) in &data.responses {
        if *rcode == dns_proto::rcode::NXDOMAIN {
            nxdomain_count += 1;
            worst_qname_len = worst_qname_len.max(*qname_len);
        }
    }
    if nxdomain_count >= NXDOMAIN_FLOOD {
        return vec![Finding::new(
            Category::Dns,
            Severity::Medium,
            "NXDOMAIN flood",
            format!(
                "{nxdomain_count} responses returned NXDOMAIN. Longest queried name measured {worst_qname_len} bytes. Compare against allowed resolver behavior for the host.",
            ),
        )];
    }
    Vec::new()
}

fn txt_exfiltration(data: &QueryData) -> Vec<Finding> {
    let mut worst = 0usize;
    let mut count = 0usize;
    for (rcode, _qname_len, _wire_len, has_txt, txt_len) in &data.responses {
        if *has_txt && *txt_len >= TXT_EXFIL_BYTES {
            count += 1;
            worst = worst.max(*txt_len);
            let _ = rcode;
        }
    }
    if count > 0 {
        return vec![Finding::new(
            Category::Dns,
            Severity::Medium,
            "Large TXT records",
            format!(
                "{count} TXT answer sets exceeded {TXT_EXFIL_BYTES} bytes. Largest TXT payload measured {worst} bytes. Treat oversized TXT answers as a covert-channel indicator.",
            ),
        )];
    }
    Vec::new()
}

fn query_concentration(data: &QueryData) -> Vec<Finding> {
    let mut by_suffix: HashMap<String, usize> = HashMap::new();
    for q in &data.queries {
        let suffix = entropy::registered_domain(&q.name);
        *by_suffix.entry(suffix).or_insert(0) += 1;
    }
    if let Some((suffix, count)) = by_suffix.into_iter().max_by_key(|(_, c)| *c) {
        if count >= QUERY_CONCENTRATION {
            return vec![Finding::new(
                Category::Dns,
                Severity::Low,
                "Query concentration",
                format!(
                    "{count} queries targeted {suffix}. Confirm that the volume matches an expected resolver pattern.",
                ),
            )];
        }
    }
    Vec::new()
}
