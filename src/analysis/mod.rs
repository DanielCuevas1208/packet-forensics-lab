//! Coordinates the analyzers and owns the findings model.

pub mod connections;
pub mod dns;
pub mod entropy;
pub mod timing;

use crate::packet::{is_syn, Flow, Frame, Proto};

/// Severity of a finding. Ordered low to high.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
}

impl Severity {
    pub fn label(self) -> &'static str {
        match self {
            Self::Info => "INFO",
            Self::Low => "LOW",
            Self::Medium => "MEDIUM",
            Self::High => "HIGH",
        }
    }
}

/// The family of analysis that produced the finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Category {
    Dns,
    Connection,
    Timing,
}

impl Category {
    pub fn label(self) -> &'static str {
        match self {
            Self::Dns => "DNS",
            Self::Connection => "Connection",
            Self::Timing => "Timing",
        }
    }
}

/// One explained anomaly discovered in the capture.
#[derive(Debug, Clone)]
pub struct Finding {
    pub category: Category,
    pub severity: Severity,
    pub title: String,
    pub detail: String,
}

impl Finding {
    fn new(
        category: Category,
        severity: Severity,
        title: impl Into<String>,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            category,
            severity,
            title: title.into(),
            detail: detail.into(),
        }
    }
}

/// Summary statistics for the inspected capture.
#[derive(Debug, Clone, Default)]
pub struct Summary {
    pub frames: usize,
    pub dns_queries: usize,
    pub dns_responses: usize,
    pub tcp_syns: usize,
    pub flows: usize,
    pub span_micros: u64,
}

/// Evidence aggregated for one direction-specific five-tuple.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlowStats {
    pub flow: Flow,
    pub packets: usize,
    pub bytes: usize,
    pub first_ts_micros: u64,
    pub last_ts_micros: u64,
    pub tcp_syns: usize,
}

impl FlowStats {
    /// Return the observed time between the first and last packet.
    pub fn duration_micros(&self) -> u64 {
        self.last_ts_micros.saturating_sub(self.first_ts_micros)
    }
}

/// The full analyis result consumed by the terminal interface.
#[derive(Debug, Clone, Default)]
pub struct Report {
    pub source: String,
    pub findings: Vec<Finding>,
    pub summary: Summary,
}

impl Report {
    pub fn max_severity(&self) -> Severity {
        self.findings
            .iter()
            .map(|f| f.severity)
            .max()
            .unwrap_or(Severity::Info)
    }
}

/// Run every analyzer across the decoded frames.
pub fn analyze(source: impl Into<String>, frames: &[Frame], span_micros: u64) -> Report {
    let mut report = Report {
        source: source.into(),
        findings: Vec::new(),
        summary: Summary {
            frames: frames.len(),
            flows: count_flows(frames),
            span_micros,
            ..Default::default()
        },
    };
    report.summary.dns_queries = frames.iter().filter(|f| dns::is_query(f)).count();
    report.summary.dns_responses = frames.iter().filter(|f| dns::is_response(f)).count();
    report.summary.tcp_syns = frames
        .iter()
        .filter(|f| f.flow.proto == crate::packet::Proto::Tcp && crate::packet::is_syn(f.tcp_flags))
        .count();

    report.findings.extend(dns::analyze(frames));
    report.findings.extend(connections::analyze(frames));
    report.findings.extend(timing::analyze(frames, span_micros));
    report
        .findings
        .sort_by_key(|f| std::cmp::Reverse(f.severity));
    report
}

fn count_flows(frames: &[Frame]) -> usize {
    let mut set = std::collections::HashSet::new();
    for f in frames {
        set.insert((
            f.flow.src,
            f.flow.dst,
            f.flow.src_port,
            f.flow.dst_port,
            f.flow.proto,
        ));
    }
    set.len()
}

/// Aggregate decoded packets by direction-specific flow.
///
/// The returned order follows the first packet seen for each flow. This keeps
/// the terminal view stable without relying on hash-map iteration order.
pub fn flow_stats(frames: &[Frame]) -> Vec<FlowStats> {
    let mut indexes = std::collections::HashMap::new();
    let mut stats = Vec::new();

    for frame in frames {
        let index = if let Some(index) = indexes.get(&frame.flow) {
            *index
        } else {
            let index = stats.len();
            indexes.insert(frame.flow.clone(), index);
            stats.push(FlowStats {
                flow: frame.flow.clone(),
                packets: 0,
                bytes: 0,
                first_ts_micros: frame.ts_micros,
                last_ts_micros: frame.ts_micros,
                tcp_syns: 0,
            });
            index
        };

        let current = &mut stats[index];
        current.packets += 1;
        current.bytes = current.bytes.saturating_add(frame.wire_len);
        current.first_ts_micros = current.first_ts_micros.min(frame.ts_micros);
        current.last_ts_micros = current.last_ts_micros.max(frame.ts_micros);
        if frame.flow.proto == Proto::Tcp && is_syn(frame.tcp_flags) {
            current.tcp_syns += 1;
        }
    }

    stats
}
