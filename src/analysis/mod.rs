//! Coordinates the analyzers and owns the findings model.

pub mod connections;
pub mod dns;
pub mod entropy;
pub mod timing;

use crate::packet::Frame;

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
