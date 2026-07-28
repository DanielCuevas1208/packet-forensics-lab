//! Plain-text report rendering for the CLI scan output.

use crate::analysis::Report;

/// Render a report as deterministic, line-oriented text.
pub fn text(report: &Report) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "Packet Forensics Lab - report for {}\n",
        report.source
    ));
    out.push_str("=============================================\n");
    let s = &report.summary;
    out.push_str(&format!("Frames decoded:  {}\n", s.frames));
    out.push_str(&format!("IP flows:        {}\n", s.flows));
    out.push_str(&format!("DNS queries:     {}\n", s.dns_queries));
    out.push_str(&format!("DNS responses:   {}\n", s.dns_responses));
    out.push_str(&format!("TCP SYN packets: {}\n", s.tcp_syns));
    out.push_str(&format!(
        "Capture window:  {:.2} s\n",
        s.span_micros as f64 / 1_000_000.0
    ));
    out.push_str(&format!("Findings:        {}\n", report.findings.len()));
    let sev = report.max_severity();
    out.push_str(&format!("Worst severity:  {}\n\n", sev.label()));

    if report.findings.is_empty() {
        out.push_str("No anomalies were detected.\n");
        return out;
    }
    for (i, finding) in report.findings.iter().enumerate() {
        out.push_str(&format!(
            "{}. [{}] [{}] {}\n",
            i + 1,
            finding.severity.label(),
            finding.category.label(),
            finding.title
        ));
        out.push_str(&format!("   {}\n", finding.detail));
    }
    out
}
