//! Plain-text and JSON report rendering for the CLI scan output.

use crate::analysis::Report;

/// Schema identifier embedded at the top of every JSON report.
/// Bump the version segment when the JSON shape changes.
pub const JSON_SCHEMA: &str = "packet-forensics-lab/report/v1";

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

/// Render a report as deterministic JSON.
///
/// The output uses stable field ordering and never pretty-prints so that
/// the same report always produces the same bytes. Down-stream tools can
/// feed the document straight into a JSON parser.
pub fn json(report: &Report) -> String {
    let s = &report.summary;
    let mut doc = Json::object();
    doc.set_str("schema", JSON_SCHEMA);
    doc.set_str("source", &report.source);
    {
        let mut summary = Json::object();
        summary.set_uint("frames", s.frames);
        summary.set_uint("flows", s.flows);
        summary.set_uint("dns_queries", s.dns_queries);
        summary.set_uint("dns_responses", s.dns_responses);
        summary.set_uint("tcp_syns", s.tcp_syns);
        summary.set_float("capture_window_seconds", s.span_micros, 1_000_000);
        summary.set_uint("findings", report.findings.len());
        summary.set_str("worst_severity", report.max_severity().label());
        doc.set_object("summary", summary);
    }
    {
        let mut findings = Vec::with_capacity(report.findings.len());
        for f in &report.findings {
            let mut item = Json::object();
            item.set_str("severity", f.severity.label());
            item.set_str("category", f.category.label());
            item.set_str("title", &f.title);
            item.set_str("detail", &f.detail);
            findings.push(item);
        }
        doc.set_array("findings", findings);
    }
    doc.finish()
}

// ----------------------------------------------------------------------
// Minimal deterministic JSON encoder.
//
// The crate keeps its runtime dependency surface small. A hand-rolled
// encoder is enough for the report shape and gives full control over
// ordering and number formatting. The test suite parses every emitted
// document with `serde_json` to prove the output is well-formed.

#[derive(Debug, Clone)]
enum Json {
    Object(Vec<(&'static str, Json)>),
    Array(Vec<Json>),
    Str(String),
    Num(String),
}

impl Json {
    fn object() -> Self {
        Json::Object(Vec::new())
    }

    fn set_str(&mut self, key: &'static str, value: &str) {
        if let Json::Object(v) = self {
            v.push((key, Json::Str(escape_json(value))));
        }
    }

    fn set_uint(&mut self, key: &'static str, value: usize) {
        if let Json::Object(v) = self {
            v.push((key, Json::Num(value.to_string())));
        }
    }

    fn set_float(&mut self, key: &'static str, numerator: u64, denominator: u64) {
        if let Json::Object(v) = self {
            let text = format_fixed(numerator, denominator);
            v.push((key, Json::Num(text)));
        }
    }

    fn set_object(&mut self, key: &'static str, value: Json) {
        if let Json::Object(v) = self {
            v.push((key, value));
        }
    }

    fn set_array(&mut self, key: &'static str, values: Vec<Json>) {
        if let Json::Object(v) = self {
            v.push((key, Json::Array(values)));
        }
    }

    fn finish(self) -> String {
        let mut out = String::new();
        write_json(&self, &mut out);
        out
    }
}

fn write_json(node: &Json, out: &mut String) {
    match node {
        Json::Num(n) => out.push_str(n),
        Json::Str(s) => {
            out.push('"');
            out.push_str(s);
            out.push('"');
        }
        Json::Array(items) => {
            out.push('[');
            for (i, it) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_json(it, out);
            }
            out.push(']');
        }
        Json::Object(pairs) => {
            out.push('{');
            for (i, (k, v)) in pairs.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push('"');
                out.push_str(k);
                out.push_str("\":");
                write_json(v, out);
            }
            out.push('}');
        }
    }
}

/// Escape a string for inclusion inside a JSON string literal.
fn escape_json(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{0008}' => out.push_str("\\b"),
            '\u{000C}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

/// Format an unsigned rational as a trimmed decimal with two decimals.
fn format_fixed(numerator: u64, denominator: u64) -> String {
    if denominator == 0 {
        return "0".to_string();
    }
    let whole = numerator / denominator;
    let frac = numerator % denominator;
    let hundredths = (frac * 100 + denominator / 2) / denominator;
    if hundredths == 100 {
        let carried = whole + 1;
        return format!("{carried}.00");
    }
    format!("{whole}.{hundredths:02}")
}

#[cfg(test)]
mod internal_tests {
    use super::*;
    use crate::analysis::{Category, Finding, Severity, Summary};

    fn sample_report() -> Report {
        Report {
            source: "demo".to_string(),
            findings: vec![Finding {
                category: Category::Dns,
                severity: Severity::High,
                title: "DNS tunneling indicator".to_string(),
                detail: "ten queries carry noisy labels.".to_string(),
            }],
            summary: Summary {
                frames: 12,
                flows: 12,
                dns_queries: 12,
                dns_responses: 7,
                tcp_syns: 0,
                span_micros: 60_000,
            },
        }
    }

    #[test]
    fn format_fixed_handles_exact_and_carry() {
        assert_eq!(format_fixed(60_000, 1_000_000), "0.06");
        assert_eq!(format_fixed(1_500_000, 1_000_000), "1.50");
        assert_eq!(format_fixed(9_999_990, 10_000_000), "1.00");
        assert_eq!(format_fixed(0, 0), "0");
    }

    #[test]
    fn escape_json_replaces_control_and_quotes() {
        assert_eq!(escape_json("plain"), "plain");
        assert_eq!(escape_json("\"quote\""), "\\\"quote\\\"");
        assert_eq!(escape_json("line\nbreak"), "line\\nbreak");
        assert_eq!(escape_json("\u{0001}"), "\\u0001");
    }

    #[test]
    fn json_report_is_deterministic_across_calls() {
        let report = sample_report();
        let a = json(&report);
        let b = json(&report);
        assert_eq!(a, b);
        assert!(a.contains("\"schema\":\"packet-forensics-lab/report/v1\""));
        assert!(a.contains("\"capture_window_seconds\":0.06"));
        assert!(a.contains("\"worst_severity\":\"HIGH\""));
    }
}
