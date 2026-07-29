//! Renderer behavior for the plain-text and JSON scan output.
//!
//! The JSON assertions run against a tiny recursive-descent parser kept
//! local to this file so the crate keeps its established test dependency
//! surface small.

use packet_forensics_lab::analysis::{Category, Finding, Report, Severity, Summary};
use packet_forensics_lab::loader;
use packet_forensics_lab::render;

fn load(name: &str) -> Report {
    let bytes = std::fs::read(format!("fixtures/{name}.pcap")).expect("read fixture");
    loader::report_for(name, &bytes).expect("analyze")
}

fn synthetic_report() -> Report {
    Report {
        source: "synthetic".to_string(),
        findings: vec![
            Finding {
                category: Category::Dns,
                severity: Severity::High,
                title: "DNS tunneling indicator".to_string(),
                detail: "twelve queries carry noisy labels.".to_string(),
            },
            Finding {
                category: Category::Dns,
                severity: Severity::Low,
                title: "Query concentration".to_string(),
                detail: "twelve queries targeted example.com.".to_string(),
            },
        ],
        summary: Summary {
            frames: 19,
            flows: 2,
            dns_queries: 12,
            dns_responses: 7,
            tcp_syns: 0,
            span_micros: 900_000,
        },
    }
}

#[test]
fn text_report_keeps_header_and_severity_order() {
    let report = synthetic_report();
    let text = render::text(&report);
    assert!(text.contains("Worst severity:  HIGH"));
    assert!(text.contains("Frames decoded:  19"));
    let high = text.find("[HIGH]").expect("high finding");
    let low = text.find("[LOW]").expect("low finding");
    assert!(high < low);
}

#[test]
fn json_report_is_valid_json_and_has_schema() {
    let report = synthetic_report();
    let payload = render::json(&report);
    let value = Json::parse(&payload).expect("valid JSON");
    assert!(value.is_object());
    assert_eq!(
        value.field_str("schema"),
        Some("packet-forensics-lab/report/v1")
    );
    assert_eq!(value.field_str("source"), Some("synthetic"));
    let summary = value.field("summary").expect("summary");
    assert_eq!(summary.field_uint("frames"), Some(19));
    assert_eq!(summary.field_uint("flows"), Some(2));
    assert_eq!(summary.field_uint("dns_queries"), Some(12));
    assert_eq!(summary.field_uint("dns_responses"), Some(7));
    assert_eq!(summary.field_uint("tcp_syns"), Some(0));
    assert_eq!(
        summary.field_num("capture_window_seconds"),
        Some("0.90".to_string())
    );
    assert_eq!(summary.field_str("worst_severity"), Some("HIGH"));
    assert_eq!(summary.field_uint("findings"), Some(2));
}

#[test]
fn json_report_preserves_finding_order_and_fields() {
    let report = synthetic_report();
    let payload = render::json(&report);
    let value = Json::parse(&payload).expect("valid JSON");
    let findings = value.array_field("findings").expect("findings array");
    assert_eq!(findings.len(), 2);
    let first = &findings[0];
    assert_eq!(first.field_str("severity"), Some("HIGH"));
    assert_eq!(first.field_str("category"), Some("DNS"));
    assert_eq!(first.field_str("title"), Some("DNS tunneling indicator"));
    let second = &findings[1];
    assert_eq!(second.field_str("severity"), Some("LOW"));
}

#[test]
fn json_report_is_deterministic_across_calls() {
    let report = synthetic_report();
    let a = render::json(&report);
    let b = render::json(&report);
    assert_eq!(a, b);
}

#[test]
fn json_report_escapes_strings_safely() {
    let mut report = synthetic_report();
    report.findings.push(Finding {
        category: Category::Connection,
        severity: Severity::Medium,
        title: "Escaped \"quotes\" and line\nbreak".to_string(),
        detail: "control characters must not break the document.".to_string(),
    });
    let payload = render::json(&report);
    let value = Json::parse(&payload).expect("valid JSON even with escapes");
    let findings = value.array_field("findings").expect("findings");
    let titles: Vec<String> = findings
        .iter()
        .filter_map(|f| f.field_str("title").map(str::to_string))
        .collect();
    assert!(titles
        .iter()
        .any(|t| t.contains("quotes") && t.contains('\n')));
}

#[test]
fn json_report_for_dns_tunnel_fixture_roundtrips_through_validator() {
    let report = load("dns_tunnel");
    let payload = render::json(&report);
    let value = Json::parse(&payload).expect("fixture JSON must be valid");
    let frames = value
        .field("summary")
        .and_then(|s| s.field_uint("frames"))
        .expect("frames count");
    assert_eq!(frames, report.summary.frames as u64);
    assert!(!report.findings.is_empty());
}

#[test]
fn text_and_json_share_the_same_severity_counts() {
    let report = load("beacon");
    let text = render::text(&report);
    let json = render::json(&report);
    let value = Json::parse(&json).expect("valid JSON");
    let summary_findings = value
        .field("summary")
        .and_then(|s| s.field_uint("findings"))
        .expect("findings count");
    assert_eq!(summary_findings, report.findings.len() as u64);
    let printed_count = text
        .lines()
        .filter(|l| l.starts_with(|c: char| c.is_ascii_digit()))
        .count();
    assert_eq!(printed_count, report.findings.len());
}

// ----------------------------------------------------------------------
// Minimal JSON value tree used by the assertions above.
//
// The parser supports the subset emitted by `render::json`: objects,
// arrays, strings with the same escape set, and numbers. The literal
// tokens `true`, `false`, and `null` are accepted for safety even when
// the renderer never emits them. Parsing fails on trailing data so the
// test catches an accidental extra token.

#[derive(Debug, Clone, PartialEq)]
enum Json {
    Null,
    Bool(bool),
    Num(String),
    Str(String),
    Array(Vec<Json>),
    Object(Vec<(String, Json)>),
}

impl Json {
    fn is_object(&self) -> bool {
        matches!(self, Json::Object(_))
    }
    fn field(&self, key: &str) -> Option<&Json> {
        if let Json::Object(pairs) = self {
            pairs.iter().find(|(k, _)| k == key).map(|(_, v)| v)
        } else {
            None
        }
    }
    fn array_field(&self, key: &str) -> Option<&Vec<Json>> {
        if let Json::Array(items) = self.field(key)? {
            Some(items)
        } else {
            None
        }
    }
    fn field_str(&self, key: &str) -> Option<&str> {
        self.field(key).and_then(Json::as_str)
    }
    fn field_uint(&self, key: &str) -> Option<u64> {
        self.field(key).and_then(Json::as_uint)
    }
    fn field_num(&self, key: &str) -> Option<String> {
        self.field(key).and_then(|v| match v {
            Json::Num(n) => Some(n.clone()),
            _ => None,
        })
    }
    fn as_str(&self) -> Option<&str> {
        if let Json::Str(s) = self {
            Some(s)
        } else {
            None
        }
    }
    fn as_uint(&self) -> Option<u64> {
        if let Json::Num(n) = self {
            n.parse().ok()
        } else {
            None
        }
    }

    fn parse(input: &str) -> Option<Json> {
        let mut p = Parser {
            bytes: input.as_bytes(),
            pos: 0,
        };
        p.ws();
        let value = p.value()?;
        p.ws();
        if p.pos != p.bytes.len() {
            return None;
        }
        Some(value)
    }
}

struct Parser<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Parser<'a> {
    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }
    fn bump(&mut self) -> Option<u8> {
        let b = self.peek()?;
        self.pos += 1;
        Some(b)
    }
    fn ws(&mut self) {
        while let Some(b) = self.peek() {
            if matches!(b, b' ' | b'\t' | b'\n' | b'\r') {
                self.pos += 1;
            } else {
                break;
            }
        }
    }
    fn expect(&mut self, c: u8) -> Option<()> {
        if self.peek()? == c {
            self.pos += 1;
            Some(())
        } else {
            None
        }
    }
    fn value(&mut self) -> Option<Json> {
        self.ws();
        match self.peek()? {
            b'{' => self.object(),
            b'[' => self.array(),
            b'"' => self.string().map(Json::Str),
            b't' | b'f' => self.bool(),
            b'n' => self.null(),
            b'-' | b'0'..=b'9' => self.number(),
            _ => None,
        }
    }
    fn object(&mut self) -> Option<Json> {
        self.expect(b'{')?;
        let mut pairs = Vec::new();
        self.ws();
        if self.peek() == Some(b'}') {
            self.pos += 1;
            return Some(Json::Object(pairs));
        }
        loop {
            self.ws();
            let key = self.string()?;
            self.ws();
            self.expect(b':')?;
            self.ws();
            let val = self.value()?;
            pairs.push((key, val));
            self.ws();
            match self.peek()? {
                b',' => {
                    self.pos += 1;
                }
                b'}' => {
                    self.pos += 1;
                    break;
                }
                _ => return None,
            }
        }
        Some(Json::Object(pairs))
    }
    fn array(&mut self) -> Option<Json> {
        self.expect(b'[')?;
        let mut items = Vec::new();
        self.ws();
        if self.peek() == Some(b']') {
            self.pos += 1;
            return Some(Json::Array(items));
        }
        loop {
            self.ws();
            items.push(self.value()?);
            self.ws();
            match self.peek()? {
                b',' => {
                    self.pos += 1;
                }
                b']' => {
                    self.pos += 1;
                    break;
                }
                _ => return None,
            }
        }
        Some(Json::Array(items))
    }
    fn string(&mut self) -> Option<String> {
        self.expect(b'"')?;
        let mut out = String::new();
        while let Some(b) = self.bump() {
            match b {
                b'"' => return Some(out),
                b'\\' => {
                    let esc = self.bump()?;
                    match esc {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'/' => out.push('/'),
                        b'n' => out.push('\n'),
                        b'r' => out.push('\r'),
                        b't' => out.push('\t'),
                        b'b' => out.push('\u{0008}'),
                        b'f' => out.push('\u{000C}'),
                        b'u' => {
                            let mut code = 0u32;
                            for _ in 0..4 {
                                let h = self.bump()?;
                                let d = match h {
                                    b'0'..=b'9' => (h - b'0') as u32,
                                    b'a'..=b'f' => (h - b'a' + 10) as u32,
                                    b'A'..=b'F' => (h - b'A' + 10) as u32,
                                    _ => return None,
                                };
                                code = code * 16 + d;
                            }
                            out.push(char::from_u32(code)?);
                        }
                        _ => return None,
                    }
                }
                0x20..=0x21 | 0x23..=0x7E => out.push(b as char),
                0x80..=0xFF => out.push(b as char),
                _ => return None,
            }
        }
        None
    }
    fn number(&mut self) -> Option<Json> {
        let start = self.pos;
        if self.peek() == Some(b'-') {
            self.pos += 1;
        }
        while let Some(b) = self.peek() {
            if matches!(b, b'0'..=b'9' | b'.' | b'e' | b'E' | b'+' | b'-') {
                self.pos += 1;
            } else {
                break;
            }
        }
        let text = std::str::from_utf8(self.bytes.get(start..self.pos)?).ok()?;
        Some(Json::Num(text.to_string()))
    }
    fn bool(&mut self) -> Option<Json> {
        if self.bytes.get(self.pos..self.pos + 4) == Some(b"true") {
            self.pos += 4;
            return Some(Json::Bool(true));
        }
        if self.bytes.get(self.pos..self.pos + 5) == Some(b"false") {
            self.pos += 5;
            return Some(Json::Bool(false));
        }
        None
    }
    fn null(&mut self) -> Option<Json> {
        if self.bytes.get(self.pos..self.pos + 4) == Some(b"null") {
            self.pos += 4;
            return Some(Json::Null);
        }
        None
    }
}
