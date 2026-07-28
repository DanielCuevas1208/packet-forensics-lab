//! Capture loading. Bridges async file reads, the parser, and the analyzers.

use crate::analysis::{self, Report};
use crate::error::ForensicsError;
use crate::packet::{self, Frame};
use crate::pcap;

/// A decoded capture paired with its analysis report.
#[derive(Debug, Clone)]
pub struct Loaded {
    pub report: Report,
    pub frames: Vec<Frame>,
}

/// Parse pcap bytes into a decoded frame list plus span in microseconds.
pub fn parse_capture(bytes: &[u8]) -> Result<(Vec<Frame>, u64), ForensicsError> {
    let cap = pcap::parse(bytes)?;
    let span = cap.span_micros();
    let mut frames = Vec::with_capacity(cap.records.len());
    for rec in &cap.records {
        let ts = rec.micros(cap.nano);
        if let Some(frame) = packet::decode_record(&rec.data, ts)? {
            frames.push(frame);
        }
    }
    Ok((frames, span))
}

/// Analyze pcap bytes already held in memory.
pub fn report_for(source: &str, bytes: &[u8]) -> anyhow::Result<Report> {
    Ok(analyze_bytes(source, bytes)?.report)
}

/// Analyze pcap bytes and return the frames alongside the report.
pub fn analyze_bytes(source: &str, bytes: &[u8]) -> anyhow::Result<Loaded> {
    let (frames, span) = parse_capture(bytes)?;
    let source = source.to_string();
    Ok(Loaded {
        report: analysis::analyze(source, &frames, span),
        frames,
    })
}

/// Read and analyze one pcap file path with async IO.
pub async fn load_path(source: &str, path: &std::path::Path) -> anyhow::Result<Loaded> {
    let source = source.to_string();
    let bytes = tokio::fs::read(path).await?;
    let report = tokio::task::spawn_blocking(move || analyze_bytes(&source, &bytes)).await??;
    Ok(report)
}

/// Load every bundled fixture in parallel. Results are returned in catalog order.
pub async fn load_bundled() -> Vec<(crate::fixtures::Bundled, anyhow::Result<Loaded>)> {
    let catalog = crate::fixtures::all();
    let mut set = tokio::task::JoinSet::new();
    for (idx, fixture) in catalog.iter().enumerate() {
        let path = crate::fixtures::path(fixture.filename);
        let title = fixture.title.to_string();
        set.spawn(async move {
            let r = load_inline(path, title).await;
            (idx, r)
        });
    }
    let mut results: Vec<anyhow::Result<Loaded>> = (0..catalog.len())
        .map(|_| Err(anyhow::Error::msg("task missing")))
        .collect();
    while let Some(res) = set.join_next().await {
        if let Ok((idx, r)) = res {
            results[idx] = r;
        }
    }
    catalog
        .iter()
        .zip(results)
        .map(|(fixture, r)| (*fixture, r))
        .collect()
}

async fn load_inline(path: std::path::PathBuf, title: String) -> anyhow::Result<Loaded> {
    let bytes = tokio::fs::read(&path).await?;
    let report = tokio::task::spawn_blocking(move || analyze_bytes(&title, &bytes)).await??;
    Ok(report)
}
