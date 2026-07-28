//! Timing anomaly analysis: beaconing and bursts.

use super::{Category, Finding, Severity};
use crate::packet::{Frame, Proto};
use std::collections::HashMap;
use std::net::Ipv4Addr;

const BEACON_MIN_GAPS: usize = 3;
const BEACON_MAX_CV: f64 = 0.20;
const BEACON_MIN_INTERVAL_MICROS: u64 = 500_000;
const BURST_WINDOW_MICROS: u64 = 100_000;
const BURST_MIN_FRAMES: usize = 20;

struct Series {
    times: Vec<u64>,
}

pub fn analyze(frames: &[Frame], span_micros: u64) -> Vec<Finding> {
    let mut by_pair: HashMap<(Ipv4Addr, Ipv4Addr, Proto), Series> = HashMap::new();
    for f in frames {
        by_pair
            .entry((f.flow.src, f.flow.dst, f.flow.proto))
            .or_insert_with(|| Series { times: Vec::new() })
            .times
            .push(f.ts_micros);
    }

    let mut out = Vec::new();
    for ((src, dst, proto), series) in by_pair {
        out.extend(beacon(&src, &dst, proto, &series));
    }
    out.extend(burst(frames));
    out.extend(quiet(span_micros));
    out
}

fn beacon(src: &Ipv4Addr, dst: &Ipv4Addr, proto: Proto, series: &Series) -> Vec<Finding> {
    let mut times = series.times.clone();
    times.sort_unstable();
    if times.len() <= BEACON_MIN_GAPS {
        return Vec::new();
    }
    let mut gaps: Vec<u64> = Vec::with_capacity(times.len() - 1);
    for w in times.windows(2) {
        let g = w[1].saturating_sub(w[0]);
        if g >= BEACON_MIN_INTERVAL_MICROS {
            gaps.push(g);
        }
    }
    if gaps.len() < BEACON_MIN_GAPS {
        return Vec::new();
    }
    let mean = mean(&gaps);
    if mean == 0.0 {
        return Vec::new();
    }
    let stdev = stdev(&gaps, mean);
    let cv = stdev / mean;
    if cv > BEACON_MAX_CV {
        return Vec::new();
    }
    vec![Finding::new(
        Category::Timing,
        Severity::High,
        "Beaconing pattern",
        format!(
            "{src} contacted {dst} via {p} on a regular cadence. Mean interval {mean_ms:.0} ms, jitter {jitter_ms:.0} ms (CV {cv:.2}). Compare against an expected heartbeat.",
            p = proto_label(proto),
            mean_ms = mean / 1000.0,
            jitter_ms = stdev / 1000.0,
        ),
    )]
}

fn burst(frames: &[Frame]) -> Vec<Finding> {
    if frames.is_empty() {
        return Vec::new();
    }
    let mut times: Vec<u64> = frames.iter().map(|f| f.ts_micros).collect();
    times.sort_unstable();
    let mut best = 0usize;
    let mut best_start = 0u64;
    let mut left = 0usize;
    for right in 0..times.len() {
        while times[right] - times[left] >= BURST_WINDOW_MICROS {
            left += 1;
        }
        let width = right - left + 1;
        if width > best {
            best = width;
            best_start = times[left];
        }
    }
    if best >= BURST_MIN_FRAMES {
        vec![Finding::new(
            Category::Timing,
            Severity::Medium,
            "Traffic burst",
            format!(
                "{best} frames were sent within {window_ms:.0} ms starting at offset {start_ms:.0} ms into the capture.",
                window_ms = BURST_WINDOW_MICROS as f64 / 1000.0,
                start_ms = best_start as f64 / 1000.0,
            ),
        )]
    } else {
        Vec::new()
    }
}

fn quiet(span_micros: u64) -> Vec<Finding> {
    if span_micros >= 5_000_000 {
        vec![Finding::new(
            Category::Timing,
            Severity::Info,
            "Extended capture window",
            format!(
                "The capture spans {seconds:.1} s. Anomalies below depend on the sampled window.",
                seconds = span_micros as f64 / 1_000_000.0,
            ),
        )]
    } else {
        Vec::new()
    }
}

fn proto_label(p: Proto) -> &'static str {
    match p {
        Proto::Udp => "UDP",
        Proto::Tcp => "TCP",
    }
}

fn mean(xs: &[u64]) -> f64 {
    if xs.is_empty() {
        return 0.0;
    }
    (xs.iter().map(|&x| x as f64).sum::<f64>()) / xs.len() as f64
}

fn stdev(xs: &[u64], mean: f64) -> f64 {
    if xs.len() < 2 {
        return 0.0;
    }
    let var: f64 = xs
        .iter()
        .map(|&x| {
            let d = x as f64 - mean;
            d * d
        })
        .sum::<f64>()
        / (xs.len() - 1) as f64;
    var.sqrt()
}
