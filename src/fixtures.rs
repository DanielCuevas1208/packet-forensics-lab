//! Bundled reference captures.
//!
//! The fixtures are crafted pcap files committed under `fixtures/`. They
//! never touch the network and contain no real hostnames. The catalog below
//! keeps the short names stable so the interface and tests can reference them.

use std::path::PathBuf;

/// A bundled fixture listed in the catalog.
#[derive(Debug, Clone, Copy)]
pub struct Bundled {
    pub name: &'static str,
    pub title: &'static str,
    pub filename: &'static str,
}

/// Return the bundled fixtures ordered from tame to hostile.
pub fn all() -> &'static [Bundled] {
    &[
        Bundled {
            name: "baseline",
            title: "Baseline office resolver traffic",
            filename: "baseline.pcap",
        },
        Bundled {
            name: "dns_tunnel",
            title: "DNS tunneling with noisy labels and NXDOMAIN flood",
            filename: "dns_tunnel.pcap",
        },
        Bundled {
            name: "port_scan",
            title: "TCP SYN sweep across 12 ports on one host",
            filename: "port_scan.pcap",
        },
        Bundled {
            name: "beacon",
            title: "Regular 5 s beacon to one host on port 443",
            filename: "beacon.pcap",
        },
    ]
}

/// Find a bundled fixture by short name.
pub fn find(name: &str) -> Option<&'static Bundled> {
    all().iter().find(|f| f.name == name)
}

/// Resolve the bundled fixtures directory.
///
/// `PFL_FIXTURES_DIR` overrides the default. Otherwise the directory is
/// discovered from `CARGO_MANIFEST_DIR` during tests and next to the
/// executable at runtime.
pub fn dir() -> PathBuf {
    if let Ok(p) = std::env::var("PFL_FIXTURES_DIR") {
        return PathBuf::from(p);
    }
    if let Ok(p) = std::env::var("CARGO_MANIFEST_DIR") {
        return PathBuf::from(p).join("fixtures");
    }
    let mut exe = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("."));
    exe.pop();
    exe.pop();
    exe.join("fixtures")
}

/// Path to a fixture filename within the bundled directory.
pub fn path(filename: &str) -> PathBuf {
    dir().join(filename)
}
