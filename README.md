# Packet Forensics Lab

Packet Forensics Lab is an offline network-forensics tool for defensive study.
It reads bundled packet captures and explains suspicious DNS, connection, and
timing patterns. It never sends packets or performs active scans. It uses only
the sample fixtures in this repository.

## Why this tool exists

This lab provides a safe way to study hostile traffic shapes. Real captures can
contain private data and real hosts. The bundled fixtures keep the traffic shape
but contain no real hosts or secrets. Each fixture is deterministic, so the same
input produces the same report.

The analyzers explain each finding. Each finding has a severity, a category,
and a short cause note. The note identifies the value that drove the decision.

## Architecture

The crate is split into small modules that each own one job.

- `pcap` reads the classic libpcap container. It supports both byte orders and
  the nanosecond timestamp variant. Ethernet (link type 1) is the only link
  layer it accepts.
- `packet` decodes Ethernet, IPv4, UDP, TCP, and DNS. The decoders never
  allocate beyond the returned structures and never verify checksums.
- `wire` builds the same layers in reverse. The fixture generator uses it to
  craft bytes. Tests use it to assert correct decode behavior.
- `analysis` runs three analyzers: DNS anomalies, connection anomalies, and
  timing anomalies. Each analyzer returns a list of `Finding` values.
- `loader` reads bytes with Tokio, parses with `spawn_blocking`, and pairs the
  decoded frames with a `Report`.
- `tui` renders a Ratatui interface. It lists fixtures, shows findings, shows
  summary numbers, and shows the decoded flow table.
- `render` writes a plain-text report for the `scan` command.

The data flow is one direction. Bytes enter at `pcap`, become frames at
`packet`, become findings at `analysis`, and become views in `tui` or text in
`render`.

## Bundled fixtures

The `fixtures/` directory holds four captures. Each is a crafted pcap file.

| Name        | Scenario                                          | Expected worst finding |
|-------------|---------------------------------------------------|-------------------------|
| baseline    | Eight normal resolver queries with irregular times | None (INFO only)        |
| dns_tunnel  | Noisy long labels, NXDOMAIN flood, large TXT      | HIGH, DNS tunneling     |
| port_scan    | Twelve SYN segments to one host                   | HIGH, port scan         |
| beacon       | Eight TCP segments on a regular 5 s cadence        | HIGH, beaconing         |

Run `cargo run --example gen_fixtures` to rebuild the fixtures. The generator
uses the `wire` module so the bytes stay in sync with the decoders.

## Build and run

This crate needs Rust 1.74 or newer. Build it from the repository root.

```
cargo build --release
```

List the bundled fixtures.

```
cargo run --release -- list
```

Scan one bundled fixture by name and print the report. The default
output is plain text. Add `--format json` for a machine-readable report.

```
cargo run --release -- scan dns_tunnel
cargo run --release -- scan dns_tunnel --format json
```

Scan any pcap file by path. The classic libpcap format is supported.

```
cargo run --release -- scan path/to/capture.pcap
cargo run --release -- scan path/to/capture.pcap --format json
```

The JSON output uses one schema string and one set of field names across
all releases. The current schema is `packet-forensics-lab/report/v1`. The
report carries a `source` string, a `summary` object, and a `findings`
array. Findings keep the severity-sorted order of the text report.

Open the interactive terminal interface. The interface runs against the
bundled fixtures.

```
cargo run --release -- tui
```

Inside the interface use Up and Down to select a fixture. Use Tab to switch
between the Findings, Summary, and Flows tabs. Press 1, 2, or 3 to jump to a
tab. Press q to quit.

## Sample output

Scan the `dns_tunnel` fixture.

```
Packet Forensics Lab - report for DNS tunneling with noisy labels and NXDOMAIN flood
=============================================
Frames decoded:  19
IP flows:        2
DNS queries:     12
DNS responses:  7
TCP SYN packets: 0
Capture window:  0.90 s
Findings:        4
Worst severity: HIGH

1. [HIGH] [DNS] DNS tunneling indicator
   12 queries to example.com from 10.10.0.21 carry noisy labels. The longest label is 30 bytes. Inspect the longest sublabels for encoded data.
2. [MEDIUM] [DNS] NXDOMAIN flood
   6 responses returned NXDOMAIN. Longest queried name measured 49 bytes. Compare against allowed resolver behavior for the host.
3. [MEDIUM] [DNS] Large TXT records
   1 TXT answer sets exceeded 64 bytes. Largest TXT payload measured 81 bytes. Treat oversized TXT answers as a covert-channel indicator.
4. [LOW] [DNS] Query concentration
   12 queries targeted example.com. Confirm that the volume matches an expected resolver pattern.
```

Scan the `port_scan` fixture.

```
Packet Forensics Lab - report for TCP SYN sweep across 12 ports on one host
=============================================
Frames decoded:  12
IP flows:        12
DNS queries:     0
DNS responses:   0
TCP SYN packets: 12
Capture window:  0.06 s
Findings:        1
Worst severity: HIGH

1. [HIGH] [Connection] TCP SYN port scan
   10.10.0.21 sent SYN segments to 12 ports on 192.0.2.50. First ports observed: 22, 23, 25, 53, 80, 110, 143, 443. This pattern matches a port sweep.
```

Scan the `port_scan` fixture with JSON output. The same call piped to
`jq .` shows the report shape.

```
$ cargo run --release -- scan port_scan --format json | jq .
{
  "schema": "packet-forensics-lab/report/v1",
  "source": "TCP SYN sweep across 12 ports on one host",
  "summary": {
    "frames": 12,
    "flows": 12,
    "dns_queries": 0,
    "dns_responses": 0,
    "tcp_syns": 12,
    "capture_window_seconds": 0.06,
    "findings": 1,
    "worst_severity": "HIGH"
  },
  "findings": [
    {
      "severity": "HIGH",
      "category": "Connection",
      "title": "TCP SYN port scan",
      "detail": "10.10.0.21 sent SYN segments to 12 ports on 192.0.2.50. First ports observed: 22, 23, 25, 53, 80, 110, 143, 443. This pattern matches a port sweep."
    }
  ]
}
```

The JSON renderer writes no whitespace between tokens. The output above
is pretty-printed by `jq` for readability. Parsing tools see a single
deterministic line.

## Tests

The suite covers parser, decoder, analyzer, renderer, and loader behavior.
Run it from the repository root.

```
cargo test
```

Format and lint options are configured for CI.

```
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
```

## Limitations

The lab accepts only the classic libpcap container. PCAPNG files are not read.
Only Ethernet and IPv4 are decoded. ARP, IPv6, and ICMP frames are skipped.
UDP and TCP checksums are never verified. The fixture generator writes zero
checksums on purpose. The analyzers use fixed thresholds that suit the bundled
fixtures. Tune the constants in `src/analysis` before you trust them on real
traffic. The timing analyzer treats each capture as a closed window. It cannot
reason about gaps that the capture did not record.

## Roadmap

The lab ships JSON and text reports from one analyzer pipeline. The
remaining work extends the lab without changing the offline contract.

### Completed

- Bundled Ethernet, IPv4, UDP, TCP, and DNS decoders.
- Classic libpcap container reader with both byte orders.
- DNS, connection, and timing analyzers with explained findings.
- Deterministic fixture generator under `examples/`.
- Ratatui terminal interface with Findings, Summary, and Flows tabs.
- Plain-text report for the `scan` command.
- JSON report for the `scan` command (`schema packet-forensics-lab/report/v1`).

### Remaining

- Decoders for IPv6, ICMP, and ARP.
- A PCAPNG container reader.
- PCAPNG write support in the fixture generator.
- Per-flow statistics in the Flows tab.
- Confidence scores that replace the hard severity thresholds.
- A plugin trait that lets external crates add analyzers.

## License

This project is licensed under the MIT License. See the `LICENSE` file.
