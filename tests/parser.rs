//! pcap container parser behavior.

use packet_forensics_lab::pcap::{self, write, WriteRecord};

#[test]
fn write_then_read_roundtrips_records() {
    let records = vec![
        WriteRecord {
            ts_secs: 1,
            ts_usec: 250_000,
            data: vec![0xAA; 40],
        },
        WriteRecord {
            ts_secs: 2,
            ts_usec: 0,
            data: vec![0xBB; 8],
        },
    ];
    let bytes = write(&records, 1);
    let cap = pcap::parse(&bytes).expect("parse");
    assert_eq!(cap.link_type, 1);
    assert!(!cap.nano);
    assert_eq!(cap.records.len(), 2);
    assert_eq!(cap.records[0].ts_secs, 1);
    assert_eq!(cap.records[0].ts_frac, 250_000);
    assert_eq!(cap.records[0].data, vec![0xAA; 40]);
    assert_eq!(cap.records[1].ts_secs, 2);
}

#[test]
fn span_micros_uses_first_and_last() {
    let records = vec![
        WriteRecord {
            ts_secs: 100,
            ts_usec: 0,
            data: vec![0; 14],
        },
        WriteRecord {
            ts_secs: 100,
            ts_usec: 500_000,
            data: vec![0; 14],
        },
        WriteRecord {
            ts_secs: 102,
            ts_usec: 250_000,
            data: vec![0; 14],
        },
    ];
    let bytes = write(&records, 1);
    let cap = pcap::parse(&bytes).unwrap();
    assert_eq!(cap.span_micros(), 2_250_000);
}

#[test]
fn big_endian_magic_is_accepted() {
    let mut bytes = write(
        &[WriteRecord {
            ts_secs: 1,
            ts_usec: 0,
            data: vec![0; 14],
        }],
        1,
    );
    // Swap the magic to big-endian and every stored word.
    for chunk in bytes.chunks_mut(4) {
        chunk.reverse();
    }
    // Fix the link type back to 1 after word swapping reversed it.
    // The writer stored link_type=1 as little-endian 01000000; reversing each
    // word converts the whole buffer to big-endian pcap. Parse should accept it.
    let cap = pcap::parse(&bytes).expect("big-endian pcap");
    assert_eq!(cap.link_type, 1);
    assert_eq!(cap.records.len(), 1);
}

#[test]
fn truncated_global_header_is_rejected() {
    let short = vec![0u8, 1, 2, 3];
    assert!(pcap::parse(&short).is_err());
}

#[test]
fn unknown_magic_is_rejected() {
    let mut bytes = vec![0u8; 24];
    bytes[0..4].copy_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
    assert!(pcap::parse(&bytes).is_err());
}

#[test]
fn unsupported_link_type_is_rejected() {
    let bytes = write(
        &[WriteRecord {
            ts_secs: 1,
            ts_usec: 0,
            data: vec![0; 14],
        }],
        99,
    );
    assert!(pcap::parse(&bytes).is_err());
}
