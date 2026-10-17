//! Minimal PCAPNG reader for Ethernet captures.
//!
//! The reader accepts Section Header, Interface Description, Enhanced Packet,
//! and Simple Packet Blocks. Other valid blocks are skipped. It keeps the
//! existing [`crate::pcap::Capture`] model so the analyzer has one input path.

use crate::error::{ForensicsError, Result};
use crate::pcap::{Capture, Record};

const BLOCK_INTERFACE_DESCRIPTION: u32 = 1;
const BLOCK_SIMPLE_PACKET: u32 = 3;
const BLOCK_ENHANCED_PACKET: u32 = 6;
const LINK_ETHERNET: u32 = 1;
const BYTE_ORDER_MAGIC: [u8; 4] = [0x1A, 0x2B, 0x3C, 0x4D];
const SECTION_HEADER_BYTES: [u8; 4] = [0x0A, 0x0D, 0x0D, 0x0A];

#[derive(Debug, Clone, Copy)]
enum Endian {
    Little,
    Big,
}

#[derive(Debug, Clone, Copy)]
enum TimestampResolution {
    Decimal(u8),
    Binary(u8),
}

impl TimestampResolution {
    fn from_option(value: u8) -> Result<Self> {
        if value & 0x80 != 0 {
            let exponent = value & 0x7f;
            if exponent > 63 {
                return Err(ForensicsError::BadPcap(
                    "pcapng binary timestamp resolution is too large",
                ));
            }
            return Ok(Self::Binary(exponent));
        }
        let exponent = value & 0x7f;
        if exponent > 18 {
            return Err(ForensicsError::BadPcap(
                "pcapng decimal timestamp resolution is too large",
            ));
        }
        Ok(Self::Decimal(exponent))
    }

    fn micros(self, timestamp: u64) -> u64 {
        match self {
            Self::Decimal(exponent) if exponent <= 6 => {
                timestamp.saturating_mul(10u64.pow(u32::from(6 - exponent)))
            }
            Self::Decimal(exponent) => timestamp / 10u64.pow(u32::from(exponent - 6)),
            Self::Binary(exponent) => {
                timestamp.saturating_mul(1_000_000)
                    / (1u64.checked_shl(u32::from(exponent)).unwrap_or(u64::MAX))
            }
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct Interface {
    link_type: u32,
    timestamp_resolution: TimestampResolution,
}

/// Return whether the input begins with a PCAPNG Section Header Block.
pub fn is_pcapng(bytes: &[u8]) -> bool {
    bytes.get(..4) == Some(&SECTION_HEADER_BYTES)
}

/// Parse a PCAPNG byte buffer into the capture model used by the analyzers.
pub fn parse(bytes: &[u8]) -> Result<Capture> {
    if bytes.len() < 12 || !is_pcapng(bytes) {
        return Err(ForensicsError::BadPcap("file is not a pcapng container"));
    }

    let mut offset = 0usize;
    let mut endian = None;
    let mut interfaces = Vec::new();
    let mut records = Vec::new();
    let mut saw_interface = false;

    while offset < bytes.len() {
        if bytes.len() - offset < 12 {
            return Err(ForensicsError::BadPcap("pcapng block header is truncated"));
        }

        let is_section_header = bytes[offset..offset + 4] == SECTION_HEADER_BYTES;
        let block_endian = if is_section_header {
            section_endian(bytes, offset)?
        } else {
            endian.ok_or(ForensicsError::BadPcap(
                "pcapng starts without a section header",
            ))?
        };
        let block_len = read_u32(bytes, offset + 4, block_endian)? as usize;
        if block_len < 12 || block_len % 4 != 0 || block_len > bytes.len() - offset {
            return Err(ForensicsError::BadPcap("invalid pcapng block length"));
        }
        let end = offset + block_len;
        let block = &bytes[offset..end];
        if read_u32(block, block_len - 4, block_endian)? != block_len as u32 {
            return Err(ForensicsError::BadPcap(
                "pcapng block length trailer does not match",
            ));
        }

        if is_section_header {
            parse_section_header(block, block_endian)?;
            endian = Some(block_endian);
            interfaces.clear();
        } else {
            let block_type = read_u32(block, 0, block_endian)?;
            match block_type {
                BLOCK_INTERFACE_DESCRIPTION => {
                    let interface = parse_interface(block, block_endian)?;
                    if interface.link_type != LINK_ETHERNET {
                        return Err(ForensicsError::UnsupportedLink(interface.link_type));
                    }
                    interfaces.push(interface);
                    saw_interface = true;
                }
                BLOCK_ENHANCED_PACKET => {
                    records.push(parse_enhanced_packet(block, block_endian, &interfaces)?);
                }
                BLOCK_SIMPLE_PACKET => {
                    records.push(parse_simple_packet(block, block_endian, &interfaces)?);
                }
                _ => {}
            }
        }

        offset = end;
    }

    if !saw_interface {
        return Err(ForensicsError::BadPcap(
            "pcapng has no Ethernet interface description",
        ));
    }

    Ok(Capture {
        link_type: LINK_ETHERNET,
        nano: false,
        records,
    })
}

fn section_endian(bytes: &[u8], offset: usize) -> Result<Endian> {
    match bytes
        .get(offset + 8..offset + 12)
        .ok_or(ForensicsError::BadPcap(
            "pcapng section header is truncated",
        ))? {
        [0x4D, 0x3C, 0x2B, 0x1A] => Ok(Endian::Little),
        [0x1A, 0x2B, 0x3C, 0x4D] => Ok(Endian::Big),
        _ => Err(ForensicsError::BadPcap("unknown pcapng byte-order magic")),
    }
}

fn parse_section_header(block: &[u8], endian: Endian) -> Result<()> {
    if block.len() < 28 {
        return Err(ForensicsError::BadPcap(
            "pcapng section header is truncated",
        ));
    }
    if read_u32(block, 8, endian)? != u32::from_be_bytes(BYTE_ORDER_MAGIC) {
        return Err(ForensicsError::BadPcap("unknown pcapng byte-order magic"));
    }
    if read_u16(block, 12, endian)? != 1 {
        return Err(ForensicsError::BadPcap("unsupported pcapng major version"));
    }
    Ok(())
}

fn parse_interface(block: &[u8], endian: Endian) -> Result<Interface> {
    if block.len() < 20 {
        return Err(ForensicsError::BadPcap(
            "pcapng interface description is truncated",
        ));
    }
    let link_type = u32::from(read_u16(block, 8, endian)?);
    let options = &block[16..block.len() - 4];
    let timestamp_resolution = parse_interface_options(options, endian)?;
    Ok(Interface {
        link_type,
        timestamp_resolution,
    })
}

fn parse_interface_options(options: &[u8], endian: Endian) -> Result<TimestampResolution> {
    let mut resolution = TimestampResolution::Decimal(6);
    let mut offset = 0usize;
    while offset < options.len() {
        if options.len() - offset < 4 {
            return Err(ForensicsError::BadPcap(
                "pcapng interface option is truncated",
            ));
        }
        let code = read_u16(options, offset, endian)?;
        let length = read_u16(options, offset + 2, endian)? as usize;
        offset += 4;
        let padded_length =
            length
                .checked_add(3)
                .map(|value| value & !3)
                .ok_or(ForensicsError::BadPcap(
                    "pcapng interface option is too large",
                ))?;
        if padded_length > options.len() - offset {
            return Err(ForensicsError::BadPcap(
                "pcapng interface option exceeds its block",
            ));
        }
        let value = &options[offset..offset + length];
        match code {
            0 => {
                if length != 0 {
                    return Err(ForensicsError::BadPcap(
                        "pcapng option terminator has a value",
                    ));
                }
                return Ok(resolution);
            }
            9 => {
                if length != 1 {
                    return Err(ForensicsError::BadPcap(
                        "pcapng timestamp resolution has an invalid length",
                    ));
                }
                resolution = TimestampResolution::from_option(value[0])?;
            }
            _ => {}
        }
        offset += padded_length;
    }
    Ok(resolution)
}

fn parse_enhanced_packet(block: &[u8], endian: Endian, interfaces: &[Interface]) -> Result<Record> {
    if block.len() < 32 {
        return Err(ForensicsError::BadPcap(
            "pcapng enhanced packet block is truncated",
        ));
    }
    let interface_id = read_u32(block, 8, endian)? as usize;
    let interface = interfaces.get(interface_id).ok_or(ForensicsError::BadPcap(
        "pcapng packet refers to an unknown interface",
    ))?;
    let timestamp =
        (u64::from(read_u32(block, 12, endian)?) << 32) | u64::from(read_u32(block, 16, endian)?);
    let captured_len = read_u32(block, 20, endian)? as usize;
    let data_start = 28usize;
    let data_end = block.len() - 4;
    let available = data_end - data_start;
    if captured_len > available {
        return Err(ForensicsError::BadPcap(
            "pcapng enhanced packet exceeds its block",
        ));
    }
    Ok(record(
        interface.timestamp_resolution.micros(timestamp),
        block[data_start..data_start + captured_len].to_vec(),
    ))
}

fn parse_simple_packet(block: &[u8], endian: Endian, interfaces: &[Interface]) -> Result<Record> {
    if block.len() < 16 {
        return Err(ForensicsError::BadPcap(
            "pcapng simple packet block is truncated",
        ));
    }
    let _interface = interfaces.first().ok_or(ForensicsError::BadPcap(
        "pcapng simple packet has no interface",
    ))?;
    let original_len = read_u32(block, 8, endian)? as usize;
    let data_start = 12usize;
    let available = block.len() - 4 - data_start;
    let captured_len = original_len.min(available);
    Ok(record(
        0,
        block[data_start..data_start + captured_len].to_vec(),
    ))
}

fn record(ts_micros: u64, data: Vec<u8>) -> Record {
    Record {
        ts_secs: ts_micros / 1_000_000,
        ts_frac: (ts_micros % 1_000_000) as u32,
        data,
    }
}

fn read_u16(bytes: &[u8], offset: usize, endian: Endian) -> Result<u16> {
    let end = offset
        .checked_add(2)
        .ok_or(ForensicsError::BadPcap("pcapng field offset overflow"))?;
    let value = bytes
        .get(offset..end)
        .ok_or(ForensicsError::BadPcap("pcapng field is truncated"))?;
    let value: [u8; 2] = value
        .try_into()
        .map_err(|_| ForensicsError::BadPcap("pcapng field is truncated"))?;
    Ok(match endian {
        Endian::Little => u16::from_le_bytes(value),
        Endian::Big => u16::from_be_bytes(value),
    })
}

fn read_u32(bytes: &[u8], offset: usize, endian: Endian) -> Result<u32> {
    let end = offset
        .checked_add(4)
        .ok_or(ForensicsError::BadPcap("pcapng field offset overflow"))?;
    let value = bytes
        .get(offset..end)
        .ok_or(ForensicsError::BadPcap("pcapng field is truncated"))?;
    let value: [u8; 4] = value
        .try_into()
        .map_err(|_| ForensicsError::BadPcap("pcapng field is truncated"))?;
    Ok(match endian {
        Endian::Little => u32::from_le_bytes(value),
        Endian::Big => u32::from_be_bytes(value),
    })
}
