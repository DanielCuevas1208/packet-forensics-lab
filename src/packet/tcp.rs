//! TCP header decoder for the small subset used by forensics analysis.

pub const FLAG_FIN: u16 = 0x0001;
pub const FLAG_SYN: u16 = 0x0002;
pub const FLAG_RST: u16 = 0x0004;
pub const FLAG_PSH: u16 = 0x0008;
pub const FLAG_ACK: u16 = 0x0010;

pub struct Header<'a> {
    pub src_port: u16,
    pub dst_port: u16,
    pub seq: u32,
    pub ack: u32,
    pub flags: u16,
    pub payload: &'a [u8],
}

/// Decode a TCP segment. Returns `None` if truncated or if the
/// data offset field describes bytes that the buffer does not hold.
pub fn decode(data: &[u8]) -> Option<Header<'_>> {
    if data.len() < 20 {
        return None;
    }
    let data_offset = ((data[12] >> 4) as usize) * 4;
    if data_offset < 20 || data.len() < data_offset {
        return None;
    }
    let src_port = u16::from_be_bytes([data[0], data[1]]);
    let dst_port = u16::from_be_bytes([data[2], data[3]]);
    let seq = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
    let ack = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);
    let flags = u16::from_be_bytes([data[12], data[13]]) & 0x01FF;
    Some(Header {
        src_port,
        dst_port,
        seq,
        ack,
        flags,
        payload: &data[data_offset..],
    })
}
