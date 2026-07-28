//! UDP header decoder.

pub struct Header<'a> {
    pub src_port: u16,
    pub dst_port: u16,
    pub length: u16,
    pub payload: &'a [u8],
}

/// Decode a UDP datagram. Returns `None` if truncated or if the
/// length field disagrees with the buffer.
pub fn decode(data: &[u8]) -> Option<Header<'_>> {
    if data.len() < 8 {
        return None;
    }
    let src_port = u16::from_be_bytes([data[0], data[1]]);
    let dst_port = u16::from_be_bytes([data[2], data[3]]);
    let length = u16::from_be_bytes([data[4], data[5]]);
    if (length as usize) < 8 || (length as usize) > data.len() {
        return None;
    }
    Some(Header {
        src_port,
        dst_port,
        length,
        payload: &data[8..length as usize],
    })
}
