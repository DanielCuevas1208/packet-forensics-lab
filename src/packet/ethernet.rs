//! Ethernet II framing decoder.

pub const ETH_IPV4: u16 = 0x0800;

pub struct Header<'a> {
    pub dst: [u8; 6],
    pub src: [u8; 6],
    pub ethertype: u16,
    pub payload: &'a [u8],
}

/// Decode an Ethernet II frame. Returns `None` for truncated data.
pub fn decode(data: &[u8]) -> Option<Header<'_>> {
    if data.len() < 14 {
        return None;
    }
    let mut dst = [0u8; 6];
    let mut src = [0u8; 6];
    dst.copy_from_slice(&data[0..6]);
    src.copy_from_slice(&data[6..12]);
    let ethertype = u16::from_be_bytes([data[12], data[13]]);
    Some(Header {
        dst,
        src,
        ethertype,
        payload: &data[14..],
    })
}
