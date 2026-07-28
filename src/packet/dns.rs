//! DNS message decoder with name-compression support.
//!
//! The decoder reads the wire format described in RFC 1035. It limits the
//! number of compression-pointer hops to prevent loops and caps the number
//! of records decoded so that malformed fixtures cannot exhaust memory.

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Question {
    pub name: String,
    pub qtype: u16,
    pub qclass: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceRecord {
    pub name: String,
    pub rtype: u16,
    pub rclass: u16,
    pub ttl: u32,
    pub rdata: Vec<u8>,
}

/// Well-known DNS record types used by the analyzers.
pub mod rtype {
    pub const A: u16 = 1;
    pub const CNAME: u16 = 5;
    pub const TXT: u16 = 16;
    pub const AAAA: u16 = 28;
    pub const MX: u16 = 15;
    pub const NS: u16 = 2;
    pub const PTR: u16 = 12;
}

/// Common RCODE values.
pub mod rcode {
    pub const NOERROR: u8 = 0;
    pub const NXDOMAIN: u8 = 3;
    pub const SERVFAIL: u8 = 2;
}

#[derive(Debug, Clone)]
pub struct Message {
    pub id: u16,
    pub flags: u16,
    pub questions: Vec<Question>,
    pub answers: Vec<ResourceRecord>,
}

impl Message {
    pub fn is_response(&self) -> bool {
        self.flags & 0x8000 != 0
    }
    pub fn rcode(&self) -> u8 {
        (self.flags & 0x000F) as u8
    }
    pub fn qtype(&self) -> Option<u16> {
        self.questions.first().map(|q| q.qtype)
    }
    /// The first question name, lowercased.
    pub fn qname(&self) -> Option<&str> {
        self.questions.first().map(|q| q.name.as_str())
    }
}

#[derive(Debug)]
struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }
    fn u16(&mut self) -> Option<u16> {
        let b = self.buf.get(self.pos..self.pos + 2)?;
        let v = u16::from_be_bytes([b[0], b[1]]);
        self.pos += 2;
        Some(v)
    }
    fn u32(&mut self) -> Option<u32> {
        let b = self.buf.get(self.pos..self.pos + 4)?;
        let v = u32::from_be_bytes([b[0], b[1], b[2], b[3]]);
        self.pos += 4;
        Some(v)
    }
    fn take(&mut self, n: usize) -> Option<Vec<u8>> {
        let b = self.buf.get(self.pos..self.pos + n)?;
        let out = b.to_vec();
        self.pos += n;
        Some(out)
    }
}

/// Decode a name with compression pointers. Returns the decoded name and
/// the number of bytes consumed at the starting offset.
fn decode_name(buf: &[u8], start: usize) -> Option<(String, usize)> {
    let mut labels: Vec<String> = Vec::new();
    let mut pos = start;
    let mut consumed: Option<usize> = None;
    let mut jumps = 0u32;

    loop {
        let len = *buf.get(pos)?;
        if len == 0 {
            if consumed.is_none() {
                consumed = Some(pos - start + 1);
            }
            break;
        }
        let kind = len & 0xC0;
        match kind {
            0x00 => {
                let label = std::str::from_utf8(buf.get(pos + 1..pos + 1 + len as usize)?)
                    .ok()?
                    .to_string();
                labels.push(label);
                pos += 1 + len as usize;
            }
            0xC0 => {
                if consumed.is_none() {
                    consumed = Some(pos - start + 2);
                }
                jumps += 1;
                if jumps > 32 {
                    return None;
                }
                let ptr = (((len & 0x3F) as usize) << 8) | (*buf.get(pos + 1)? as usize);
                if ptr >= pos {
                    return None;
                }
                pos = ptr;
            }
            _ => return None,
        }
    }
    let consumed = consumed.unwrap_or(0);
    let name = labels.join(".").to_lowercase();
    Some((name, consumed))
}

/// Parse a DNS message. Returns `None` when the buffer is too short or
/// the record counts do not match the available bytes.
pub fn parse(buf: &[u8]) -> Option<Message> {
    if buf.len() < 12 {
        return None;
    }
    let id = u16::from_be_bytes([buf[0], buf[1]]);
    let flags = u16::from_be_bytes([buf[2], buf[3]]);
    let qd = u16::from_be_bytes([buf[4], buf[5]]) as usize;
    let an = u16::from_be_bytes([buf[6], buf[7]]) as usize;
    let ns = u16::from_be_bytes([buf[8], buf[9]]) as usize;
    let ar = u16::from_be_bytes([buf[10], buf[11]]) as usize;
    let total = qd + an + ns + ar;
    if total > 64 {
        return None;
    }

    let mut cur = Cursor::new(buf);
    cur.pos = 12;

    let mut questions = Vec::with_capacity(qd);
    for _ in 0..qd {
        let (name, consumed) = decode_name(buf, cur.pos)?;
        cur.pos += consumed;
        let qtype = cur.u16()?;
        let qclass = cur.u16()?;
        questions.push(Question {
            name,
            qtype,
            qclass,
        });
    }

    let mut answers = Vec::with_capacity(an + ns + ar);
    for _ in 0..(an + ns + ar) {
        let (name, consumed) = decode_name(buf, cur.pos)?;
        cur.pos += consumed;
        let rtype = cur.u16()?;
        let rclass = cur.u16()?;
        let ttl = cur.u32()?;
        let rdlen = cur.u16()? as usize;
        let rdata = cur.take(rdlen)?;
        answers.push(ResourceRecord {
            name,
            rtype,
            rclass,
            ttl,
            rdata,
        });
    }

    Some(Message {
        id,
        flags,
        questions,
        answers,
    })
}

/// Best-effort extraction of the TXT string payload from an rdata buffer.
pub fn txt_string(rdata: &[u8]) -> Option<String> {
    let mut out = String::new();
    let mut i = 0;
    while i < rdata.len() {
        let len = rdata[i] as usize;
        i += 1;
        if i + len > rdata.len() {
            return None;
        }
        out.push_str(std::str::from_utf8(&rdata[i..i + len]).ok()?);
        i += len;
    }
    Some(out)
}
