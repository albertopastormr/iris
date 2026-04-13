use bytes::{Buf, BufMut, BytesMut};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum DnsError {
    #[error("DNS message is too short: expected at least {expected} bytes, but got {actual}")]
    TooShort { expected: usize, actual: usize },
    #[error("Malformed DNS header")]
    MalformedHeader,
    #[error("Invalid Query Type: {0}")]
    InvalidQueryType(u16),
    #[error("Invalid UTF-8 in label")]
    InvalidLabelText(#[from] std::string::FromUtf8Error),
}

pub trait ByteCodec: Sized {
    fn from_bytes(buf: &mut impl Buf) -> Result<Self, DnsError>;
    fn to_bytes(&self, buf: &mut BytesMut);
}

pub const HEADER_SIZE: usize = 12;
pub const MAX_PACKET_SIZE: usize = 512;

// DNS Header Flag Bit Positions
const QR_SHIFT: u8 = 15;
const OPCODE_SHIFT: u8 = 11;
const AA_SHIFT: u8 = 10;
const TC_SHIFT: u8 = 9;
const RD_SHIFT: u8 = 8;
const RA_SHIFT: u8 = 7;
const Z_SHIFT: u8 = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueryType {
    A = 1,
    CNAME = 5,
}

impl TryFrom<u16> for QueryType {
    type Error = DnsError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(QueryType::A),
            5 => Ok(QueryType::CNAME),
            _ => Err(DnsError::InvalidQueryType(value)),
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct DnsHeader {
    pub id: u16,
    pub qr: bool,   // Query/Response (0 for query, 1 for response)
    pub opcode: u8, // 4 bits
    pub aa: bool,   // Authoritative Answer
    pub tc: bool,   // Truncation
    pub rd: bool,   // Recursion Desired
    pub ra: bool,   // Recursion Available
    pub z: u8,      // Reserved (3 bits)
    pub rcode: u8,  // Response Code (4 bits)
    pub qdcount: u16,
    pub ancount: u16,
    pub nscount: u16,
    pub arcount: u16,
}

impl ByteCodec for DnsHeader {
    fn from_bytes(buf: &mut impl Buf) -> Result<Self, DnsError> {
        if buf.remaining() < HEADER_SIZE {
            return Err(DnsError::TooShort {
                expected: HEADER_SIZE,
                actual: buf.remaining(),
            });
        }

        let id = buf.get_u16();
        let flags = buf.get_u16();

        let qr = (flags >> QR_SHIFT) & 1 == 1;
        let opcode = ((flags >> OPCODE_SHIFT) & 0b1111) as u8;
        let aa = (flags >> AA_SHIFT) & 1 == 1;
        let tc = (flags >> TC_SHIFT) & 1 == 1;
        let rd = (flags >> RD_SHIFT) & 1 == 1;
        let ra = (flags >> RA_SHIFT) & 1 == 1;
        let z = ((flags >> Z_SHIFT) & 0b111) as u8;
        let rcode = (flags & 0b1111) as u8;

        let qdcount = buf.get_u16();
        let ancount = buf.get_u16();
        let nscount = buf.get_u16();
        let arcount = buf.get_u16();

        Ok(DnsHeader {
            id,
            qr,
            opcode,
            aa,
            tc,
            rd,
            ra,
            z,
            rcode,
            qdcount,
            ancount,
            nscount,
            arcount,
        })
    }

    fn to_bytes(&self, buf: &mut BytesMut) {
        buf.put_u16(self.id);

        let mut flags: u16 = 0;
        if self.qr {
            flags |= 1 << QR_SHIFT;
        }
        flags |= (self.opcode as u16 & 0b1111) << OPCODE_SHIFT;
        if self.aa {
            flags |= 1 << AA_SHIFT;
        }
        if self.tc {
            flags |= 1 << TC_SHIFT;
        }
        if self.rd {
            flags |= 1 << RD_SHIFT;
        }
        if self.ra {
            flags |= 1 << RA_SHIFT;
        }
        flags |= (self.z as u16 & 0b111) << Z_SHIFT;
        flags |= self.rcode as u16 & 0b1111;

        buf.put_u16(flags);
        buf.put_u16(self.qdcount);
        buf.put_u16(self.ancount);
        buf.put_u16(self.nscount);
        buf.put_u16(self.arcount);
    }
}

#[derive(Debug, Clone)]
pub struct DnsQuestion {
    pub name: String,
    pub qtype: QueryType,
    pub qclass: u16,
}

impl ByteCodec for DnsQuestion {
    fn from_bytes(buf: &mut impl Buf) -> Result<Self, DnsError> {
        let name = decode_name(buf)?;
        let qtype = QueryType::try_from(buf.get_u16())?;
        let qclass = buf.get_u16();

        Ok(DnsQuestion { name, qtype, qclass })
    }

    fn to_bytes(&self, buf: &mut BytesMut) {
        encode_name(&self.name, buf);
        buf.put_u16(self.qtype as u16);
        buf.put_u16(self.qclass);
    }
}

#[derive(Debug, Clone)]
pub enum RData {
    A(std::net::Ipv4Addr),
}

impl RData {
    pub fn from_bytes(buf: &mut impl Buf, rtype: QueryType, rdlength: u16) -> Result<Self, DnsError> {
        match rtype {
            QueryType::A => {
                if rdlength != 4 {
                    // In a production server, we'd define a specific error for this
                    return Err(DnsError::MalformedHeader);
                }
                let mut octets = [0u8; 4];
                buf.copy_to_slice(&mut octets);
                Ok(RData::A(std::net::Ipv4Addr::from(octets)))
            }
            _ => Err(DnsError::InvalidQueryType(rtype as u16)),
        }
    }

    pub fn to_bytes(&self, buf: &mut BytesMut) {
        match self {
            RData::A(addr) => buf.put_slice(&addr.octets()),
        }
    }

    pub fn len(&self) -> u16 {
        match self {
            RData::A(_) => 4,
        }
    }
}


#[derive(Debug, Clone)]
pub struct DnsRecord {
    pub name: String,
    pub rtype: QueryType,
    pub class: u16,
    pub ttl: u32,
    pub data: RData,
}

impl ByteCodec for DnsRecord {
    fn from_bytes(buf: &mut impl Buf) -> Result<Self, DnsError> {
        let name = decode_name(buf)?;
        let rtype = QueryType::try_from(buf.get_u16())?;
        let class = buf.get_u16();
        let ttl = buf.get_u32();
        let rdlength = buf.get_u16();
        let data = RData::from_bytes(buf, rtype, rdlength)?;

        Ok(DnsRecord { name, rtype, class, ttl, data })
    }

    fn to_bytes(&self, buf: &mut BytesMut) {
        encode_name(&self.name, buf);
        buf.put_u16(self.rtype as u16);
        buf.put_u16(self.class);
        buf.put_u32(self.ttl);
        buf.put_u16(self.data.len());
        self.data.to_bytes(buf);
    }
}

#[derive(Debug, Clone)]
pub struct DnsMessage {
    pub header: DnsHeader,
    pub questions: Vec<DnsQuestion>,
    pub answers: Vec<DnsRecord>,
}

impl ByteCodec for DnsMessage {
    fn from_bytes(buf: &mut impl Buf) -> Result<Self, DnsError> {
        let header = DnsHeader::from_bytes(buf)?;
        let mut questions = Vec::with_capacity(header.qdcount as usize);
        let mut answers = Vec::with_capacity(header.ancount as usize);

        for _ in 0..header.qdcount {
            questions.push(DnsQuestion::from_bytes(buf)?);
        }

        for _ in 0..header.ancount {
            answers.push(DnsRecord::from_bytes(buf)?);
        }

        Ok(DnsMessage { header, questions, answers })
    }

    fn to_bytes(&self, buf: &mut BytesMut) {
        self.header.to_bytes(buf);
        for question in &self.questions {
            question.to_bytes(buf);
        }
        for answer in &self.answers {
            answer.to_bytes(buf);
        }
    }
}

// --- Helper Functions for Name Encoding/Decoding ---

fn encode_name(name: &str, buf: &mut BytesMut) {
    for label in name.split('.') {
        buf.put_u8(label.len() as u8);
        buf.put_slice(label.as_bytes());
    }
    buf.put_u8(0);
}

fn decode_name(buf: &mut impl Buf) -> Result<String, DnsError> {
    let mut name = String::new();
    loop {
        let len = buf.get_u8();
        if len == 0 {
            break;
        }

        if !name.is_empty() {
            name.push('.');
        }

        let mut label_bytes = vec![0; len as usize];
        if buf.remaining() < len as usize {
            return Err(DnsError::TooShort {
                expected: len as usize,
                actual: buf.remaining(),
            });
        }
        buf.copy_to_slice(&mut label_bytes);
        name.push_str(&String::from_utf8(label_bytes)?);
    }
    Ok(name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;

    #[test]
    fn test_header_serialization_deserialization() {
        let original_header = DnsHeader {
            id: 0x1234,
            qr: true,
            opcode: 0,
            aa: true,
            tc: false,
            rd: true,
            ra: true,
            z: 0,
            rcode: 0,
            qdcount: 1,
            ancount: 1,
            nscount: 0,
            arcount: 0,
        };

        let mut buf = BytesMut::with_capacity(HEADER_SIZE);
        original_header.to_bytes(&mut buf);
        assert_eq!(buf.len(), HEADER_SIZE);

        let mut read_buf = buf.freeze();
        let decoded_header = DnsHeader::from_bytes(&mut read_buf).expect("Should decode");

        assert_eq!(decoded_header.id, original_header.id);
        assert_eq!(decoded_header.qr, original_header.qr);
        assert_eq!(decoded_header.aa, original_header.aa);
        assert_eq!(decoded_header.rd, original_header.rd);
        assert_eq!(decoded_header.qdcount, original_header.qdcount);
        assert_eq!(decoded_header.ancount, original_header.ancount);
    }

    #[test]
    fn test_header_too_short() {
        let mut short_buf = Bytes::from_static(&[0; 10]);
        let result = DnsHeader::from_bytes(&mut short_buf);
        assert!(matches!(result, Err(DnsError::TooShort { .. })));
    }

    #[test]
    fn test_query_type_try_from() {
        assert_eq!(QueryType::try_from(1).unwrap(), QueryType::A);
        assert_eq!(QueryType::try_from(5).unwrap(), QueryType::CNAME);
        assert!(QueryType::try_from(99).is_err());
    }

    #[test]
    fn test_question_codec() {
        let original = DnsQuestion {
            name: "google.com".to_string(),
            qtype: QueryType::A,
            qclass: 1,
        };

        let mut buf = BytesMut::new();
        original.to_bytes(&mut buf);

        // Expected bytes: [6, g, o, o, g, l, e, 3, c, o, m, 0, 0, 1, 0, 1]
        assert_eq!(buf[0], 6);
        assert_eq!(&buf[1..7], b"google");
        assert_eq!(buf[7], 3);
        assert_eq!(&buf[8..11], b"com");
        assert_eq!(buf[11], 0);

        let mut read_buf = buf.freeze();
        let decoded = DnsQuestion::from_bytes(&mut read_buf).unwrap();
        assert_eq!(decoded.name, "google.com");
        assert_eq!(decoded.qtype, QueryType::A);
        assert_eq!(decoded.qclass, 1);
    }

    #[test]
    fn test_message_codec() {
        let header = DnsHeader {
            id: 1234,
            qr: true,
            qdcount: 2,
            ..Default::default()
        };

        let q1 = DnsQuestion {
            name: "a.com".to_string(),
            qtype: QueryType::A,
            qclass: 1,
        };

        let q2 = DnsQuestion {
            name: "b.org".to_string(),
            qtype: QueryType::CNAME,
            qclass: 1,
        };

        let original = DnsMessage {
            header,
            questions: vec![q1, q2],
        };

        let mut buf = BytesMut::new();
        original.to_bytes(&mut buf);

        let mut read_buf = buf.freeze();
        let decoded = DnsMessage::from_bytes(&mut read_buf).unwrap();

        assert_eq!(decoded.header.id, 1234);
        assert_eq!(decoded.questions.len(), 2);
        assert_eq!(decoded.questions[0].name, "a.com");
        assert_eq!(decoded.questions[1].name, "b.org");
    }

    #[test]
    fn test_truncated_label() {
        // Label says length is 10, but only 3 bytes follow before null
        let data = Bytes::from_static(&[10, b'a', b'b', b'c', 0]);
        let mut buf = data;
        let result = DnsQuestion::from_bytes(&mut buf);
        assert!(matches!(result, Err(DnsError::TooShort { .. })));
    }
}
