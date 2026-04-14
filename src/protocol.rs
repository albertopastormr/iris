use bytes::{BufMut, BytesMut};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum DnsError {
    #[error("DNS message is too short")]
    TooShort,
    #[error("Too many jumps in compressed name")]
    TooManyJumps,
    #[error("Malformed DNS header")]
    MalformedHeader,
    #[error("Invalid Query Type: {0}")]
    InvalidQueryType(u16),
    #[error("Invalid UTF-8 in label")]
    InvalidLabelText(#[from] std::string::FromUtf8Error),
}

pub struct PacketBuffer<'a> {
    pub buf: &'a [u8],
    pub pos: usize,
}

impl<'a> PacketBuffer<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    pub fn read_u8(&mut self) -> Result<u8, DnsError> {
        if self.pos >= self.buf.len() {
            return Err(DnsError::TooShort);
        }
        let val = self.buf[self.pos];
        self.pos += 1;
        Ok(val)
    }

    pub fn read_u16(&mut self) -> Result<u16, DnsError> {
        if self.pos + 2 > self.buf.len() {
            return Err(DnsError::TooShort);
        }
        let val = u16::from_be_bytes([self.buf[self.pos], self.buf[self.pos + 1]]);
        self.pos += 2;
        Ok(val)
    }

    pub fn read_u32(&mut self) -> Result<u32, DnsError> {
        if self.pos + 4 > self.buf.len() {
            return Err(DnsError::TooShort);
        }
        let val = u32::from_be_bytes([
            self.buf[self.pos],
            self.buf[self.pos + 1],
            self.buf[self.pos + 2],
            self.buf[self.pos + 3],
        ]);
        self.pos += 4;
        Ok(val)
    }

    pub fn copy_to_slice(&mut self, dest: &mut [u8]) -> Result<(), DnsError> {
        if self.pos + dest.len() > self.buf.len() {
            return Err(DnsError::TooShort);
        }
        dest.copy_from_slice(&self.buf[self.pos..self.pos + dest.len()]);
        self.pos += dest.len();
        Ok(())
    }
}

pub trait ByteCodec: Sized {
    fn from_bytes(buffer: &mut PacketBuffer) -> Result<Self, DnsError>;
    fn to_bytes(&self, buf: &mut BytesMut);
}

pub const HEADER_SIZE: usize = 12;
pub const MAX_PACKET_SIZE: usize = 512;

// DNS Opcodes
pub const OPCODE_STANDARD_QUERY: u8 = 0;

// DNS Response Codes
pub const RCODE_NO_ERROR: u8 = 0;
pub const RCODE_NOT_IMPLEMENTED: u8 = 4;

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

#[derive(Debug, Clone, Copy, Default)]
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
    fn from_bytes(buffer: &mut PacketBuffer) -> Result<Self, DnsError> {
        let id = buffer.read_u16()?;
        let flags = buffer.read_u16()?;

        let qr = (flags >> QR_SHIFT) & 1 == 1;
        let opcode = ((flags >> OPCODE_SHIFT) & 0b1111) as u8;
        let aa = (flags >> AA_SHIFT) & 1 == 1;
        let tc = (flags >> TC_SHIFT) & 1 == 1;
        let rd = (flags >> RD_SHIFT) & 1 == 1;
        let ra = (flags >> RA_SHIFT) & 1 == 1;
        let z = ((flags >> Z_SHIFT) & 0b111) as u8;
        let rcode = (flags & 0b1111) as u8;

        let qdcount = buffer.read_u16()?;
        let ancount = buffer.read_u16()?;
        let nscount = buffer.read_u16()?;
        let arcount = buffer.read_u16()?;

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

impl DnsHeader {
    pub fn into_response(self) -> Self {
        DnsHeader {
            id: self.id,
            qr: true,
            opcode: self.opcode,
            aa: false,
            tc: false,
            rd: self.rd,
            ra: false,
            z: 0,
            rcode: if self.opcode == OPCODE_STANDARD_QUERY {
                RCODE_NO_ERROR
            } else {
                RCODE_NOT_IMPLEMENTED
            },
            qdcount: self.qdcount,
            ancount: 0, // Should be updated by the caller
            nscount: 0,
            arcount: 0,
        }
    }
}

#[derive(Debug, Clone)]
pub struct DnsQuestion {
    pub name: String,
    pub qtype: QueryType,
    pub qclass: u16,
}

impl ByteCodec for DnsQuestion {
    fn from_bytes(buffer: &mut PacketBuffer) -> Result<Self, DnsError> {
        let name = decode_name(buffer)?;
        let qtype = QueryType::try_from(buffer.read_u16()?)?;
        let qclass = buffer.read_u16()?;

        Ok(DnsQuestion {
            name,
            qtype,
            qclass,
        })
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
    pub fn from_bytes(buffer: &mut PacketBuffer, rtype: QueryType, rdlength: u16) -> Result<Self, DnsError> {
        match rtype {
            QueryType::A => {
                if rdlength != 4 {
                    return Err(DnsError::MalformedHeader);
                }
                let mut octets = [0u8; 4];
                buffer.copy_to_slice(&mut octets)?;
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
    fn from_bytes(buffer: &mut PacketBuffer) -> Result<Self, DnsError> {
        let name = decode_name(buffer)?;
        let rtype = QueryType::try_from(buffer.read_u16()?)?;
        let class = buffer.read_u16()?;
        let ttl = buffer.read_u32()?;
        let rdlength = buffer.read_u16()?;
        let data = RData::from_bytes(buffer, rtype, rdlength)?;

        Ok(DnsRecord {
            name,
            rtype,
            class,
            ttl,
            data,
        })
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
    fn from_bytes(buffer: &mut PacketBuffer) -> Result<Self, DnsError> {
        let header = DnsHeader::from_bytes(buffer)?;
        let mut questions = Vec::with_capacity(header.qdcount as usize);
        let mut answers = Vec::with_capacity(header.ancount as usize);

        for _ in 0..header.qdcount {
            questions.push(DnsQuestion::from_bytes(buffer)?);
        }

        for _ in 0..header.ancount {
            answers.push(DnsRecord::from_bytes(buffer)?);
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

fn decode_name(buffer: &mut PacketBuffer) -> Result<String, DnsError> {
    decode_name_recursive(buffer, 0)
}

fn decode_name_recursive(buffer: &mut PacketBuffer, jumps: u8) -> Result<String, DnsError> {
    if jumps > 5 {
        return Err(DnsError::TooManyJumps);
    }

    let mut name = String::new();

    loop {
        let len = buffer.read_u8()?;
        
        // 1. Check for compression (top two bits set: 0b11000000)
        if (len & 0xC0) == 0xC0 {
            let b2 = buffer.read_u8()?;
            let offset = (((len as u16) ^ 0xC0) << 8) | (b2 as u16);
            
            // In a recursive jump, we resolve the suffix and join it
            let mut temp_buffer = PacketBuffer {
                buf: buffer.buf,
                pos: offset as usize,
            };
            
            let suffix = decode_name_recursive(&mut temp_buffer, jumps + 1)?;
            if !name.is_empty() {
                name.push('.');
            }
            name.push_str(&suffix);
            
            // Once we jump, the name is finished
            return Ok(name);
        }

        // 2. Normal label
        if len == 0 {
            break;
        }

        if !name.is_empty() {
            name.push('.');
        }

        let mut label_bytes = vec![0; len as usize];
        buffer.copy_to_slice(&mut label_bytes)?;
        name.push_str(&String::from_utf8(label_bytes)?);
    }

    Ok(name)
}

#[cfg(test)]
mod tests {
    use super::*;

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

        let bytes = buf.freeze();
        let mut packet_buffer = PacketBuffer::new(&bytes);
        let decoded_header = DnsHeader::from_bytes(&mut packet_buffer).expect("Should decode");

        assert_eq!(decoded_header.id, original_header.id);
        assert_eq!(decoded_header.qr, original_header.qr);
        assert_eq!(decoded_header.aa, original_header.aa);
        assert_eq!(decoded_header.rd, original_header.rd);
        assert_eq!(decoded_header.qdcount, original_header.qdcount);
        assert_eq!(decoded_header.ancount, original_header.ancount);
    }

    #[test]
    fn test_header_too_short() {
        let bytes = [0u8; 10];
        let mut packet_buffer = PacketBuffer::new(&bytes);
        let result = DnsHeader::from_bytes(&mut packet_buffer);
        assert!(matches!(result, Err(DnsError::TooShort)));
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

        let bytes = buf.freeze();
        let mut packet_buffer = PacketBuffer::new(&bytes);
        let decoded = DnsQuestion::from_bytes(&mut packet_buffer).unwrap();
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
            answers: vec![],
        };

        let mut buf = BytesMut::new();
        original.to_bytes(&mut buf);

        let bytes = buf.freeze();
        let mut packet_buffer = PacketBuffer::new(&bytes);
        let decoded = DnsMessage::from_bytes(&mut packet_buffer).unwrap();

        assert_eq!(decoded.header.id, 1234);
        assert_eq!(decoded.questions.len(), 2);
        assert_eq!(decoded.questions[0].name, "a.com");
        assert_eq!(decoded.questions[1].name, "b.org");
    }

    #[test]
    fn test_truncated_label() {
        // Label says length is 10, but only 3 bytes follow before null
        let data = [10, b'a', b'b', b'c', 0];
        let mut packet_buffer = PacketBuffer::new(&data);
        let result = DnsQuestion::from_bytes(&mut packet_buffer);
        assert!(matches!(result, Err(DnsError::TooShort)));
    }

    #[test]
    fn test_decompression() {
        // Packet:
        // [0..12] Header
        // [12..24] "google.com" (length 6 + google + length 3 + com + 0)
        // [24] Pointer to offset 12 (0xC0, 0x0C)
        let mut data = vec![0u8; 12]; // Dummy header
        data.extend_from_slice(&[6, b'g', b'o', b'o', b'g', b'l', b'e', 3, b'c', b'o', b'm', 0]);
        data.extend_from_slice(&[0xC0, 12]);

        let mut packet_buffer = PacketBuffer::new(&data);
        packet_buffer.pos = 24; // Seek to the pointer

        let name = decode_name(&mut packet_buffer).expect("Should decode compressed name");
        assert_eq!(name, "google.com");
    }

    #[test]
    fn test_header_into_response() {
        let mut header = DnsHeader::default();
        header.opcode = OPCODE_STANDARD_QUERY;
        
        let response = header.into_response();
        assert!(response.qr);
        assert_eq!(response.rcode, RCODE_NO_ERROR);

        header.opcode = 1; // Not a standard query
        let response = header.into_response();
        assert_eq!(response.rcode, RCODE_NOT_IMPLEMENTED);
    }

    #[test]
    fn test_record_codec() {
        let record = DnsRecord {
            name: "test.com".to_string(),
            rtype: QueryType::A,
            class: 1,
            ttl: 300,
            data: RData::A(std::net::Ipv4Addr::new(1, 2, 3, 4)),
        };

        let mut buf = BytesMut::new();
        record.to_bytes(&mut buf);

        let bytes = buf.freeze();
        let mut packet_buffer = PacketBuffer::new(&bytes);
        let decoded = DnsRecord::from_bytes(&mut packet_buffer).unwrap();

        assert_eq!(decoded.name, "test.com");
        assert_eq!(decoded.ttl, 300);
        let RData::A(addr) = decoded.data;
        assert_eq!(addr, std::net::Ipv4Addr::new(1, 2, 3, 4));
    }

    #[test]
    fn test_packet_buffer_boundary_checks() {
        let data = [1, 2, 3];
        let mut buffer = PacketBuffer::new(&data);
        
        assert!(buffer.read_u32().is_err()); // Needs 4, only has 3
        buffer.pos = 2;
        assert!(buffer.read_u16().is_err()); // Needs 2, only has 1
    }

    #[test]
    fn test_infinite_compression_loop() {
        // Offset 0: 0xC0, 0x00 (Points to itself)
        let data = [0xC0, 0x00];
        let mut buffer = PacketBuffer::new(&data);
        let result = decode_name(&mut buffer);
        
        assert!(matches!(result, Err(DnsError::TooManyJumps)));
    }

    #[test]
    fn test_nested_decompression() {
        // [0..11] "google.com"
        // [11.. ] "news." + pointer to 0
        let mut data = vec![6, b'g', b'o', b'o', b'g', b'l', b'e', 3, b'c', b'o', b'm', 0];
        data.extend_from_slice(&[4, b'n', b'e', b'w', b's', 0xC0, 0]);

        let mut buffer = PacketBuffer::new(&data);
        buffer.pos = 12; // Start at "news"

        let name = decode_name(&mut buffer).unwrap();
        assert_eq!(name, "news.google.com");
    }
}
