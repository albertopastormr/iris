use bytes::{Buf, BufMut, BytesMut};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum DnsError {
    #[error("DNS message is too short: expected at least {expected} bytes, but got {actual}")]
    TooShort { expected: usize, actual: usize },
    #[error("Malformed DNS header")]
    MalformedHeader,
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

#[derive(Debug, Clone, Copy, Default)]
pub struct DnsHeader {
    pub id: u16,
    pub qr: bool,          // Query/Response (0 for query, 1 for response)
    pub opcode: u8,        // 4 bits
    pub aa: bool,          // Authoritative Answer
    pub tc: bool,          // Truncation
    pub rd: bool,          // Recursion Desired
    pub ra: bool,          // Recursion Available
    pub z: u8,             // Reserved (3 bits)
    pub rcode: u8,         // Response Code (4 bits)
    pub qdcount: u16,
    pub ancount: u16,
    pub nscount: u16,
    pub arcount: u16,
}

impl DnsHeader {
    pub fn from_bytes(buf: &mut impl Buf) -> Result<Self, DnsError> {
        if buf.remaining() < HEADER_SIZE {
            return Err(DnsError::TooShort { expected: HEADER_SIZE, actual: buf.remaining() });
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

    pub fn to_bytes(&self, buf: &mut BytesMut) {
        buf.put_u16(self.id);
        
        let mut flags: u16 = 0;
        if self.qr { flags |= 1 << QR_SHIFT; }
        flags |= (self.opcode as u16 & 0b1111) << OPCODE_SHIFT;
        if self.aa { flags |= 1 << AA_SHIFT; }
        if self.tc { flags |= 1 << TC_SHIFT; }
        if self.rd { flags |= 1 << RD_SHIFT; }
        if self.ra { flags |= 1 << RA_SHIFT; }
        flags |= (self.z as u16 & 0b111) << Z_SHIFT;
        flags |= self.rcode as u16 & 0b1111;
        
        buf.put_u16(flags);
        buf.put_u16(self.qdcount);
        buf.put_u16(self.ancount);
        buf.put_u16(self.nscount);
        buf.put_u16(self.arcount);
    }
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
}
