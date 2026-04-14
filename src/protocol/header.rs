use bytes::BufMut;
use crate::protocol::{ByteCodec, DnsError, PacketBuffer, OPCODE_STANDARD_QUERY, RCODE_NO_ERROR, RCODE_NOT_IMPLEMENTED};

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

    fn to_bytes(&self, buf: &mut bytes::BytesMut) {
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

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::BytesMut;
    use crate::protocol::HEADER_SIZE;

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
    fn test_header_flag_masking() {
        let mut header = DnsHeader::default();
        header.opcode = 0b11111; // 5 bits, should be masked to 0b1111 (15)
        header.z = 0b1111;      // 4 bits, should be masked to 0b111 (7)
        
        let mut buf = BytesMut::new();
        header.to_bytes(&mut buf);
        
        let mut read_buffer = PacketBuffer::new(&buf);
        let decoded = DnsHeader::from_bytes(&mut read_buffer).unwrap();
        
        assert_eq!(decoded.opcode, 15);
        assert_eq!(decoded.z, 7);
    }
}
