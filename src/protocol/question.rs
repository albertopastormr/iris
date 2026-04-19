use bytes::BufMut;
use crate::protocol::{ByteCodec, DnsError, PacketBuffer};
use crate::protocol::names::{decode_name, encode_name};

#[derive(Debug, Clone)]
pub struct DnsQuestion {
    pub name: String,
    pub qtype: u16,
    pub qclass: u16,
}

impl ByteCodec for DnsQuestion {
    fn from_bytes(buffer: &mut PacketBuffer) -> Result<Self, DnsError> {
        let name = decode_name(buffer)?;
        let qtype = buffer.read_u16()?;
        let qclass = buffer.read_u16()?;

        Ok(DnsQuestion {
            name,
            qtype,
            qclass,
        })
    }

    fn to_bytes(&self, buf: &mut bytes::BytesMut) {
        encode_name(&self.name, buf);
        buf.put_u16(self.qtype);
        buf.put_u16(self.qclass);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::BytesMut;

    #[test]
    fn test_question_codec() {
        let original = DnsQuestion {
            name: "google.com".to_string(),
            qtype: crate::protocol::QTYPE_A,
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
        assert_eq!(decoded.qtype, crate::protocol::QTYPE_A);
        assert_eq!(decoded.qclass, 1);
    }
}
