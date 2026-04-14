use bytes::BufMut;
use crate::protocol::{ByteCodec, DnsError, PacketBuffer, QueryType, IPV4_SIZE};
use crate::protocol::names::{decode_name, encode_name};

#[derive(Debug, Clone)]
pub enum RData {
    A(std::net::Ipv4Addr),
}

impl RData {
    pub fn from_bytes(buffer: &mut PacketBuffer, rtype: QueryType, rdlength: u16) -> Result<Self, DnsError> {
        match rtype {
            QueryType::A => {
                if rdlength != IPV4_SIZE {
                    return Err(DnsError::MalformedHeader);
                }
                let mut octets = [0u8; 4];
                buffer.copy_to_slice(&mut octets)?;
                Ok(RData::A(std::net::Ipv4Addr::from(octets)))
            }
            _ => Err(DnsError::InvalidQueryType(rtype as u16)),
        }
    }

    pub fn to_bytes(&self, buf: &mut bytes::BytesMut) {
        match self {
            RData::A(addr) => buf.put_slice(&addr.octets()),
        }
    }

    pub fn len(&self) -> u16 {
        match self {
            RData::A(_) => IPV4_SIZE,
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

    fn to_bytes(&self, buf: &mut bytes::BytesMut) {
        encode_name(&self.name, buf);
        buf.put_u16(self.rtype as u16);
        buf.put_u16(self.class);
        buf.put_u32(self.ttl);
        buf.put_u16(self.data.len());
        self.data.to_bytes(buf);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::BytesMut;

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
    fn test_record_malformed_a_length() {
        // A record says length is 3, but should be 4
        let mut data = vec![4, b't', b'e', b's', b't', 0]; // name
        data.extend_from_slice(&[0, 1]); // type A
        data.extend_from_slice(&[0, 1]); // class IN
        data.extend_from_slice(&[0, 0, 0, 60]); // ttl
        data.extend_from_slice(&[0, 3]); // rdlength 3 (WRONG!)
        data.extend_from_slice(&[1, 2, 3]);

        let mut packet_buffer = PacketBuffer::new(&data);
        let result = DnsRecord::from_bytes(&mut packet_buffer);
        assert!(matches!(result, Err(DnsError::MalformedHeader)));
    }
}
