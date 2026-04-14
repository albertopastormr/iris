use bytes::BytesMut;
use thiserror::Error;

pub mod buffer;
pub mod header;
pub mod message;
pub mod names;
pub mod question;
pub mod record;

pub use buffer::PacketBuffer;
pub use header::DnsHeader;
pub use message::DnsMessage;
pub use question::DnsQuestion;
pub use record::{DnsRecord, RData};

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

pub trait ByteCodec: Sized {
    fn from_bytes(buffer: &mut PacketBuffer) -> Result<Self, DnsError>;
    fn to_bytes(&self, buf: &mut BytesMut);
}

#[allow(dead_code)]
pub const HEADER_SIZE: usize = 12;
pub const MAX_PACKET_SIZE: usize = 512;
pub const MAX_JUMPS: u8 = 5;
pub const COMPRESSION_MASK: u8 = 0xC0;

// Data Sizes
pub const U16_SIZE: usize = 2;
pub const U32_SIZE: usize = 4;
pub const IPV4_SIZE: u16 = 4;

// DNS Opcodes
pub const OPCODE_STANDARD_QUERY: u8 = 0;

// DNS Response Codes
pub const RCODE_NO_ERROR: u8 = 0;
pub const RCODE_NOT_IMPLEMENTED: u8 = 4;

// Query Types
pub const QTYPE_A: u16 = 1;
pub const QTYPE_CNAME: u16 = 5;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueryType {
    A = QTYPE_A as isize,
    CNAME = QTYPE_CNAME as isize,
}

impl TryFrom<u16> for QueryType {
    type Error = DnsError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            QTYPE_A => Ok(QueryType::A),
            QTYPE_CNAME => Ok(QueryType::CNAME),
            _ => Err(DnsError::InvalidQueryType(value)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_query_type_try_from() {
        assert_eq!(QueryType::try_from(QTYPE_A).unwrap(), QueryType::A);
        assert_eq!(QueryType::try_from(QTYPE_CNAME).unwrap(), QueryType::CNAME);
        assert!(QueryType::try_from(99).is_err());
    }
}
