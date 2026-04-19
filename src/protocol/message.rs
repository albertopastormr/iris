use crate::protocol::{ByteCodec, DnsError, DnsHeader, DnsQuestion, DnsRecord, PacketBuffer};

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

    fn to_bytes(&self, buf: &mut bytes::BytesMut) {
        self.header.to_bytes(buf);
        for question in &self.questions {
            question.to_bytes(buf);
        }
        for answer in &self.answers {
            answer.to_bytes(buf);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::BytesMut;

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
            qtype: crate::protocol::QTYPE_A,
            qclass: 1,
        };

        let q2 = DnsQuestion {
            name: "b.org".to_string(),
            qtype: crate::protocol::QTYPE_CNAME,
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
}
