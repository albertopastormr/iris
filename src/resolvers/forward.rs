use std::net::{UdpSocket, SocketAddr};
use crate::protocol::{ByteCodec, DnsMessage, PacketBuffer, MAX_PACKET_SIZE, DnsHeader};
use crate::resolvers::DnsResolver;
use anyhow::Result;

pub struct ForwardResolver {
    resolver_addr: SocketAddr,
}

impl ForwardResolver {
    pub fn new(resolver_addr: SocketAddr) -> Self {
        Self { resolver_addr }
    }
}

impl DnsResolver for ForwardResolver {
    fn resolve(&self, query: &DnsMessage) -> Result<DnsMessage> {
        let mut response_answers = Vec::with_capacity(query.questions.len());

        for question in &query.questions {
            let upstream_query = DnsMessage {
                header: DnsHeader {
                    id: query.header.id,
                    qdcount: 1,
                    rd: true, // Crucial: Ask the upstream to perform recursion
                    ..Default::default()
                },
                questions: vec![question.clone()],
                answers: Vec::new(),
            };

            let mut upstream_buf = bytes::BytesMut::with_capacity(MAX_PACKET_SIZE);
            upstream_query.to_bytes(&mut upstream_buf);

            let temp_socket = UdpSocket::bind(crate::protocol::ANY_PORT_ADDR)?;
            temp_socket.send_to(&upstream_buf, self.resolver_addr)?;

            let mut answer_buf = [0; MAX_PACKET_SIZE];
            let (size, _) = temp_socket.recv_from(&mut answer_buf)?;
            
            let mut packet_buffer = PacketBuffer::new(&answer_buf[..size]);
            let upstream_response = DnsMessage::from_bytes(&mut packet_buffer)?;

            response_answers.extend(upstream_response.answers);
        }

        Ok(DnsMessage {
            header: {
                let mut h = query.header.into_response();
                h.ancount = response_answers.len() as u16;
                h
            },
            questions: query.questions.clone(),
            answers: response_answers,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{DnsHeader, DnsQuestion, DnsRecord, RData};
    use std::thread;

    #[test]
    fn test_forward_resolver_with_mock_upstream() {
        // 1. Setup a Mock Upstream Server on a random port on 127.0.0.1
        let mock_socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let mock_addr = mock_socket.local_addr().unwrap();

        // 2. Spawn a thread to act as the "Google" resolver
        thread::spawn(move || {
            let mut buf = [0; 512];
            // Listen for 1 encoded question
            if let Ok((size, src)) = mock_socket.recv_from(&mut buf) {
                let mut buffer = PacketBuffer::new(&buf[..size]);
                let query = DnsMessage::from_bytes(&mut buffer).unwrap();
                
                // Build a fake answer for whatever was asked
                let mut response = query.clone();
                response.header.qr = true;
                response.header.ancount = 1;
                response.answers.push(DnsRecord {
                    name: query.questions[0].name.clone(),
                    rtype: crate::protocol::QTYPE_A,
                    class: 1,
                    ttl: 60,
                    data: RData::A(std::net::Ipv4Addr::new(1, 2, 3, 4)),
                });

                let mut res_buf = bytes::BytesMut::with_capacity(512);
                response.to_bytes(&mut res_buf);
                mock_socket.send_to(&res_buf, src).unwrap();
            }
        });

        // 3. Test our forwarder against this local mock
        let resolver = ForwardResolver::new(mock_addr);
        let query = DnsMessage {
            header: DnsHeader { id: 0x1234, qdcount: 1, ..Default::default() },
            questions: vec![DnsQuestion { name: "test.com".to_string(), qtype: crate::protocol::QTYPE_A, qclass: 1 }],
            answers: vec![],
        };

        let result = resolver.resolve(&query).unwrap();
        
        // 4. Verify the merge happened correctly
        assert_eq!(result.header.id, 0x1234);
        assert_eq!(result.answers.len(), 1);
        if let RData::A(ip) = result.answers[0].data {
            assert_eq!(ip, std::net::Ipv4Addr::new(1, 2, 3, 4));
        } else {
            panic!("Expected RData::A");
        }
    }
}
