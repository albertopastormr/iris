use std::net::{UdpSocket, SocketAddr};
use crate::protocol::{ByteCodec, DnsMessage, PacketBuffer, MAX_PACKET_SIZE, DnsHeader};
use anyhow::Result;

pub struct Forwarder {
    resolver_addr: SocketAddr,
}

impl Forwarder {
    pub fn new(resolver_addr: SocketAddr) -> Self {
        Self { resolver_addr }
    }

    pub fn forward(&self, query: &DnsMessage) -> Result<DnsMessage> {
        let mut response_answers = Vec::with_capacity(query.questions.len());

        for question in &query.questions {
            // We only need to mimic the ID from the original query.
            let upstream_query = DnsMessage {
                header: DnsHeader {
                    id: query.header.id,
                    qdcount: 1,
                    ..Default::default()
                },
                questions: vec![question.clone()],
                answers: Vec::new(),
            };

            let mut upstream_buf = bytes::BytesMut::with_capacity(MAX_PACKET_SIZE);
            upstream_query.to_bytes(&mut upstream_buf);

            // Dedicated socket for this specific upstream request.
            // Using "0" port lets the OS assign a random high-range port.
            let temp_socket = UdpSocket::bind(crate::protocol::ANY_PORT_ADDR)?;
            temp_socket.send_to(&upstream_buf, self.resolver_addr)?;

            // Receive answer
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
