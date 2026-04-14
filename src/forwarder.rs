use std::net::{UdpSocket, SocketAddr};
use crate::protocol::{ByteCodec, DnsMessage, PacketBuffer, MAX_PACKET_SIZE};
use anyhow::Result;

pub struct Forwarder {
    resolver_addr: SocketAddr,
}

impl Forwarder {
    pub fn new(resolver_addr: SocketAddr) -> Self {
        Self { resolver_addr }
    }

    pub fn forward(&self, query: &DnsMessage) -> Result<DnsMessage> {
        let mut response_answers = Vec::new();

        for question in &query.questions {
            // 1. Create a single-question query for the upstream
            let mut upstream_query = query.clone();
            upstream_query.header.qdcount = 1;
            upstream_query.header.ancount = 0;
            upstream_query.header.qr = false;
            upstream_query.questions = vec![question.clone()];
            upstream_query.answers = vec![];

            let mut upstream_buf = bytes::BytesMut::with_capacity(MAX_PACKET_SIZE);
            upstream_query.to_bytes(&mut upstream_buf);

            // 2. Send to resolver using a temporary socket (to avoid port clashing)
            let temp_socket = UdpSocket::bind("0.0.0.0:0")?;
            temp_socket.send_to(&upstream_buf, self.resolver_addr)?;

            // 3. Receive answer
            let mut answer_buf = [0; MAX_PACKET_SIZE];
            let (size, _) = temp_socket.recv_from(&mut answer_buf)?;
            
            let mut packet_buffer = PacketBuffer::new(&answer_buf[..size]);
            let upstream_response = DnsMessage::from_bytes(&mut packet_buffer)?;

            // 4. Collect answers
            response_answers.extend(upstream_response.answers);
        }

        let mut final_response = query.clone();
        final_response.header = query.header.into_response();
        final_response.answers = response_answers;
        final_response.header.ancount = final_response.answers.len() as u16;

        Ok(final_response)
    }
}
