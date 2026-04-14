use anyhow::Result;
use bytes::BytesMut;
use std::net::{UdpSocket, SocketAddr};

mod protocol;
use protocol::{ByteCodec, DnsMessage, PacketBuffer, MAX_PACKET_SIZE};

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let resolver_addr: Option<SocketAddr> = if let Some(pos) = args.iter().position(|r| r == "--resolver") {
        args.get(pos + 1).map(|addr| addr.parse().expect("Invalid resolver address"))
    } else {
        None
    };

    let udp_socket = UdpSocket::bind("127.0.0.1:2053")?;
    let mut buf = [0; MAX_PACKET_SIZE];

    loop {
        match udp_socket.recv_from(&mut buf) {
            Ok((size, source)) => {
                println!("Received {} bytes from {}", size, source);
                
                // 1. Decode the query message
                let mut packet_buffer = PacketBuffer::new(&buf[..size]);
                let query_message = match DnsMessage::from_bytes(&mut packet_buffer) {
                    Ok(msg) => msg,
                    Err(e) => {
                        eprintln!("Failed to parse DNS message: {}", e);
                        continue;
                    }
                };

                // 2. Prepare the response message
                let mut response_message = DnsMessage {
                    header: query_message.header.into_response(),
                    questions: query_message.questions.clone(),
                    answers: Vec::new(),
                };

                // Forwarding
                if let Some(upstream_addr) = resolver_addr {
                    for question in &query_message.questions {
                        // 1. Create a single-question query for the upstream
                        let mut upstream_query = query_message.clone();
                        upstream_query.header.qdcount = 1;
                        upstream_query.header.ancount = 0;
                        upstream_query.header.qr = false;
                        upstream_query.questions = vec![question.clone()];
                        upstream_query.answers = vec![];

                        let mut upstream_buf = BytesMut::with_capacity(MAX_PACKET_SIZE);
                        upstream_query.to_bytes(&mut upstream_buf);

                        // 2. Send to resolver using a temporary socket (to avoid port clashing)
                        let temp_socket = UdpSocket::bind("0.0.0.0:0")?;
                        temp_socket.send_to(&upstream_buf, upstream_addr)?;

                        // 3. Receive answer
                        let mut answer_buf = [0; MAX_PACKET_SIZE];
                        let (size, _) = temp_socket.recv_from(&mut answer_buf)?;
                        
                        let mut packet_buffer = PacketBuffer::new(&answer_buf[..size]);
                        let upstream_response = DnsMessage::from_bytes(&mut packet_buffer)?;

                        // 4. Collect answers
                        response_message.answers.extend(upstream_response.answers);
                    }
                } else {
                    // FALLBACK: If no resolver, just respond with placeholder
                    response_message.answers = query_message
                        .questions
                        .iter()
                        .map(|q| protocol::DnsRecord {
                            name: q.name.clone(),
                            rtype: q.qtype,
                            class: q.qclass,
                            ttl: 60,
                            data: protocol::RData::A(std::net::Ipv4Addr::new(8, 8, 8, 8)),
                        })
                        .collect();
                }

                response_message.header.ancount = response_message.answers.len() as u16;

                // 3. Serialize and send back
                let mut response_buf = BytesMut::with_capacity(MAX_PACKET_SIZE);
                response_message.to_bytes(&mut response_buf);

                udp_socket.send_to(&response_buf, source)?;
            }
            Err(e) => {
                eprintln!("Error receiving data: {}", e);
                break;
            }
        }
    }

    Ok(())
}
