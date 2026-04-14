use anyhow::Result;
use bytes::BytesMut;
use std::net::UdpSocket;

mod protocol;
use protocol::{ByteCodec, DnsMessage, DnsRecord, PacketBuffer, QueryType, RData, MAX_PACKET_SIZE};
use std::net::Ipv4Addr;

const SERVER_ADDRESS: &str = "127.0.0.1:2053";

fn main() -> Result<()> {
    println!("Starting Your DNS Server...");

    let udp_socket = UdpSocket::bind(SERVER_ADDRESS)?;
    let mut buf = [0; MAX_PACKET_SIZE];

    loop {
        match udp_socket.recv_from(&mut buf) {
            Ok((size, source)) => {
                println!("Received {} bytes from {}", size, source);
                
                // 1. Decode the query message
                let mut packet_buffer = PacketBuffer::new(&buf[..size]);
                let query_msg = match DnsMessage::from_bytes(&mut packet_buffer) {
                    Ok(msg) => msg,
                    Err(e) => {
                        eprintln!("Failed to parse DNS message: {}", e);
                        continue;
                    }
                };

                // 2. Prepare the response message
                let mut response_header = query_msg.header.into_response();
                
                let answers: Vec<DnsRecord> = query_msg.questions.iter().map(|q| {
                    DnsRecord {
                        name: q.name.clone(),
                        rtype: QueryType::A,
                        class: 1,
                        ttl: 60,
                        data: RData::A(Ipv4Addr::new(8, 8, 8, 8)),
                    }
                }).collect();

                response_header.ancount = answers.len() as u16;

                let response_msg = DnsMessage {
                    header: response_header,
                    questions: query_msg.questions,
                    answers,
                };

                // 3. Serialize and send back
                let mut response_buf = BytesMut::new();
                response_msg.to_bytes(&mut response_buf);

                udp_socket
                    .send_to(&response_buf, source)
                    .map_err(|e| {
                        eprintln!("Failed to send response: {}", e);
                        e
                    })
                    .ok();
            }
            Err(e) => {
                eprintln!("Error receiving data: {}", e);
                break;
            }
        }
    }

    Ok(())
}
