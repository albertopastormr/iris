use anyhow::Result;
use bytes::BytesMut;
use std::net::UdpSocket;

mod protocol;
use protocol::{ByteCodec, DnsMessage, DnsRecord, QueryType, RData, MAX_PACKET_SIZE};
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
                let mut query_bytes = &buf[..size];
                let query_msg = match DnsMessage::from_bytes(&mut query_bytes) {
                    Ok(msg) => msg,
                    Err(e) => {
                        eprintln!("Failed to parse DNS message: {}", e);
                        continue;
                    }
                };

                // 2. Prepare the response message
                let mut response_header = query_msg.header;
                response_header.id = 1234; // Constant for this stage
                response_header.qr = true; // Mark as response
                response_header.ancount = 1;

                let answer = DnsRecord {
                    name: "codecrafters.io".to_string(),
                    rtype: QueryType::A,
                    class: 1,
                    ttl: 60,
                    data: RData::A(Ipv4Addr::new(8, 8, 8, 8)),
                };

                let response_msg = DnsMessage {
                    header: response_header,
                    questions: query_msg.questions,
                    answers: vec![answer],
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
