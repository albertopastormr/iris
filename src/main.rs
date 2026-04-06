use bytes::{BytesMut};
use std::net::UdpSocket;
use anyhow::Result;

mod protocol;
use protocol::{DnsHeader, MAX_PACKET_SIZE};

const SERVER_ADDRESS: &str = "127.0.0.1:2053";

fn main() -> Result<()> {
    println!("Starting Your DNS Server...");

    let udp_socket = UdpSocket::bind(SERVER_ADDRESS)?;
    let mut buf = [0; MAX_PACKET_SIZE];
    
    loop {
        match udp_socket.recv_from(&mut buf) {
            Ok((size, source)) => {
                println!("Received {} bytes from {}", size, source);
                
                // 1. Decode the query header
                let mut query_buf = &buf[..size];
                let query_header = match DnsHeader::from_bytes(&mut query_buf) {
                    Ok(h) => h,
                    Err(e) => {
                        eprintln!("Failed to parse DNS header: {}", e);
                        continue;
                    }
                };

                // 2. Prepare the response header
                let response_header = DnsHeader {
                    id: query_header.id,
                    qr: true, // It's a response
                    opcode: query_header.opcode,
                    aa: false,
                    tc: false,
                    rd: query_header.rd, // Inherit RD from query
                    ra: false,
                    z: 0,
                    rcode: 0, // No error
                    qdcount: 0,
                    ancount: 0,
                    nscount: 0,
                    arcount: 0,
                };

                // 3. Serialize and send back
                let mut response_buf = BytesMut::with_capacity(protocol::HEADER_SIZE);
                response_header.to_bytes(&mut response_buf);

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
