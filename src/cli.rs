use std::net::UdpSocket;
use crate::protocol::{ByteCodec, DnsMessage, DnsHeader, DnsQuestion, PacketBuffer, MAX_PACKET_SIZE};
use bytes::BytesMut;

pub fn run_query(server_addr: &str, domain: &str) {
    // 1. Build Query
    let mut header = DnsHeader::default();
    header.id = 0xAAAA;
    header.qdcount = 1;
    header.rd = true;

    let question = DnsQuestion {
        name: domain.to_string(),
        qtype: crate::protocol::QTYPE_A,
        qclass: 1,
    };

    let query = DnsMessage {
        header,
        questions: vec![question],
        answers: vec![],
    };

    let mut buf = BytesMut::with_capacity(MAX_PACKET_SIZE);
    query.to_bytes(&mut buf);

    // 2. Send to server
    let socket = UdpSocket::bind("0.0.0.0:0").expect("Couldn't bind local socket");
    socket.send_to(&buf, server_addr).expect("Failed to send query");

    println!("🔍 Querying {} for {}...", server_addr, domain);

    // 3. Receive Response
    let mut res_buf = [0; MAX_PACKET_SIZE];
    match socket.recv_from(&mut res_buf) {
        Ok((size, _)) => {
            let mut packet_buffer = PacketBuffer::new(&res_buf[..size]);
            let response = DnsMessage::from_bytes(&mut packet_buffer).expect("Failed to parse response");

            println!("✅ Received Response (ID: 0x{:X})", response.header.id);
            println!("   Status: {}", crate::protocol::rcode_to_str(response.header.rcode));
            
            if response.answers.is_empty() {
                println!("   (No records found in answer section)");
            } else {
                for answer in response.answers {
                    println!("   -> {} [{}] TTL: {} DATA: {:?}", 
                        answer.name, 
                        crate::protocol::qtype_to_str(answer.rtype), 
                        answer.ttl, 
                        answer.data
                    );
                }
            }
        }
        Err(_) => println!("❌ No response received from server."),
    }
}
