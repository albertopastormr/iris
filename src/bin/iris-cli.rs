use std::net::UdpSocket;
use std::env;
use iris::protocol::{ByteCodec, DnsMessage, DnsHeader, DnsQuestion, PacketBuffer, MAX_PACKET_SIZE, DEFAULT_SERVER_ADDR};
use bytes::BytesMut;

fn main() {
    let args: Vec<String> = env::args().collect();
    
    // Parse server address
    let mut server_addr = DEFAULT_SERVER_ADDR.to_string();
    if let Some(pos) = args.iter().position(|r| r == "-s" || r == "--server") {
        if let Some(val) = args.get(pos + 1) {
            server_addr = val.clone();
        }
    }

    // Parse domain (last non-flag argument)
    let domain = args.last().filter(|s| !s.starts_with('-'));

    if domain.is_none() || args.len() < 2 {
        println!("🌈 IrisDNS CLI");
        println!("Usage: iris-cli [-s <server>] <domain>");
        println!("Default server: {}", DEFAULT_SERVER_ADDR);
        return;
    }

    let domain = domain.unwrap();
    
    // 1. Build Query
    let mut header = DnsHeader::default();
    header.id = 0xAAAA;
    header.qdcount = 1;
    header.rd = true;

    let question = DnsQuestion {
        name: domain.to_string(),
        qtype: iris::protocol::QTYPE_A,
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
    socket.send_to(&buf, &server_addr).expect("Failed to send query");

    println!("🔍 Querying {} for {}...", server_addr, domain);

    // 3. Receive Response
    let mut res_buf = [0; MAX_PACKET_SIZE];
    match socket.recv_from(&mut res_buf) {
        Ok((size, _)) => {
            let mut packet_buffer = PacketBuffer::new(&res_buf[..size]);
            let response = DnsMessage::from_bytes(&mut packet_buffer).expect("Failed to parse response");

            println!("✅ Received Response (ID: 0x{:X})", response.header.id);
            println!("   Status: {}", iris::protocol::rcode_to_str(response.header.rcode));
            
            if response.answers.is_empty() {
                println!("   (No records found in answer section)");
            } else {
                for answer in response.answers {
                    println!("   -> {} [{}] TTL: {} DATA: {:?}", 
                        answer.name, 
                        iris::protocol::qtype_to_str(answer.rtype), 
                        answer.ttl, 
                        answer.data
                    );
                }
            }
        }
        Err(_) => println!("❌ No response received from server."),
    }
}
