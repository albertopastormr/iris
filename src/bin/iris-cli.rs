use std::net::UdpSocket;
use std::env;
use iris::protocol::{ByteCodec, DnsMessage, DnsHeader, DnsQuestion, PacketBuffer, QueryType, MAX_PACKET_SIZE};
use bytes::BytesMut;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        println!("Usage: iris-cli <domain>");
        return;
    }

    let domain = &args[1];
    let server_addr = "127.0.0.1:2053";
    
    // 1. Build Query
    let mut header = DnsHeader::default();
    header.id = 0xAAAA;
    header.qdcount = 1;
    header.rd = true;

    let question = DnsQuestion {
        name: domain.to_string(),
        qtype: QueryType::A,
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

    println!("🔍 Querying IrisDNS for {}...", domain);

    // 3. Receive Response
    let mut res_buf = [0; MAX_PACKET_SIZE];
    let (size, _) = socket.recv_from(&mut res_buf).expect("No response received");

    let mut packet_buffer = PacketBuffer::new(&res_buf[..size]);
    let response = DnsMessage::from_bytes(&mut packet_buffer).expect("Failed to parse response");

    println!("✅ Received Response (ID: 0x{:X})", response.header.id);
    for answer in response.answers {
        println!("   -> {} [{:?}] TTL: {} DATA: {:?}", answer.name, answer.rtype, answer.ttl, answer.data);
    }
}
