use std::net::UdpSocket;
use std::thread;
use std::time::Duration;
use iris::server::IrisServer;
use iris::resolvers::build_resolver;
use iris::protocol::{DnsMessage, DnsHeader, DnsQuestion, QueryType, ByteCodec, MAX_PACKET_SIZE};
use bytes::BytesMut;

#[test]
fn test_end_to_end_server_resolution() {
    // Start the IrisServer on a random port in a background thread
    let server_addr = "127.0.0.1:0"; 
    
    let resolver = build_resolver(None);
    let server = IrisServer::new(server_addr, resolver).unwrap();
    let local_addr = server.get_local_addr().unwrap();

    thread::spawn(move || {
        server.run().unwrap();
    });

    // Give the server a moment to bind
    thread::sleep(Duration::from_millis(100));

    // Build a real DNS query
    let test_domain = "integration.test";
    let test_id = 0x5555;

    let mut header = DnsHeader::default();
    header.id = test_id;
    header.qdcount = 1;

    let query = DnsMessage {
        header,
        questions: vec![DnsQuestion {
            name: test_domain.to_string(),
            qtype: QueryType::A,
            qclass: 1,
        }],
        answers: vec![],
    };

    let mut buf = BytesMut::with_capacity(MAX_PACKET_SIZE);
    query.to_bytes(&mut buf);

    // Send query to the running server via a standard UDP socket
    let client_socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    client_socket.send_to(&buf, local_addr).unwrap();

    // Receive and verify response
    let mut res_buf = [0; MAX_PACKET_SIZE];
    client_socket.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
    let (size, _) = client_socket.recv_from(&mut res_buf).unwrap();

    let mut packet_buffer = iris::protocol::PacketBuffer::new(&res_buf[..size]);
    let response = DnsMessage::from_bytes(&mut packet_buffer).unwrap();

    assert_eq!(response.header.id, test_id);
    assert_eq!(response.answers.len(), 1);
    assert_eq!(response.answers[0].name, test_domain);
}
