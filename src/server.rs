use std::net::{UdpSocket, SocketAddr};
use crate::protocol::{ByteCodec, DnsMessage, PacketBuffer, MAX_PACKET_SIZE};
use crate::resolvers::DnsResolver;
use anyhow::Result;
use bytes::BytesMut;

pub struct IrisServer {
    socket: UdpSocket,
    resolver: Box<dyn DnsResolver>,
}

impl IrisServer {
    pub fn new(addr: &str, resolver: Box<dyn DnsResolver>) -> Result<Self> {
        let socket = UdpSocket::bind(addr)?;
        Ok(Self { socket, resolver })
    }

    pub fn run(&self) -> Result<()> {
        println!("🌈 IrisDNS is listening on {}", self.socket.local_addr()?);
        
        let mut buf = [0; MAX_PACKET_SIZE];
        loop {
            match self.socket.recv_from(&mut buf) {
                Ok((size, source)) => {
                    if let Err(e) = self.handle_request(&buf[..size], source) {
                        eprintln!("Error handling request from {}: {}", source, e);
                    }
                }
                Err(e) => eprintln!("Error receiving packet: {}", e),
            }
        }
    }

    fn handle_request(&self, data: &[u8], source: SocketAddr) -> Result<()> {
        let mut packet_buffer = PacketBuffer::new(data);
        let query = match DnsMessage::from_bytes(&mut packet_buffer) {
            Ok(msg) => msg,
            Err(e) => {
                eprintln!("Failed to parse query from {}: {}", source, e);
                return Ok(());
            }
        };

        // THE BEAUTY: IrisServer doesn't know (or care) HOW it's resolved!
        let response = self.resolver.resolve(&query)?;

        let mut res_buf = BytesMut::with_capacity(MAX_PACKET_SIZE);
        response.to_bytes(&mut res_buf);
        self.socket.send_to(&res_buf, source)?;

        Ok(())
    }
}
