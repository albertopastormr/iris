use std::net::{UdpSocket, SocketAddr};
use crate::protocol::{ByteCodec, DnsMessage, PacketBuffer, MAX_PACKET_SIZE};
use crate::forwarder::Forwarder;
use crate::handler;
use anyhow::Result;
use bytes::BytesMut;

pub struct IrisServer {
    socket: UdpSocket,
    forwarder: Option<Forwarder>,
}

impl IrisServer {
    pub fn new(addr: &str, resolver: Option<SocketAddr>) -> Result<Self> {
        let socket = UdpSocket::bind(addr)?;
        let forwarder = resolver.map(Forwarder::new);
        Ok(Self { socket, forwarder })
    }

    pub fn run(&self) -> Result<()> {
        println!("🌈 IrisDNS is listening on {}", self.socket.local_addr()?);
        if let Some(_) = &self.forwarder {
            println!("🔄 Forwarding mode enabled.");
        }

        let mut buf = [0; MAX_PACKET_SIZE];
        loop {
            match self.socket.recv_from(&mut buf) {
                Ok((size, source)) => {
                    self.handle_request(&buf[..size], source)?;
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

        let response = if let Some(forwarder) = &self.forwarder {
            forwarder.forward(&query)?
        } else {
            handler::handle_locally(&query)
        };

        let mut res_buf = BytesMut::with_capacity(MAX_PACKET_SIZE);
        response.to_bytes(&mut res_buf);
        self.socket.send_to(&res_buf, source)?;

        Ok(())
    }
}
