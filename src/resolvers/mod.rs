use crate::protocol::DnsMessage;
use anyhow::Result;
use std::net::SocketAddr;

pub mod forward;
pub mod local;
pub mod combined;

pub trait DnsResolver: Send + Sync {
    fn resolve(&self, query: &DnsMessage) -> Result<DnsMessage>;
}

/// A factory function that builds the standard IrisDNS resolver chain
pub fn build_resolver(upstream_addr: Option<SocketAddr>) -> Box<dyn DnsResolver> {
    let forwarder = upstream_addr.map(forward::ForwardResolver::new);
    Box::new(combined::CombinedResolver::new(forwarder))
}
