use crate::protocol::DnsMessage;
use crate::resolvers::DnsResolver;
use crate::resolvers::forward::ForwardResolver;
use crate::resolvers::local::LocalResolver;
use anyhow::Result;

pub struct CombinedResolver {
    local: LocalResolver,
    forwarder: Option<ForwardResolver>,
}

impl CombinedResolver {
    pub fn new(forwarder: Option<ForwardResolver>) -> Self {
        Self {
            local: LocalResolver,
            forwarder,
        }
    }
}

impl DnsResolver for CombinedResolver {
    fn resolve(&self, query: &DnsMessage) -> Result<DnsMessage> {
        if let Some(forwarder) = &self.forwarder {
            forwarder.resolve(query)
        } else {
            self.local.resolve(query)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{DnsHeader, DnsQuestion};

    #[test]
    fn test_combined_resolver_delegation() {
        // Test case 1: No forwarder -> should use local
        let combined = CombinedResolver::new(None);
        let query = DnsMessage {
            header: DnsHeader { id: 1, qdcount: 1, ..Default::default() },
            questions: vec![DnsQuestion { name: "a.com".to_string(), qtype: crate::protocol::QTYPE_A, qclass: 1 }],
            answers: vec![],
        };

        let response = combined.resolve(&query).unwrap();
        // Since it's local, we know it will return 8.8.8.8
        if let crate::protocol::RData::A(addr) = response.answers[0].data {
            assert_eq!(addr, std::net::Ipv4Addr::new(8, 8, 8, 8));
        } else {
            panic!("Expected RData::A");
        }
    }
}
