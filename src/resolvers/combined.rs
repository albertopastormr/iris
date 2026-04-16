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
        // In a real DNS, we would check local first, then forward.
        // For now, we still pick a strategy
        if let Some(forwarder) = &self.forwarder {
            forwarder.resolve(query)
        } else {
            self.local.resolve(query)
        }
    }
}
