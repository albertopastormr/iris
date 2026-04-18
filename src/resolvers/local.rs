use crate::protocol::{DnsMessage, DnsRecord, RData, QueryType};
use crate::resolvers::DnsResolver;
use anyhow::Result;
use std::net::Ipv4Addr;

pub struct LocalResolver;

impl DnsResolver for LocalResolver {
    fn resolve(&self, query: &DnsMessage) -> Result<DnsMessage> {
        let answers: Vec<DnsRecord> = query
            .questions
            .iter()
            .map(|q| DnsRecord {
                name: q.name.clone(),
                rtype: QueryType::A,
                class: 1,
                ttl: 60,
                data: RData::A(Ipv4Addr::new(8, 8, 8, 8)),
            })
            .collect();

        let mut header = query.header.into_response();
        header.ancount = answers.len() as u16;

        Ok(DnsMessage {
            header,
            questions: query.questions.clone(),
            answers,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{DnsHeader, DnsQuestion, QueryType};

    #[test]
    fn test_local_resolver_identity_matching() {
        let resolver = LocalResolver;
        let mut header = DnsHeader::default();
        header.id = 0xABCD;
        header.qdcount = 1;

        let query = DnsMessage {
            header,
            questions: vec![DnsQuestion {
                name: "test.com".to_string(),
                qtype: QueryType::A,
                qclass: 1,
            }],
            answers: vec![],
        };

        let response = resolver.resolve(&query).unwrap();

        // Check ID matching
        assert_eq!(response.header.id, 0xABCD);
        // Check name matching in answer
        assert_eq!(response.answers[0].name, "test.com");
        // Check QR flag is set
        assert!(response.header.qr);
    }
}
