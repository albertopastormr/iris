use crate::protocol::{DnsMessage, DnsRecord, RData, QueryType};
use std::net::Ipv4Addr;

pub fn handle_locally(query: &DnsMessage) -> DnsMessage {
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

    DnsMessage {
        header,
        questions: query.questions.clone(),
        answers,
    }
}
