use std::net::SocketAddr;
use iris::server::IrisServer;
use iris::resolvers::build_resolver;
use anyhow::Result;

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let resolver_addr: Option<SocketAddr> = if let Some(pos) = args.iter().position(|r| r == "--resolver") {
        args.get(pos + 1).map(|addr| addr.parse().expect("Invalid resolver address"))
    } else {
        None
    };

    let resolver = build_resolver(resolver_addr);

    let server = IrisServer::new(iris::protocol::DEFAULT_SERVER_ADDR, resolver)?;
    server.run()?;

    Ok(())
}
