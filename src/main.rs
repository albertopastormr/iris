use std::net::SocketAddr;
use iris::server::IrisServer;
use anyhow::Result;

fn main() -> Result<()> {
    // Parse arguments: ./your_server --resolver <ip:port>
    let args: Vec<String> = std::env::args().collect();
    let resolver_addr: Option<SocketAddr> = if let Some(pos) = args.iter().position(|r| r == "--resolver") {
        args.get(pos + 1).map(|addr| addr.parse().expect("Invalid resolver address"))
    } else {
        None
    };

    let server_addr = iris::protocol::DEFAULT_SERVER_ADDR;
    let server = IrisServer::new(server_addr, resolver_addr)?;
    server.run()?;

    Ok(())
}
