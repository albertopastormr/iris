use std::net::{SocketAddr, IpAddr};
use iris::server::IrisServer;
use iris::resolvers::build_resolver;
use iris::cli::run_query;
use iris::protocol::DEFAULT_SERVER_ADDR;
use anyhow::Result;
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "iris")]
#[command(about = "🌈 A high-performance DNS recursive forwarder", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the IrisDNS server
    Start {
        /// Optional upstream resolver (e.g. 8.8.8.8)
        #[arg(short, long)]
        resolver: Option<String>,
    },
    /// Query a DNS server
    Query {
        /// Domain to lookup
        domain: String,
        /// Server to query
        #[arg(short, long, default_value_t = DEFAULT_SERVER_ADDR.to_string())]
        server: String,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Start { resolver } => {
            let resolver_addr: Option<SocketAddr> = resolver.map(|addr| {
                addr.parse::<SocketAddr>().unwrap_or_else(|_| {
                    let ip = addr.parse::<IpAddr>().expect("Invalid resolver address (must be IP or IP:PORT)");
                    SocketAddr::new(ip, 53)
                })
            });

            let resolver = build_resolver(resolver_addr);
            let server = IrisServer::new(DEFAULT_SERVER_ADDR, resolver)?;
            server.run()?;
        }
        Commands::Query { domain, server } => {
            run_query(&server, &domain);
        }
    }

    Ok(())
}
