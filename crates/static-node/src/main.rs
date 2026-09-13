//! static-node - The main Static network node binary
//!
//! Runs the Static node: a privacy-preserving network node that
//! participates in the Sphinx mixnet, storage swap, and cover
//! traffic system.

use anyhow::Result;
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use static_node::{NodeConfig, StaticNode};

/// Static - A privacy network where traffic is indistinguishable from noise
#[derive(Parser, Debug)]
#[command(name = "static", version, about)]
struct Cli {
    /// Data directory for node storage
    #[arg(long, default_value = "./node-data")]
    data_dir: PathBuf,

    /// Cover traffic rate in bytes per second
    #[arg(long, default_value_t = 100 * 1024)]
    cover_rate: u64,

    /// Cover traffic interval in milliseconds
    #[arg(long, default_value_t = 100)]
    cover_interval: u64,

    /// Disable cover traffic (NOT RECOMMENDED - removes deniability)
    #[arg(long)]
    no_cover: bool,

    /// Listen address
    #[arg(long, default_value = "0.0.0.0:9000")]
    listen: String,

    /// Bootstrap peer (can be specified multiple times)
    #[arg(long, action = clap::ArgAction::Append)]
    peer: Vec<String>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Start the node
    Start,
    /// Show node status
    Status,
    /// Generate a new node identity
    GenId,
    /// Show version and architecture info
    Info,
}

fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let cli = Cli::parse();

    let config = NodeConfig {
        data_dir: cli.data_dir.clone(),
        cover_traffic_rate_bps: cli.cover_rate,
        cover_traffic_interval_ms: cli.cover_interval,
        cover_traffic_enabled: !cli.no_cover,
        listen_addr: cli.listen.clone(),
        bootstrap_peers: cli.peer.clone(),
        ..Default::default()
    };

    match cli.command {
        Commands::Start => {
            let mut node = StaticNode::new(config);
            node.init()?;
            node.start();

            println!("Static node is running.");
            println!("Node ID: {:02x?}", node.mesh.node_id);
            println!("Cover traffic: {} bps", node.config.cover_traffic_rate_bps);
            println!("Press Ctrl+C to stop.");

            // In a real implementation, this would start the async runtime
            // and run the main event loop. For now, we just print status.
            let status = node.status();
            println!("Peers: {} known, {} connected", status.peer_count, status.connected_peers);

            // Keep the node running until Ctrl+C
            // This is a placeholder - the real implementation will use
            // tokio::signal::ctrl_c() in an async context
            println!("\nNote: This is a scaffold. The async runtime is not yet implemented.");
            println!("The node state is in memory but not actively networking.");
        }
        Commands::Status => {
            let node = StaticNode::new(config);
            let status = node.status();

            println!("Static Node Status");
            println!("==================");
            println!("Running: {}", status.running);
            println!("Node ID: {:02x?}", status.node_id);
            println!("Peers: {} known, {} connected", status.peer_count, status.connected_peers);
            println!("Stored chunks: {}", status.stored_chunks);
            println!("Published content: {}", status.published_content);
            println!("Cover traffic: {}", if status.cover_traffic_enabled { "enabled" } else { "disabled" });
            println!("Bytes served: {}", status.total_bytes_served);
            println!("Bytes received: {}", status.total_bytes_received);
        }
        Commands::GenId => {
            let node = StaticNode::with_defaults();
            println!("Generated new node identity:");
            println!("  Node ID: {:02x?}", node.mesh.node_id);
            println!("  Mix public key: {:02x?}", node.mix_node.public_key);
            println!("\nSave these to your configuration to persist identity across restarts.");
        }
        Commands::Info => {
            println!("Static - Privacy network where traffic is indistinguishable from noise");
            println!();
            println!("Architecture:");
            println!("  - Sphinx mixnet (indistinguishable packets)");
            println!("  - Encrypted distributed storage (swap barter)");
            println!("  - Constant-rate cover traffic (always hot)");
            println!("  - Local peer-to-peer accounting (no blockchain)");
            println!("  - Pure darknet (no clearnet exit)");
            println!();
            println!("Status: Pre-alpha scaffold");
            println!("Version: 0.1.0");
            println!("License: AGPL-3.0-or-later");
        }
    }

    Ok(())
}
