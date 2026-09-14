//! static-node - The main Static network node binary

use anyhow::Result;
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use static_node::NodeConfig;
use static_node::runner::NodeRunner;

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

    /// Maximum storage to contribute in bytes
    #[arg(long, default_value_t = 10 * 1024 * 1024 * 1024)]
    max_storage: u64,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Start the node and connect to the network
    Start,
    /// Show node status (requires node to be running separately)
    Status,
    /// Generate a new node identity
    GenId,
    /// Show version and architecture info
    Info,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let cli = Cli::parse();

    let config = NodeConfig {
        data_dir: cli.data_dir.clone(),
        cover_traffic_rate_bps: cli.cover_rate,
        cover_traffic_interval_ms: cli.cover_interval,
        cover_traffic_enabled: !cli.no_cover,
        listen_addr: cli.listen.clone(),
        bootstrap_peers: cli.peer.clone(),
        max_storage_bytes: cli.max_storage,
        ..Default::default()
    };

    match cli.command {
        Commands::Start => {
            // Ensure data directory exists
            std::fs::create_dir_all(&config.data_dir)?;

            // Load or create node identity
            let persistent_config = static_node::config::PersistentConfig::load_or_create(&config.data_dir)?;
            let node_id = persistent_config.node_id;
            let mix_node = persistent_config.to_mix_node();

            tracing::info!("Starting Static node: {:02x?}", node_id);
            tracing::info!("Listen address: {}", config.listen_addr);
            tracing::info!("Cover traffic: {} bps", config.cover_traffic_rate_bps);
            tracing::info!("Storage contribution: {} bytes", config.max_storage_bytes);

            let runner = NodeRunner::new(config, node_id, mix_node);

            // Run the node in a tokio task
            let node_handle = tokio::spawn(async move {
                if let Err(e) = runner.run().await {
                    tracing::error!("Node runner error: {}", e);
                }
            });

            tracing::info!("Node running. Press Ctrl+C to stop.");

            // Wait for Ctrl+C
            tokio::signal::ctrl_c().await?;
            
            tracing::info!("Shutdown signal received, stopping node...");
            node_handle.abort();
            tracing::info!("Node stopped.");
        }
        Commands::Status => {
            // In a real implementation, this would connect to the running node via IPC/API
            // For now, just show what the config would be
            println!("Static Node Status");
            println!("==================");
            println!("Data directory: {:?}", config.data_dir);
            println!("Listen address: {}", config.listen_addr);
            println!("Cover traffic: {}", if config.cover_traffic_enabled { "enabled" } else { "disabled" });
            println!("Cover rate: {} bps", config.cover_traffic_rate_bps);
            println!("Max storage: {} bytes", config.max_storage_bytes);
            println!("Bootstrap peers: {:?}", config.bootstrap_peers);
        }
        Commands::GenId => {
            let persistent_config = static_node::config::PersistentConfig::new();
            println!("Generated new node identity:");
            println!("  Node ID: {:02x?}", persistent_config.node_id);
            println!("  Mix private key: {:02x?}", persistent_config.mix_private_key);
            println!("\nRun 'static-node start' to save this to config.json and start the node.");
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
            println!("Status: Pre-alpha");
            println!("Version: 0.1.0");
            println!("License: AGPL-3.0-or-later");
        }
    }

    Ok(())
}
