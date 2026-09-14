//! static-node - The main Static network node binary

use anyhow::Result;
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use static_node::{NodeConfig, runner::NodeRunner};
use static_node::config::PersistentConfig;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use serde::{Serialize, Deserialize};

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

    /// Listen address for P2P network
    #[arg(long, default_value = "0.0.0.0:9000")]
    listen: String,

    /// Local API listen address
    #[arg(long, default_value = "127.0.0.1:9050")]
    api_addr: String,

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
    /// Publish a file to the network
    Publish {
        /// Path to the file to publish
        file_path: PathBuf,
    },
    /// Retrieve a file from the network
    Retrieve {
        /// Path to the JSON manifest file
        manifest_path: PathBuf,
        /// Hex-encoded master key
        master_key: String,
        /// Path to save the retrieved file
        output_path: PathBuf,
    },
}

#[derive(Serialize, Deserialize, Debug)]
struct ApiRequest {
    action: String,
    data: Option<String>,
    manifest: Option<static_storage::ContentManifest>,
    master_key: Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
struct ApiResponse {
    status: String,
    message: String,
    content_id: Option<String>,
    manifest: Option<static_storage::ContentManifest>,
    data: Option<String>,
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
        api_addr: cli.api_addr.clone(),
        bootstrap_peers: cli.peer.clone(),
        max_storage_bytes: cli.max_storage,
        ..Default::default()
    };

    match cli.command {
        Commands::Start => {
            std::fs::create_dir_all(&config.data_dir)?;
            let persistent_config = PersistentConfig::load_or_create(&config.data_dir)?;
            let node_id = persistent_config.node_id;
            let mix_node = persistent_config.to_mix_node();

            tracing::info!("Starting Static node: {:02x?}", node_id);
            tracing::info!("P2P Listen address: {}", config.listen_addr);
            tracing::info!("API Listen address: {}", config.api_addr);
            tracing::info!("Cover traffic: {} bps", config.cover_traffic_rate_bps);
            tracing::info!("Storage contribution: {} bytes", config.max_storage_bytes);

            let runner = Arc::new(NodeRunner::new(config, node_id, mix_node));
            let runner_clone = runner.clone();
            
            let node_handle = tokio::spawn(async move {
                if let Err(e) = runner_clone.run().await {
                    tracing::error!("Node runner error: {}", e);
                }
            });

            tracing::info!("Node running. Press Ctrl+C to stop.");

            tokio::signal::ctrl_c().await?;
            tracing::info!("Shutdown signal received, stopping node...");
            node_handle.abort();
            tracing::info!("Node stopped.");
        }
        Commands::Status => {
            println!("Static Node Status");
            println!("==================");
            println!("Data directory: {:?}", config.data_dir);
            println!("P2P address: {}", config.listen_addr);
            println!("API address: {}", config.api_addr);
            println!("Cover traffic: {}", if config.cover_traffic_enabled { "enabled" } else { "disabled" });
            println!("Cover rate: {} bps", config.cover_traffic_rate_bps);
            println!("Max storage: {} bytes", config.max_storage_bytes);
            println!("Bootstrap peers: {:?}", config.bootstrap_peers);
        }
        Commands::GenId => {
            let persistent_config = PersistentConfig::new();
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
        Commands::Publish { file_path } => {
            let file_data = std::fs::read(&file_path)?;
            let data_hex = hex::encode(&file_data);
            
            let request = ApiRequest {
                action: "publish".into(),
                data: Some(data_hex),
                manifest: None,
                master_key: None,
            };
            
            let response = send_api_request(&config.api_addr, &request).await?;
            
            if response.status == "ok" {
                println!("Successfully published file: {:?}", file_path);
                println!("Content ID: {}", response.content_id.unwrap_or_default());
                if let Some(manifest) = response.manifest {
                    let manifest_json = serde_json::to_string_pretty(&manifest)?;
                    let manifest_path = file_path.with_extension("manifest.json");
                    std::fs::write(&manifest_path, manifest_json)?;
                    println!("Manifest saved to: {:?}", manifest_path);
                }
            } else {
                eprintln!("Publish failed: {}", response.message);
            }
        }
        Commands::Retrieve { manifest_path, master_key, output_path } => {
            let manifest_json = std::fs::read_to_string(&manifest_path)?;
            let manifest: static_storage::ContentManifest = serde_json::from_str(&manifest_json)?;
            
            let request = ApiRequest {
                action: "retrieve".into(),
                data: None,
                manifest: Some(manifest),
                master_key: Some(master_key),
            };
            
            let response = send_api_request(&config.api_addr, &request).await?;
            
            if response.status == "ok" {
                if let Some(data_hex) = response.data {
                    let file_data = hex::decode(&data_hex)?;
                    std::fs::write(&output_path, &file_data)?;
                    println!("Successfully retrieved file to: {:?}", output_path);
                } else {
                    eprintln!("Retrieve succeeded but no data returned.");
                }
            } else {
                eprintln!("Retrieve failed: {}", response.message);
            }
        }
    }

    Ok(())
}

async fn send_api_request(api_addr: &str, request: &ApiRequest) -> Result<ApiResponse> {
    let mut stream = TcpStream::connect(api_addr).await?;
    let request_bytes = serde_json::to_vec(request)?;
    stream.write_all(&request_bytes).await?;
    
    let mut buf = vec![0u8; 1024 * 1024 * 10]; // 10MB buffer for large files
    let n = stream.read(&mut buf).await?;
    
    let response: ApiResponse = serde_json::from_slice(&buf[..n])?;
    Ok(response)
}
