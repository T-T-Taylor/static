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

    /// Bandwidth tier for cover traffic and priority (low, standard, high)
    #[arg(long, default_value = "standard")]
    tier: String,

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

    /// Node mode (full, seed, backup)
    #[arg(long, default_value = "full")]
    mode: String,

    /// Sponsor peer address (required for seed-only mode)
    #[arg(long)]
    sponsor: Option<String>,

    /// Primary node address to monitor (required for backup mode)
    #[arg(long)]
    backup_primary: Option<String>,

    /// Heartbeat timeout in seconds (default: 5400 = 3x 30-min cadence)
    #[arg(long, default_value_t = 5400)]
    backup_timeout: u64,

    /// Use post-quantum hybrid Sphinx packets (default: true)
    ///
    /// Bare `--hybrid-crypto` means true; pass `--hybrid-crypto=false`
    /// to force classical-only (v0) packets.
    #[arg(
        long,
        default_value_t = true,
        default_missing_value = "true",
        require_equals = true,
        num_args = 0..=1,
        action = clap::ArgAction::Set,
        value_parser = clap::builder::BoolishValueParser::new()
    )]
    hybrid_crypto: bool,

    /// Disable hot storage rotation
    #[arg(long)]
    no_rotation: bool,

    /// Rotation epoch duration in seconds (default: 86400 = 24 hours)
    #[arg(long, default_value_t = 86400)]
    rotation_epoch: u64,

    /// Percentage of chunks to rotate per epoch (default: 10)
    #[arg(long, default_value_t = 10)]
    rotation_percentage: u8,

    /// Disable chunk caching (Freenet-style)
    #[arg(long)]
    no_caching: bool,

    /// Maximum cached chunks (default: 100)
    #[arg(long, default_value_t = 100)]
    max_cached: usize,

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
        /// Hex-encoded content public key
        content_pub_key: String,
        /// Path to save the retrieved file
        output_path: PathBuf,
    },
}

#[derive(Serialize, Deserialize, Debug)]
struct ApiRequest {
    action: String,
    data: Option<String>,
    content_pub_key: Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
struct ApiResponse {
    status: String,
    message: String,
    content_id: Option<String>,
    manifest: Option<static_storage::ContentManifest>,
    data: Option<String>,
    content_pub_key: Option<String>,
}


#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let cli = Cli::parse();

    let tier = match cli.tier.to_lowercase().as_str() {
        "low" => static_mesh::BandwidthTier::Low,
        "high" => static_mesh::BandwidthTier::High,
        _ => static_mesh::BandwidthTier::Standard,
    };

    // If tier is specified, override the cover rate with the tier default
    let cover_rate = if cli.tier != "standard" {
        tier.target_rate_bps()
    } else {
        cli.cover_rate
    };

    let mode = match cli.mode.to_lowercase().as_str() {
        "seed" => static_node::NodeMode::SeedOnly,
        "backup" => static_node::NodeMode::BackupOnly,
        _ => static_node::NodeMode::Full,
    };

    if matches!(mode, static_node::NodeMode::SeedOnly) && cli.sponsor.is_none() {
        anyhow::bail!("Seed-only mode requires --sponsor <addr>");
    }

    if matches!(mode, static_node::NodeMode::BackupOnly) && cli.backup_primary.is_none() {
        anyhow::bail!("Backup-only mode requires --backup-primary <addr>");
    }

    let backup_config = if matches!(mode, static_node::NodeMode::BackupOnly) {
        static_node::BackupConfig {
            enabled: true,
            primary_address: cli.backup_primary.clone(),
            primary_node_id: None,
            heartbeat_timeout_secs: cli.backup_timeout,
            permanent_takeover: true,
        }
    } else {
        static_node::BackupConfig::default()
    };

    let rotation_config = static_storage::rotation::RotationConfig {
        enabled: !cli.no_rotation,
        epoch_duration_secs: cli.rotation_epoch,
        rotation_percentage: cli.rotation_percentage,
        enable_caching: !cli.no_caching,
        max_cached_chunks: cli.max_cached,
        min_lease_remaining_secs: 3600,
    };

    let config = NodeConfig {
        data_dir: cli.data_dir.clone(),
        cover_traffic_rate_bps: cover_rate,
        cover_traffic_interval_ms: cli.cover_interval,
        cover_traffic_enabled: !cli.no_cover,
        listen_addr: cli.listen.clone(),
        api_addr: cli.api_addr.clone(),
        bootstrap_peers: cli.peer.clone(),
        max_storage_bytes: cli.max_storage,
        tier,
        mode,
        sponsor: cli.sponsor.clone(),
        use_hybrid_crypto: cli.hybrid_crypto,
        rotation_config,
        backup_config,
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
            tracing::info!("Node mode: {:?}", config.mode);
            if let Some(sponsor) = &config.sponsor {
                tracing::info!("Sponsor: {}", sponsor);
            }
            tracing::info!(
                "Hybrid crypto: {}",
                if config.use_hybrid_crypto { "enabled (v1 preferred)" } else { "disabled (v0 only)" }
            );
            tracing::info!("Bandwidth tier: {:?}", config.tier);
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
            println!("Node mode: {:?}", config.mode);
            if let Some(sponsor) = &config.sponsor {
                println!("Sponsor: {}", sponsor);
            }
            println!("Bandwidth tier: {:?}", config.tier);
            println!("Cover traffic: {}", if config.cover_traffic_enabled { "enabled" } else { "disabled" });
            println!("Cover rate: {} bps", config.cover_traffic_rate_bps);
            println!("Max storage: {} bytes", config.max_storage_bytes);
            println!("Bootstrap peers: {:?}", config.bootstrap_peers);
            println!("Rotation: {}", if config.rotation_config.enabled { "enabled" } else { "disabled" });
            println!("Rotation percentage: {}%", config.rotation_config.rotation_percentage);
            println!("Caching: {}", if config.rotation_config.enable_caching { "enabled" } else { "disabled" });
            if matches!(config.mode, static_node::NodeMode::BackupOnly) {
                println!(
                    "Backup primary: {}",
                    config.backup_config.primary_address.as_deref().unwrap_or("<unconfigured>")
                );
                println!("Backup heartbeat timeout: {}s", config.backup_config.heartbeat_timeout_secs);
                println!("Backup permanent takeover: {}", config.backup_config.permanent_takeover);
            }
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
                content_pub_key: None,
            };
            
            let response = send_api_request(&config.api_addr, &request).await?;
            
            if response.status == "ok" {
                println!("Successfully published file: {:?}", file_path);
                println!("Content ID: {}", response.content_id.unwrap_or_default());
                println!("Content Public Key: {}", response.content_pub_key.unwrap_or_default());
                if let Some(manifest) = response.manifest {
                    let manifest_json = serde_json::to_string_pretty(&manifest)?;
                    // Append .manifest.json to the original filename
                    let manifest_path = {
                        let mut path = file_path.clone();
                        path.set_extension(format!("{}.manifest.json", path.extension().unwrap_or_default().to_string_lossy().to_string()));
                        path
                    };
                    std::fs::write(&manifest_path, manifest_json)?;
                    println!("Manifest saved to: {:?}", manifest_path);
                }
            } else {
                eprintln!("Publish failed: {}", response.message);
            }
        }
        Commands::Retrieve { content_pub_key, output_path } => {
            let request = ApiRequest {
                action: "retrieve".into(),
                data: None,
                content_pub_key: Some(content_pub_key),
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
