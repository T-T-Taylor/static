//! static-node - The main Static network node binary

use anyhow::Result;
use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};
use static_node::config::PersistentConfig;
use static_node::{runner::NodeRunner, NodeConfig};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

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

    /// Node mode (full, seed, backup, client)
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

    /// Enable compute request handling (sandboxed WASM execution)
    #[arg(long)]
    compute_enabled: bool,

    /// Maximum concurrent compute executions (default: 4)
    #[arg(long, default_value_t = 4)]
    compute_capacity: u32,

    /// Compute price per execution in atomic units (e.g. 0.001 XMR =
    /// 1000000000 atomic). Default 0 = free compute (no payment required)
    #[arg(long)]
    compute_price: Option<u64>,

    /// Accepted payment currencies, comma-separated (xmr, dark, nav)
    #[arg(long, default_value = "xmr")]
    compute_currencies: String,

    /// Required blockchain confirmations before executing paid compute
    #[arg(long, default_value_t = 1)]
    compute_confirmations: u32,

    /// Monero wallet RPC URL (monero-wallet-rpc, not monerod)
    #[arg(long, default_value = "http://127.0.0.1:18082/json_rpc")]
    monero_rpc: String,

    /// Enable chunk integrity verification challenges (item 14)
    #[arg(long, default_value_t = true)]
    verification_enabled: bool,

    /// Verification challenge interval in seconds (default: 1800 = 30 minutes)
    #[arg(long, default_value_t = 1800)]
    verification_interval: u64,

    /// Suppress non-error output (tracing level ERROR instead of INFO)
    #[arg(long)]
    quiet: bool,

    /// Bearer token required by the local API (never logged).
    /// Must match the running node's `--api-token` for CLI commands.
    #[arg(long)]
    api_token: Option<String>,

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
    /// Submit a compute request for a WASM module
    Compute {
        /// Hex-encoded content public key of the WASM module
        module_key: String,
        /// Hex-encoded input data for the module
        input: String,
        /// Payment currency (xmr, dark, or nav)
        #[arg(long, default_value = "xmr")]
        currency: String,
        /// Seconds to wait for the result before giving up (0 = submit only)
        #[arg(long, default_value_t = 30)]
        wait: u64,
    },
    /// Confirm an on-chain compute payment (after paying the quoted address)
    ComputeConfirm {
        /// Hex-encoded compute request ID from the compute command
        request_id: String,
        /// Transaction hash of the on-chain payment
        tx_hash: String,
    },
    /// Poll the result of a previously submitted compute request
    ComputeResult {
        /// Hex-encoded compute request ID
        request_id: String,
        /// Seconds to keep polling (0 = single check)
        #[arg(long, default_value_t = 30)]
        wait: u64,
    },
}

#[derive(Serialize, Deserialize, Debug)]
struct ApiRequest {
    action: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    content_pub_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    compute_currency: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    request_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tx_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    token: Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
struct ApiResponse {
    status: String,
    message: String,
    #[serde(default)]
    content_id: Option<String>,
    #[serde(default)]
    manifest: Option<static_storage::ContentManifest>,
    #[serde(default)]
    data: Option<String>,
    #[serde(default)]
    content_pub_key: Option<String>,
    #[serde(default)]
    request_id: Option<String>,
    #[serde(default)]
    payment_required: bool,
    #[serde(default)]
    payment_currency: Option<String>,
    #[serde(default)]
    payment_address: Option<String>,
    #[serde(default)]
    payment_amount: Option<u64>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // `--quiet` suppresses non-error output: ERROR instead of INFO.
    if cli.quiet {
        tracing_subscriber::fmt()
            .with_max_level(tracing::Level::ERROR)
            .init();
    } else {
        tracing_subscriber::fmt()
            .with_max_level(tracing::Level::INFO)
            .init();
    }

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
        "client" => static_node::NodeMode::Client,
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

    let compute_currencies = cli
        .compute_currencies
        .split(',')
        .map(|ticker| ticker.trim())
        .filter(|ticker| !ticker.is_empty())
        .map(|ticker| {
            static_node::payment::Currency::from_str(ticker).ok_or_else(|| {
                anyhow::anyhow!(
                    "Unsupported compute currency '{}' (accepted: xmr, dark, nav)",
                    ticker
                )
            })
        })
        .collect::<Result<Vec<_>>>()?;
    if compute_currencies.is_empty() {
        anyhow::bail!("--compute-currencies must name at least one currency (xmr, dark, nav)");
    }

    // Cover traffic is mandatory for Full/Client nodes; hybrid crypto is
    // mandatory for all modes. Seed-only nodes run reduced cover via the
    // runner (which forces a minimal rate), as a documented trade-off.
    let config = NodeConfig {
        data_dir: cli.data_dir.clone(),
        cover_traffic_rate_bps: cover_rate,
        cover_traffic_interval_ms: cli.cover_interval,
        cover_traffic_enabled: true,
        listen_addr: cli.listen.clone(),
        api_addr: cli.api_addr.clone(),
        bootstrap_peers: cli.peer.clone(),
        max_storage_bytes: cli.max_storage,
        tier,
        mode,
        sponsor: cli.sponsor.clone(),
        use_hybrid_crypto: true,
        rotation_config,
        backup_config,
        compute_config: static_node::ComputeConfig {
            enabled: cli.compute_enabled,
            capacity: cli.compute_capacity,
            pricing: static_node::payment::ComputePricing {
                price_per_execution: cli.compute_price.unwrap_or(0),
                accepted_currencies: compute_currencies,
                required_confirmations: cli.compute_confirmations,
                ..Default::default()
            },
            blockchain_config: static_node::payment::BlockchainConfig {
                monero_rpc_url: cli.monero_rpc.clone(),
                ..Default::default()
            },
            ..Default::default()
        },
        verification_enabled: cli.verification_enabled,
        verification_interval_secs: cli.verification_interval,
        api_token: cli.api_token.clone(),
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
            // Hybrid crypto is mandatory (v1 preferred, v0 fallback).
            tracing::info!("Hybrid crypto: enabled (v1 preferred)");
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
            println!(
                "Cover traffic: {}",
                if config.cover_traffic_enabled {
                    "enabled"
                } else {
                    "disabled"
                }
            );
            println!("Cover rate: {} bps", config.cover_traffic_rate_bps);
            println!("Max storage: {} bytes", config.max_storage_bytes);
            println!("Bootstrap peers: {:?}", config.bootstrap_peers);
            println!(
                "Rotation: {}",
                if config.rotation_config.enabled {
                    "enabled"
                } else {
                    "disabled"
                }
            );
            println!(
                "Rotation percentage: {}%",
                config.rotation_config.rotation_percentage
            );
            println!(
                "Caching: {}",
                if config.rotation_config.enable_caching {
                    "enabled"
                } else {
                    "disabled"
                }
            );
            if matches!(config.mode, static_node::NodeMode::BackupOnly) {
                println!(
                    "Backup primary: {}",
                    config
                        .backup_config
                        .primary_address
                        .as_deref()
                        .unwrap_or("<unconfigured>")
                );
                println!(
                    "Backup heartbeat timeout: {}s",
                    config.backup_config.heartbeat_timeout_secs
                );
                println!(
                    "Backup permanent takeover: {}",
                    config.backup_config.permanent_takeover
                );
            }
        }
        Commands::GenId => {
            // Never print private key material: Node ID + identity public
            // key only.
            let persistent_config = PersistentConfig::new();
            println!("Generated new node identity:");
            println!("  Node ID: {}", hex::encode(persistent_config.node_id));
            println!(
                "  Identity public key: {}",
                hex::encode(persistent_config.identity_public_key)
            );
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
                compute_currency: None,
                request_id: None,
                tx_hash: None,
                token: cli.api_token.clone(),
            };

            let response = send_api_request(&config.api_addr, &request).await?;

            if response.status == "ok" {
                println!("Successfully published file: {:?}", file_path);
                println!("Content ID: {}", response.content_id.unwrap_or_default());
                println!(
                    "Content Public Key: {}",
                    response.content_pub_key.unwrap_or_default()
                );
                if let Some(manifest) = response.manifest {
                    let manifest_json = serde_json::to_string_pretty(&manifest)?;
                    // Append .manifest.json to the original filename
                    let manifest_path = {
                        let mut path = file_path.clone();
                        path.set_extension(format!(
                            "{}.manifest.json",
                            path.extension()
                                .unwrap_or_default()
                                .to_string_lossy()
                                .to_string()
                        ));
                        path
                    };
                    std::fs::write(&manifest_path, manifest_json)?;
                    println!("Manifest saved to: {:?}", manifest_path);
                }
            } else {
                eprintln!("Publish failed: {}", response.message);
            }
        }
        Commands::Retrieve {
            content_pub_key,
            output_path,
        } => {
            let request = ApiRequest {
                action: "retrieve".into(),
                data: None,
                content_pub_key: Some(content_pub_key),
                compute_currency: None,
                request_id: None,
                tx_hash: None,
                token: cli.api_token.clone(),
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
        Commands::Compute {
            module_key,
            input,
            currency,
            wait,
        } => {
            let request = ApiRequest {
                action: "compute".into(),
                data: Some(input),
                content_pub_key: Some(module_key),
                compute_currency: Some(currency),
                request_id: None,
                tx_hash: None,
                token: cli.api_token.clone(),
            };

            let response = send_api_request(&config.api_addr, &request).await?;

            if response.status != "ok" {
                eprintln!("Compute failed: {}", response.message);
                return Ok(());
            }

            let request_id = response
                .request_id
                .ok_or_else(|| anyhow::anyhow!("Compute accepted but no request ID returned"))?;
            println!("Compute request submitted. Request ID: {}", request_id);

            if wait > 0 {
                poll_compute_result(&config.api_addr, &request_id, wait, cli.api_token.clone())
                    .await;
            } else {
                println!(
                    "Poll for the result: static-node compute-result {} --wait",
                    request_id
                );
            }
        }
        Commands::ComputeConfirm {
            request_id,
            tx_hash,
        } => {
            let request = ApiRequest {
                action: "compute_confirm".into(),
                data: None,
                content_pub_key: None,
                compute_currency: None,
                request_id: Some(request_id.clone()),
                tx_hash: Some(tx_hash),
                token: cli.api_token.clone(),
            };

            let response = send_api_request(&config.api_addr, &request).await?;
            if response.status == "ok" {
                println!("{}", response.message);
                println!(
                    "Poll for the result: static-node compute-result {} --wait 600",
                    request_id
                );
            } else {
                eprintln!("Compute confirm failed: {}", response.message);
            }
        }
        Commands::ComputeResult { request_id, wait } => {
            poll_compute_result(&config.api_addr, &request_id, wait, cli.api_token.clone()).await;
        }
    }

    Ok(())
}

/// Poll the local API until a compute result arrives or the wait budget
/// is exhausted. When the provider quotes a payment the user pays from
/// their own wallet, then confirms via `static-node compute-confirm`;
/// polling keeps running in case the payment confirms within the budget.
async fn poll_compute_result(
    api_addr: &str,
    request_id: &str,
    wait_secs: u64,
    api_token: Option<String>,
) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(wait_secs);
    let mut payment_announced = false;
    while std::time::Instant::now() < deadline {
        tokio::time::sleep(std::time::Duration::from_millis(1000)).await;

        let poll = ApiRequest {
            action: "compute_result".into(),
            data: Some(request_id.to_string()),
            content_pub_key: None,
            compute_currency: None,
            request_id: None,
            tx_hash: None,
            token: api_token.clone(),
        };
        let poll_response = match send_api_request(api_addr, &poll).await {
            Ok(response) => response,
            Err(e) => {
                eprintln!("Poll failed: {}", e);
                return;
            }
        };

        match poll_response.status.as_str() {
            "ok" => {
                let output_hex = poll_response.data.unwrap_or_default();
                if poll_response.message.contains("failed") {
                    eprintln!("Compute execution failed: {}", output_hex);
                } else {
                    println!("Compute output (hex): {}", output_hex);
                }
                return;
            }
            "pending" => {
                if poll_response.payment_required && !payment_announced {
                    payment_announced = true;
                    println!(
                        "Payment required: {} {} to {}",
                        poll_response.payment_amount.unwrap_or(0),
                        poll_response.payment_currency.unwrap_or_default(),
                        poll_response.payment_address.unwrap_or_default()
                    );
                    println!(
                        "Send the payment from your wallet, then run:\n  static-node compute-confirm {} <tx_hash>",
                        request_id
                    );
                    println!("Polling for the result...");
                }
            }
            _ => {
                eprintln!("Compute failed: {}", poll_response.message);
                return;
            }
        }
    }
    if payment_announced {
        println!(
            "Payment not confirmed yet. After paying, confirm with:\n  static-node compute-confirm {} <tx_hash>",
            request_id
        );
    } else {
        println!(
            "Result not ready yet. Poll again later: static-node compute-result {} --wait",
            request_id
        );
    }
}

async fn send_api_request(api_addr: &str, request: &ApiRequest) -> Result<ApiResponse> {
    let mut stream = TcpStream::connect(api_addr).await?;
    let request_bytes = serde_json::to_vec(request)?;
    stream.write_all(&request_bytes).await?;
    // Half-close writes so the server sees EOF promptly; then read the
    // response chunked until EOF (server closes after responding).
    let _ = stream.shutdown().await;
    const MAX_RESPONSE_BYTES: usize = 10 * 1024 * 1024;
    let mut buf = Vec::with_capacity(8192);
    let mut chunk = [0u8; 8192];
    loop {
        match stream.read(&mut chunk).await {
            Ok(0) => break,
            Ok(n) => {
                if buf.len() + n > MAX_RESPONSE_BYTES {
                    anyhow::bail!("API response too large");
                }
                buf.extend_from_slice(&chunk[..n]);
            }
            Err(e) => anyhow::bail!("API read failed: {}", e),
        }
    }

    let response: ApiResponse = serde_json::from_slice(&buf)?;
    Ok(response)
}
