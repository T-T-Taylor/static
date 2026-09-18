//! static-node library - Node logic for the Static network
//!
//! Ties together all Static components:
//! - Sphinx mixnet for indistinguishable packet routing
//! - Encrypted distributed storage with swap barter
//! - Local peer-to-peer accounting without a blockchain
//! - Mesh transport with constant-rate cover traffic
//!
//! The node coordinates these components to provide a privacy-preserving
//! network where traffic is indistinguishable from noise.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

/// Node configuration persistence
pub mod config;

/// Local API server
pub mod api;

/// WASM compute execution (sandboxed module runtime)
pub mod compute;

/// Cryptocurrency payment support for compute (prepayment, blockchain watching)
pub mod payment;

/// Async node runner
pub mod runner;

use static_crypto::SymmetricKey;
use static_mesh::{MeshState, CoverTrafficConfig};
use static_sphinx::MixNode;
use static_accounting::AccountingState;
use std::collections::HashMap;
use std::path::PathBuf;
use rand::rngs::OsRng;
use rand::RngCore;

/// Node operation mode
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum NodeMode {
    /// Full node: hosts and retrieves content normally
    Full = 0,
    /// Seed-only node: pre-pays a sponsor to host on its behalf
    SeedOnly = 1,
    /// Backup-only node: dormant until primary fails, then activates
    BackupOnly = 2,
}

impl Default for NodeMode {
    fn default() -> Self {
        NodeMode::Full
    }
}

/// Configuration for a Static node
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct NodeConfig {
    /// Data directory for node storage
    pub data_dir: PathBuf,
    /// Target send rate for cover traffic in bytes per second
    pub cover_traffic_rate_bps: u64,
    /// Cover traffic interval in milliseconds
    pub cover_traffic_interval_ms: u64,
    /// Whether to enable cover traffic
    pub cover_traffic_enabled: bool,
    /// Bandwidth tier for this node
    pub tier: static_mesh::BandwidthTier,
    /// Listen address for the node
    pub listen_addr: String,
    /// Bootstrap peers to connect to
    pub bootstrap_peers: Vec<String>,
    /// Local API listen address
    pub api_addr: String,
    /// Maximum storage to contribute in bytes
    pub max_storage_bytes: u64,
    /// Node operation mode
    pub mode: NodeMode,
    /// Sponsor peer address (required for seed-only mode)
    pub sponsor: Option<String>,
    /// Whether to use post-quantum hybrid Sphinx packets
    ///
    /// When true (default for new nodes), cover traffic and retrieval
    /// forward requests use hybrid v1 packets whenever the peer's KEM
    /// key is known, falling back to classical v0 otherwise.
    #[serde(default = "default_hybrid_crypto")]
    pub use_hybrid_crypto: bool,
    /// Hot storage rotation configuration (Freenet-style migration/caching)
    #[serde(default = "default_rotation_config")]
    pub rotation_config: static_storage::rotation::RotationConfig,
    /// Backup-only mode configuration
    #[serde(default = "default_backup_config")]
    pub backup_config: BackupConfig,
    /// Compute offering configuration (WASM execution for peers)
    #[serde(default = "default_compute_config")]
    pub compute_config: ComputeConfig,
    /// Whether to run chunk integrity verification challenges (item 14)
    #[serde(default = "default_verification_enabled")]
    pub verification_enabled: bool,
    /// Verification challenge sweep interval in seconds (default 1800)
    #[serde(default = "default_verification_interval")]
    pub verification_interval_secs: u64,
}

/// Default for `NodeConfig::use_hybrid_crypto`: new nodes opt into hybrid
fn default_hybrid_crypto() -> bool {
    true
}

/// Default for `NodeConfig::rotation_config`
fn default_rotation_config() -> static_storage::rotation::RotationConfig {
    static_storage::rotation::RotationConfig::default()
}

/// Configuration for backup-only mode
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct BackupConfig {
    /// Whether this backup node is enabled
    pub enabled: bool,
    /// Address of the primary content owner to monitor (required for
    /// `--mode backup`). The node dials this address and resolves the
    /// primary's node ID from the handshake.
    pub primary_address: Option<String>,
    /// Node ID of the primary content owner
    ///
    /// Normally resolved automatically from `primary_address` after the
    /// first handshake. Can be set directly for programmatic use and
    /// tests. When neither address nor ID is known, a backup never
    /// activates (it has no liveness signal to monitor).
    pub primary_node_id: Option<[u8; 16]>,
    /// Heartbeat timeout in seconds
    ///
    /// The primary is considered failed once no inbound activity
    /// (gossip, cover-adjacent traffic, swaps, requests) has been seen
    /// for this long. Default: 5400 = 3x the 30-minute gossip/heartbeat
    /// cadence.
    pub heartbeat_timeout_secs: u64,
    /// Whether to take over permanently on activation (default: true)
    ///
    /// When true, an activated backup keeps extending the leases of its
    /// held chunks and stays the serving primary. When false, leases are
    /// extended once at activation and then lapse naturally, so the
    /// content expires if the original primary does not return.
    pub permanent_takeover: bool,
}

impl Default for BackupConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            primary_address: None,
            primary_node_id: None,
            heartbeat_timeout_secs: 5400,
            permanent_takeover: true,
        }
    }
}

/// Default for `NodeConfig::backup_config`
fn default_backup_config() -> BackupConfig {
    BackupConfig::default()
}

/// Configuration for compute offering (sandboxed WASM execution)
///
/// A compute provider executes WASM modules for peers through the mixnet
/// and is paid in cryptocurrency prepayment (see [`payment`]). Disabled by
/// default; enable with `--compute-enabled`. All-zero [`payment::ComputePricing`]
/// (the default) offers free compute with no payment round-trip.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ComputeConfig {
    /// Whether this node accepts compute requests
    pub enabled: bool,
    /// Maximum concurrent compute executions
    pub capacity: u32,
    /// Maximum CPU time per execution in milliseconds (fuel-based cap)
    pub max_cpu_ms: u64,
    /// Maximum memory per execution in megabytes
    pub max_memory_mb: u32,
    /// Provider's compute pricing (all-zero = free tier)
    #[serde(default)]
    pub pricing: crate::payment::ComputePricing,
    /// Blockchain configuration for payment watching
    #[serde(default)]
    pub blockchain_config: crate::payment::BlockchainConfig,
}

impl Default for ComputeConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            capacity: 4,
            max_cpu_ms: 5000,
            max_memory_mb: 64,
            pricing: crate::payment::ComputePricing::default(),
            blockchain_config: crate::payment::BlockchainConfig::default(),
        }
    }
}

/// Default for `NodeConfig::compute_config`
fn default_compute_config() -> ComputeConfig {
    ComputeConfig::default()
}

/// Default for `NodeConfig::verification_enabled` (challenges on)
fn default_verification_enabled() -> bool {
    true
}

/// Default for `NodeConfig::verification_interval_secs` (30 minutes)
fn default_verification_interval() -> u64 {
    1800
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            data_dir: PathBuf::from("./node-data"),
            cover_traffic_rate_bps: 100 * 1024, // 100 KB/s
            cover_traffic_interval_ms: 100,
            cover_traffic_enabled: true,
            tier: static_mesh::BandwidthTier::Standard,
            listen_addr: "0.0.0.0:9000".to_string(),
            bootstrap_peers: vec![],
            api_addr: "127.0.0.1:9050".to_string(),
            max_storage_bytes: 10 * 1024 * 1024 * 1024, // 10 GB
            mode: NodeMode::Full,
            sponsor: None,
            use_hybrid_crypto: default_hybrid_crypto(),
            rotation_config: default_rotation_config(),
            backup_config: default_backup_config(),
            compute_config: default_compute_config(),
            verification_enabled: default_verification_enabled(),
            verification_interval_secs: default_verification_interval(),
        }
    }
}

/// The main Static node
pub struct StaticNode {
    /// Node configuration
    pub config: NodeConfig,
    /// Mesh state (peers, cover traffic)
    pub mesh: MeshState,
    /// Mix node (Sphinx processing)
    pub mix_node: MixNode,
    /// Accounting state (local credit tracking)
    pub accounting: AccountingState,
    /// Master key for this node's storage
    pub storage_key: SymmetricKey,
    /// Chunks this node is storing for others
    pub stored_chunks: HashMap<[u8; 32], Vec<u8>>,
    /// Content this node has published (content_id -> manifest)
    pub published_content: HashMap<[u8; 32], static_storage::ContentManifest>,
    /// Whether the node is running
    pub running: bool,
}

impl StaticNode {
    /// Create a new Static node with the given configuration
    pub fn new(config: NodeConfig) -> Self {
        let mesh = MeshState::new();
        let mix_node = MixNode::new();
        let accounting = AccountingState::default();
        let storage_key = SymmetricKey::random();

        Self {
            config,
            mesh,
            mix_node,
            accounting,
            storage_key,
            stored_chunks: HashMap::new(),
            published_content: HashMap::new(),
            running: false,
        }
    }

    /// Create a new Static node with default configuration
    pub fn with_defaults() -> Self {
        Self::new(NodeConfig::default())
    }

    /// Initialize the node
    pub fn init(&mut self) -> anyhow::Result<()> {
        // Create data directory if it doesn't exist
        std::fs::create_dir_all(&self.config.data_dir)?;

        // Update cover traffic config
        let cover_config = CoverTrafficConfig {
            target_rate_bps: self.config.cover_traffic_rate_bps,
            interval_ms: self.config.cover_traffic_interval_ms,
            enabled: self.config.cover_traffic_enabled,
            tier: self.config.tier,
            use_hybrid: self.config.use_hybrid_crypto,
        };
        self.mesh.cover_traffic.update_config(cover_config);

        // Add bootstrap peers
        for peer_addr in &self.config.bootstrap_peers {
            let mut peer_id = [0u8; 16];
            OsRng.fill_bytes(&mut peer_id);
            self.mesh.add_peer(peer_id, peer_addr.clone(), self.config.tier);
        }

        tracing::info!("Static node initialized");
        tracing::info!("Node ID: {:?}", self.mesh.node_id);
        tracing::info!("Mix node public key: {:?}", self.mix_node.public_key);
        tracing::info!("Data directory: {:?}", self.config.data_dir);
        tracing::info!("Cover traffic: {} bps", self.config.cover_traffic_rate_bps);

        Ok(())
    }

    /// Start the node (placeholder for async runtime)
    pub fn start(&mut self) {
        self.running = true;
        tracing::info!("Static node started");
    }

    /// Stop the node
    pub fn stop(&mut self) {
        self.running = false;
        tracing::info!("Static node stopped");
    }

    /// Get node status
    pub fn status(&self) -> NodeStatus {
        NodeStatus {
            running: self.running,
            node_id: self.mesh.node_id,
            peer_count: self.mesh.peer_count(),
            connected_peers: self.mesh.connected_count(),
            stored_chunks: self.stored_chunks.len(),
            published_content: self.published_content.len(),
            cover_traffic_enabled: self.mesh.cover_traffic.is_enabled(),
            total_bytes_served: self.accounting.total_bytes_served,
            total_bytes_received: self.accounting.total_bytes_received,
        }
    }

    /// Store a chunk for another node
    pub fn store_chunk(&mut self, chunk_id: [u8; 32], data: Vec<u8>) {
        self.stored_chunks.insert(chunk_id, data);
    }

    /// Retrieve a stored chunk
    pub fn get_stored_chunk(&self, chunk_id: &[u8; 32]) -> Option<&Vec<u8>> {
        self.stored_chunks.get(chunk_id)
    }

    /// Remove a stored chunk
    pub fn remove_stored_chunk(&mut self, chunk_id: &[u8; 32]) {
        self.stored_chunks.remove(chunk_id);
    }

    /// Get the total bytes stored for others
    pub fn total_stored_bytes(&self) -> u64 {
        self.stored_chunks
            .values()
            .map(|c| c.len() as u64)
            .sum()
    }
}

/// Node status information
#[derive(Debug, Clone, serde::Serialize)]
pub struct NodeStatus {
    /// Whether the node is running
    pub running: bool,
    /// This node's ID
    pub node_id: [u8; 16],
    /// Number of known peers
    pub peer_count: usize,
    /// Number of connected peers
    pub connected_peers: usize,
    /// Number of chunks stored for others
    pub stored_chunks: usize,
    /// Number of content items published
    pub published_content: usize,
    /// Whether cover traffic is enabled
    pub cover_traffic_enabled: bool,
    /// Total bytes served to others
    pub total_bytes_served: u64,
    /// Total bytes received from others
    pub total_bytes_received: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_node_creation() {
        let node = StaticNode::with_defaults();
        assert!(!node.running);
        assert_eq!(node.mesh.peer_count(), 0);
        assert_eq!(node.stored_chunks.len(), 0);
    }

    #[test]
    fn test_node_init() {
        let temp_dir = std::env::temp_dir().join("static-test-node");
        let config = NodeConfig {
            data_dir: temp_dir.clone(),
            ..Default::default()
        };
        let mut node = StaticNode::new(config);

        node.init().unwrap();
        assert!(temp_dir.exists());

        // Clean up
        std::fs::remove_dir_all(&temp_dir).ok();
    }

    #[test]
    fn test_node_start_stop() {
        let mut node = StaticNode::with_defaults();
        node.start();
        assert!(node.running);

        node.stop();
        assert!(!node.running);
    }

    #[test]
    fn test_node_status() {
        let node = StaticNode::with_defaults();
        let status = node.status();

        assert!(!status.running);
        assert_eq!(status.peer_count, 0);
        assert_eq!(status.connected_peers, 0);
    }

    #[test]
    fn test_store_and_retrieve_chunk() {
        let mut node = StaticNode::with_defaults();
        let chunk_id = [0x42u8; 32];
        let chunk_data = vec![0xABu8; 1024];

        node.store_chunk(chunk_id, chunk_data.clone());

        let retrieved = node.get_stored_chunk(&chunk_id).unwrap();
        assert_eq!(retrieved, &chunk_data);
        assert_eq!(node.total_stored_bytes(), 1024);
    }

    #[test]
    fn test_remove_chunk() {
        let mut node = StaticNode::with_defaults();
        let chunk_id = [0x42u8; 32];
        let chunk_data = vec![0xABu8; 1024];

        node.store_chunk(chunk_id, chunk_data);
        assert_eq!(node.stored_chunks.len(), 1);

        node.remove_stored_chunk(&chunk_id);
        assert_eq!(node.stored_chunks.len(), 0);
        assert!(node.get_stored_chunk(&chunk_id).is_none());
    }

    #[test]
    fn test_cover_traffic_config_update() {
        let config = NodeConfig {
            cover_traffic_rate_bps: 500 * 1024,
            cover_traffic_interval_ms: 50,
            cover_traffic_enabled: false,
            ..Default::default()
        };
        let mut node = StaticNode::new(config);
        node.init().unwrap();

        let temp_dir = node.config.data_dir.clone();
        assert!(!node.mesh.cover_traffic.is_enabled());

        // Clean up
        std::fs::remove_dir_all(&temp_dir).ok();
    }

    #[test]
    fn test_backup_config_default() {
        let config = BackupConfig::default();
        assert!(!config.enabled);
        assert_eq!(config.primary_address, None);
        assert_eq!(config.primary_node_id, None);
        assert_eq!(config.heartbeat_timeout_secs, 5400);
        assert!(config.permanent_takeover);

        // NodeConfig carries it with serde defaults
        let node_config = NodeConfig::default();
        assert_eq!(node_config.backup_config, BackupConfig::default());
    }
}
