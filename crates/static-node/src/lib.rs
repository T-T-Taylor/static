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

/// Async node runner
pub mod runner;

use static_crypto::SymmetricKey;
use static_mesh::{MeshState, CoverTrafficConfig};
use static_sphinx::MixNode;
use static_storage::AccountingState;
use std::collections::HashMap;
use std::path::PathBuf;
use rand::rngs::OsRng;
use rand::RngCore;

/// Configuration for a Static node
#[derive(Debug, Clone)]
pub struct NodeConfig {
    /// Data directory for node storage
    pub data_dir: PathBuf,
    /// Target send rate for cover traffic in bytes per second
    pub cover_traffic_rate_bps: u64,
    /// Cover traffic interval in milliseconds
    pub cover_traffic_interval_ms: u64,
    /// Whether to enable cover traffic
    pub cover_traffic_enabled: bool,
    /// Listen address for the node
    pub listen_addr: String,
    /// Bootstrap peers to connect to
    pub bootstrap_peers: Vec<String>,
    /// Maximum storage to contribute in bytes
    pub max_storage_bytes: u64,
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            data_dir: PathBuf::from("./node-data"),
            cover_traffic_rate_bps: 100 * 1024, // 100 KB/s
            cover_traffic_interval_ms: 100,
            cover_traffic_enabled: true,
            listen_addr: "0.0.0.0:9000".to_string(),
            bootstrap_peers: vec![],
            max_storage_bytes: 10 * 1024 * 1024 * 1024, // 10 GB
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
        };
        self.mesh.cover_traffic.update_config(cover_config);

        // Add bootstrap peers
        for peer_addr in &self.config.bootstrap_peers {
            let mut peer_id = [0u8; 16];
            OsRng.fill_bytes(&mut peer_id);
            self.mesh.add_peer(peer_id, peer_addr.clone());
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
            total_bytes_served: self.accounting.bytes_contributed,
            total_bytes_received: self.accounting.bytes_used,
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
}
