//! static-mesh - Overlay and mesh transport layer
//!
//! Implements:
//! - Peer discovery and connection management
//! - Constant-rate cover traffic (every node always sends/receives at fixed rate)
//! - Real traffic multiplexing (real Sphinx packets mixed with cover traffic)
//! - Bandwidth shaping (maintains constant rate regardless of real activity)
//!
//! The cover traffic is the core deniability property. Every node is
//! always "hot" - sending and receiving at a fixed rate. An adversary
//! cannot distinguish real traffic from cover traffic, cannot detect
//! when a node is active or idle, and cannot correlate timing patterns.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

/// Wire protocol module
pub mod wire;

/// Async TCP transport module
pub mod transport;

use std::collections::HashMap;
use std::time::{Duration, Instant};
use rand::rngs::OsRng;
use rand::RngCore;

/// Size of a node ID
pub const NODE_ID_SIZE: usize = 16;

/// Default target send rate in bytes per second (100 KB/s)
pub const DEFAULT_SEND_RATE_BPS: u64 = 100 * 1024;

/// Default cover traffic interval in milliseconds
pub const DEFAULT_COVER_INTERVAL_MS: u64 = 100;

/// Default peer timeout in seconds (5 minutes)
pub const DEFAULT_PEER_TIMEOUT_SECS: u64 = 300;

/// A node ID
pub type NodeId = [u8; NODE_ID_SIZE];

/// Peer connection state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerState {
    /// Peer is connected and active
    Connected,
    /// Peer is disconnected
    Disconnected,
    /// Peer connection is being established
    Connecting,
}

/// A peer in the mesh network
#[derive(Debug, Clone)]
pub struct Peer {
    /// The peer's node ID
    pub node_id: NodeId,
    /// The peer's network address (IP:port or mesh address)
    pub address: String,
    /// Connection state
    pub state: PeerState,
    /// Last seen timestamp
    pub last_seen: Instant,
    /// Bytes sent to this peer
    pub bytes_sent: u64,
    /// Bytes received from this peer
    pub bytes_received: u64,
}

impl Peer {
    /// Create a new peer
    pub fn new(node_id: NodeId, address: String) -> Self {
        Self {
            node_id,
            address,
            state: PeerState::Disconnected,
            last_seen: Instant::now(),
            bytes_sent: 0,
            bytes_received: 0,
        }
    }

    /// Mark peer as connected
    pub fn mark_connected(&mut self) {
        self.state = PeerState::Connected;
        self.last_seen = Instant::now();
    }

    /// Mark peer as disconnected
    pub fn mark_disconnected(&mut self) {
        self.state = PeerState::Disconnected;
    }

    /// Update last seen time
    pub fn touch(&mut self) {
        self.last_seen = Instant::now();
    }

    /// Check if peer is stale (not seen recently)
    pub fn is_stale(&self, timeout: Duration) -> bool {
        self.last_seen.elapsed() > timeout
    }

    /// Record bytes sent
    pub fn record_sent(&mut self, bytes: u64) {
        self.bytes_sent += bytes;
        self.touch();
    }

    /// Record bytes received
    pub fn record_received(&mut self, bytes: u64) {
        self.bytes_received += bytes;
        self.touch();
    }
}

/// Cover traffic generator configuration
#[derive(Debug, Clone)]
pub struct CoverTrafficConfig {
    /// Target send rate in bytes per second
    pub target_rate_bps: u64,
    /// Interval between cover packets in milliseconds
    pub interval_ms: u64,
    /// Whether cover traffic is enabled
    pub enabled: bool,
}

impl Default for CoverTrafficConfig {
    fn default() -> Self {
        Self {
            target_rate_bps: DEFAULT_SEND_RATE_BPS,
            interval_ms: DEFAULT_COVER_INTERVAL_MS,
            enabled: true,
        }
    }
}

/// Cover traffic generator
///
/// Generates dummy Sphinx packets at a constant rate to maintain
/// the "always hot" property. Real traffic is multiplexed in with
/// cover traffic, so an observer cannot distinguish real from dummy.
pub struct CoverTrafficGenerator {
    /// Configuration
    config: CoverTrafficConfig,
    /// Bytes sent in current interval
    bytes_this_interval: u64,
    /// Real bytes sent in current interval
    real_bytes_this_interval: u64,
    /// Cover bytes sent in current interval
    cover_bytes_this_interval: u64,
    /// Total bytes sent (all time)
    total_bytes_sent: u64,
    /// Total real bytes sent
    total_real_bytes_sent: u64,
    /// Total cover bytes sent
    total_cover_bytes_sent: u64,
    /// Last interval reset time
    last_reset: Instant,
}

impl CoverTrafficGenerator {
    /// Create a new cover traffic generator
    pub fn new(config: CoverTrafficConfig) -> Self {
        Self {
            config,
            bytes_this_interval: 0,
            real_bytes_this_interval: 0,
            cover_bytes_this_interval: 0,
            total_bytes_sent: 0,
            total_real_bytes_sent: 0,
            total_cover_bytes_sent: 0,
            last_reset: Instant::now(),
        }
    }

    /// Get the target bytes per interval
    pub fn target_bytes_per_interval(&self) -> u64 {
        (self.config.target_rate_bps * self.config.interval_ms) / 1000
    }

    /// Record real traffic sent
    pub fn record_real_traffic(&mut self, bytes: u64) {
        self.bytes_this_interval += bytes;
        self.real_bytes_this_interval += bytes;
        self.total_bytes_sent += bytes;
        self.total_real_bytes_sent += bytes;
    }

    /// Generate cover traffic to fill the current interval
    ///
    /// Returns the number of cover bytes to send. If real traffic
    /// has already filled the interval, returns 0.
    pub fn generate_cover_traffic(&mut self) -> u64 {
        let target = self.target_bytes_per_interval();
        let remaining = target.saturating_sub(self.bytes_this_interval);

        if remaining > 0 {
            self.bytes_this_interval += remaining;
            self.cover_bytes_this_interval += remaining;
            self.total_bytes_sent += remaining;
            self.total_cover_bytes_sent += remaining;
            remaining
        } else {
            0
        }
    }

    /// Check if it's time to reset the interval
    pub fn should_reset_interval(&self) -> bool {
        self.last_reset.elapsed() >= Duration::from_millis(self.config.interval_ms)
    }

    /// Reset the interval counters
    pub fn reset_interval(&mut self) {
        self.bytes_this_interval = 0;
        self.real_bytes_this_interval = 0;
        self.cover_bytes_this_interval = 0;
        self.last_reset = Instant::now();
    }

    /// Get current interval statistics
    pub fn interval_stats(&self) -> IntervalStats {
        IntervalStats {
            target_bytes: self.target_bytes_per_interval(),
            real_bytes: self.real_bytes_this_interval,
            cover_bytes: self.cover_bytes_this_interval,
            total_bytes: self.bytes_this_interval,
        }
    }

    /// Get total statistics
    pub fn total_stats(&self) -> TotalStats {
        TotalStats {
            total_bytes: self.total_bytes_sent,
            total_real_bytes: self.total_real_bytes_sent,
            total_cover_bytes: self.total_cover_bytes_sent,
            real_ratio: if self.total_bytes_sent > 0 {
                self.total_real_bytes_sent as f64 / self.total_bytes_sent as f64
            } else {
                0.0
            },
        }
    }

    /// Generate a dummy Sphinx packet for cover traffic
    pub fn generate_dummy_packet(&self, size: usize) -> Vec<u8> {
        let mut packet = vec![0u8; size];
        OsRng.fill_bytes(&mut packet);
        packet
    }

    /// Update configuration
    pub fn update_config(&mut self, config: CoverTrafficConfig) {
        self.config = config;
    }

    /// Check if cover traffic is enabled
    pub fn is_enabled(&self) -> bool {
        self.config.enabled
    }
}

/// Statistics for a single interval
#[derive(Debug, Clone)]
pub struct IntervalStats {
    /// Target bytes for this interval
    pub target_bytes: u64,
    /// Real bytes sent this interval
    pub real_bytes: u64,
    /// Cover bytes sent this interval
    pub cover_bytes: u64,
    /// Total bytes sent this interval
    pub total_bytes: u64,
}

/// Total statistics across all intervals
#[derive(Debug, Clone)]
pub struct TotalStats {
    /// Total bytes sent
    pub total_bytes: u64,
    /// Total real bytes sent
    pub total_real_bytes: u64,
    /// Total cover bytes sent
    pub total_cover_bytes: u64,
    /// Ratio of real to total traffic
    pub real_ratio: f64,
}

/// Mesh node state
pub struct MeshState {
    /// This node's ID
    pub node_id: NodeId,
    /// Known peers
    pub peers: HashMap<NodeId, Peer>,
    /// Cover traffic generator
    pub cover_traffic: CoverTrafficGenerator,
    /// Peer timeout duration
    pub peer_timeout: Duration,
}

impl MeshState {
    /// Create a new mesh state with a random node ID
    pub fn new() -> Self {
        let mut node_id = [0u8; NODE_ID_SIZE];
        OsRng.fill_bytes(&mut node_id);

        Self {
            node_id,
            peers: HashMap::new(),
            cover_traffic: CoverTrafficGenerator::new(CoverTrafficConfig::default()),
            peer_timeout: Duration::from_secs(DEFAULT_PEER_TIMEOUT_SECS),
        }
    }

    /// Create a new mesh state with a specific node ID
    pub fn with_node_id(node_id: NodeId) -> Self {
        Self {
            node_id,
            peers: HashMap::new(),
            cover_traffic: CoverTrafficGenerator::new(CoverTrafficConfig::default()),
            peer_timeout: Duration::from_secs(DEFAULT_PEER_TIMEOUT_SECS),
        }
    }

    /// Add a peer
    pub fn add_peer(&mut self, node_id: NodeId, address: String) {
        self.peers.insert(node_id, Peer::new(node_id, address));
    }

    /// Remove a peer
    pub fn remove_peer(&mut self, node_id: &NodeId) {
        self.peers.remove(node_id);
    }

    /// Get a peer
    pub fn get_peer(&self, node_id: &NodeId) -> Option<&Peer> {
        self.peers.get(node_id)
    }

    /// Get a mutable peer
    pub fn get_peer_mut(&mut self, node_id: &NodeId) -> Option<&mut Peer> {
        self.peers.get_mut(node_id)
    }

    /// Get connected peers
    pub fn connected_peers(&self) -> Vec<NodeId> {
        self.peers
            .iter()
            .filter(|(_, p)| p.state == PeerState::Connected)
            .map(|(id, _)| *id)
            .collect()
    }

    /// Prune stale peers
    pub fn prune_stale_peers(&mut self) {
        let timeout = self.peer_timeout;
        self.peers.retain(|_, peer| !peer.is_stale(timeout));
    }

    /// Record bytes sent to a peer
    pub fn record_sent(&mut self, peer: &NodeId, bytes: u64) {
        if let Some(p) = self.peers.get_mut(peer) {
            p.record_sent(bytes);
        }
        self.cover_traffic.record_real_traffic(bytes);
    }

    /// Record bytes received from a peer
    pub fn record_received(&mut self, peer: &NodeId, bytes: u64) {
        if let Some(p) = self.peers.get_mut(peer) {
            p.record_received(bytes);
        }
    }

    /// Get the number of known peers
    pub fn peer_count(&self) -> usize {
        self.peers.len()
    }

    /// Get the number of connected peers
    pub fn connected_count(&self) -> usize {
        self.peers
            .values()
            .filter(|p| p.state == PeerState::Connected)
            .count()
    }
}

impl Default for MeshState {
    fn default() -> Self {
        Self::new()
    }
}

/// Errors that can occur during mesh operations
#[derive(Debug, thiserror::Error)]
pub enum MeshError {
    /// Peer not found
    #[error("peer not found")]
    PeerNotFound,
    /// Peer not connected
    #[error("peer not connected")]
    PeerNotConnected,
    /// Cover traffic disabled
    #[error("cover traffic disabled")]
    CoverTrafficDisabled,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn random_node_id() -> NodeId {
        let mut id = [0u8; NODE_ID_SIZE];
        OsRng.fill_bytes(&mut id);
        id
    }

    #[test]
    fn test_peer_creation() {
        let node_id = random_node_id();
        let peer = Peer::new(node_id, "127.0.0.1:8000".to_string());

        assert_eq!(peer.node_id, node_id);
        assert_eq!(peer.address, "127.0.0.1:8000");
        assert_eq!(peer.state, PeerState::Disconnected);
        assert_eq!(peer.bytes_sent, 0);
        assert_eq!(peer.bytes_received, 0);
    }

    #[test]
    fn test_peer_state_transitions() {
        let node_id = random_node_id();
        let mut peer = Peer::new(node_id, "127.0.0.1:8000".to_string());

        peer.mark_connected();
        assert_eq!(peer.state, PeerState::Connected);

        peer.mark_disconnected();
        assert_eq!(peer.state, PeerState::Disconnected);
    }

    #[test]
    fn test_peer_byte_tracking() {
        let node_id = random_node_id();
        let mut peer = Peer::new(node_id, "127.0.0.1:8000".to_string());

        peer.record_sent(1000);
        peer.record_received(500);

        assert_eq!(peer.bytes_sent, 1000);
        assert_eq!(peer.bytes_received, 500);
    }

    #[test]
    fn test_peer_staleness() {
        let node_id = random_node_id();
        let mut peer = Peer::new(node_id, "127.0.0.1:8000".to_string());

        // Fresh peer
        assert!(!peer.is_stale(Duration::from_secs(60)));

        // Manually set last_seen to past
        peer.last_seen = Instant::now() - Duration::from_secs(120);
        assert!(peer.is_stale(Duration::from_secs(60)));
    }

    #[test]
    fn test_cover_traffic_config_default() {
        let config = CoverTrafficConfig::default();

        assert_eq!(config.target_rate_bps, DEFAULT_SEND_RATE_BPS);
        assert_eq!(config.interval_ms, DEFAULT_COVER_INTERVAL_MS);
        assert!(config.enabled);
    }

    #[test]
    fn test_cover_traffic_target_bytes() {
        let config = CoverTrafficConfig {
            target_rate_bps: 1000, // 1 KB/s
            interval_ms: 100,      // 100ms
            enabled: true,
        };
        let generator = CoverTrafficGenerator::new(config);

        // 1000 bytes/s * 100ms / 1000 = 100 bytes per interval
        assert_eq!(generator.target_bytes_per_interval(), 100);
    }

    #[test]
    fn test_cover_traffic_no_real_traffic() {
        let config = CoverTrafficConfig {
            target_rate_bps: 1000,
            interval_ms: 100,
            enabled: true,
        };
        let mut generator = CoverTrafficGenerator::new(config);

        // No real traffic, should generate full cover
        let cover = generator.generate_cover_traffic();
        assert_eq!(cover, 100);
        assert_eq!(generator.total_cover_bytes_sent, 100);
        assert_eq!(generator.total_real_bytes_sent, 0);
    }

    #[test]
    fn test_cover_traffic_with_real_traffic() {
        let config = CoverTrafficConfig {
            target_rate_bps: 1000,
            interval_ms: 100,
            enabled: true,
        };
        let mut generator = CoverTrafficGenerator::new(config);

        // Send 60 bytes of real traffic
        generator.record_real_traffic(60);

        // Should only generate 40 bytes of cover
        let cover = generator.generate_cover_traffic();
        assert_eq!(cover, 40);
        assert_eq!(generator.total_real_bytes_sent, 60);
        assert_eq!(generator.total_cover_bytes_sent, 40);
        assert_eq!(generator.total_bytes_sent, 100);
    }

    #[test]
    fn test_cover_traffic_real_exceeds_target() {
        let config = CoverTrafficConfig {
            target_rate_bps: 1000,
            interval_ms: 100,
            enabled: true,
        };
        let mut generator = CoverTrafficGenerator::new(config);

        // Send 150 bytes of real traffic (exceeds 100 byte target)
        generator.record_real_traffic(150);

        // Should generate 0 bytes of cover
        let cover = generator.generate_cover_traffic();
        assert_eq!(cover, 0);
        assert_eq!(generator.total_real_bytes_sent, 150);
        assert_eq!(generator.total_cover_bytes_sent, 0);
    }

    #[test]
    fn test_cover_traffic_interval_reset() {
        let config = CoverTrafficConfig {
            target_rate_bps: 1000,
            interval_ms: 100,
            enabled: true,
        };
        let mut generator = CoverTrafficGenerator::new(config);

        // Fill interval
        generator.record_real_traffic(50);
        let _ = generator.generate_cover_traffic();
        assert_eq!(generator.bytes_this_interval, 100);

        // Reset
        generator.reset_interval();
        assert_eq!(generator.bytes_this_interval, 0);
        assert_eq!(generator.total_bytes_sent, 100); // Total preserved
    }

    #[test]
    fn test_cover_traffic_stats() {
        let config = CoverTrafficConfig {
            target_rate_bps: 1000,
            interval_ms: 100,
            enabled: true,
        };
        let mut generator = CoverTrafficGenerator::new(config);

        generator.record_real_traffic(30);
        let _ = generator.generate_cover_traffic();

        let interval = generator.interval_stats();
        assert_eq!(interval.target_bytes, 100);
        assert_eq!(interval.real_bytes, 30);
        assert_eq!(interval.cover_bytes, 70);
        assert_eq!(interval.total_bytes, 100);

        let total = generator.total_stats();
        assert_eq!(total.total_bytes, 100);
        assert_eq!(total.total_real_bytes, 30);
        assert_eq!(total.total_cover_bytes, 70);
        assert_eq!(total.real_ratio, 0.3);
    }

    #[test]
    fn test_dummy_packet_generation() {
        let config = CoverTrafficConfig::default();
        let generator = CoverTrafficGenerator::new(config);

        let packet1 = generator.generate_dummy_packet(1024);
        let packet2 = generator.generate_dummy_packet(1024);

        assert_eq!(packet1.len(), 1024);
        assert_eq!(packet2.len(), 1024);
        // Two random packets should be different
        assert_ne!(packet1, packet2);
    }

    #[test]
    fn test_mesh_state_creation() {
        let state = MeshState::new();

        assert_ne!(state.node_id, [0u8; NODE_ID_SIZE]);
        assert_eq!(state.peer_count(), 0);
        assert!(state.cover_traffic.is_enabled());
    }

    #[test]
    fn test_mesh_state_with_node_id() {
        let node_id = random_node_id();
        let state = MeshState::with_node_id(node_id);

        assert_eq!(state.node_id, node_id);
    }

    #[test]
    fn test_mesh_add_remove_peer() {
        let mut state = MeshState::new();
        let peer_id = random_node_id();

        state.add_peer(peer_id, "127.0.0.1:8000".to_string());
        assert_eq!(state.peer_count(), 1);

        state.remove_peer(&peer_id);
        assert_eq!(state.peer_count(), 0);
    }

    #[test]
    fn test_mesh_connected_peers() {
        let mut state = MeshState::new();
        let peer1 = random_node_id();
        let peer2 = random_node_id();

        state.add_peer(peer1, "127.0.0.1:8001".to_string());
        state.add_peer(peer2, "127.0.0.1:8002".to_string());

        // Mark peer1 as connected
        state.get_peer_mut(&peer1).unwrap().mark_connected();

        let connected = state.connected_peers();
        assert_eq!(connected.len(), 1);
        assert_eq!(connected[0], peer1);
        assert_eq!(state.connected_count(), 1);
    }

    #[test]
    fn test_mesh_record_traffic() {
        let mut state = MeshState::new();
        let peer_id = random_node_id();

        state.add_peer(peer_id, "127.0.0.1:8000".to_string());
        state.record_sent(&peer_id, 1000);
        state.record_received(&peer_id, 500);

        let peer = state.get_peer(&peer_id).unwrap();
        assert_eq!(peer.bytes_sent, 1000);
        assert_eq!(peer.bytes_received, 500);

        // Cover traffic should have recorded the real traffic
        let stats = state.cover_traffic.total_stats();
        assert_eq!(stats.total_real_bytes, 1000);
    }

    #[test]
    fn test_mesh_prune_stale() {
        let mut state = MeshState::new();
        let peer1 = random_node_id();
        let peer2 = random_node_id();

        state.add_peer(peer1, "127.0.0.1:8001".to_string());
        state.add_peer(peer2, "127.0.0.1:8002".to_string());

        // Make peer2 stale
        state.get_peer_mut(&peer2).unwrap().last_seen =
            Instant::now() - Duration::from_secs(600);

        state.prune_stale_peers();

        assert!(state.peers.contains_key(&peer1));
        assert!(!state.peers.contains_key(&peer2));
    }
}
