//! Routing table and peer discovery for Static network
//!
//! Implements:
//! - Routing table for storing known nodes (public key, ID, address)
//! - Peer gossip protocol for exchanging known peers
//! - Route building for creating Sphinx paths
//! - Random node selection for anonymity
//!
//! The routing table is the foundation of the mixnet. Without knowing
//! other nodes' public keys, we cannot build Sphinx packets. The gossip
//! protocol ensures the network stays connected without central directories.

use static_sphinx::{Route, RouteHop, NodeId, MixNode};
use rand::seq::SliceRandom;
use std::collections::HashMap;

/// Maximum number of peers to gossip in a single message
pub const MAX_GOSSIP_PEERS: usize = 50;

/// A known node in the network
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct KnownNode {
    /// The node's ID
    pub node_id: NodeId,
    /// The node's public key (Montgomery point bytes, Sphinx)
    pub public_key: [u8; 32],
    /// The node's network address
    pub address: String,
    /// The node's ML-KEM-768 public key (for hybrid Sphinx)
    ///
    /// Learned via direct handshake. `None` for legacy peers or entries
    /// learned via gossip (gossip strips KEM keys to bound message size).
    #[serde(default)]
    pub kem_public_key: Option<Vec<u8>>,
    /// Whether this node accepts compute requests
    ///
    /// Learned via direct handshake or gossip.
    #[serde(default)]
    pub compute_enabled: bool,
    /// Maximum concurrent compute executions on this node
    #[serde(default)]
    pub compute_capacity: u8,
    /// Ed25519 identity public key (handshake authentication, gossip continuity)
    #[serde(default)]
    pub identity_public_key: Option<[u8; 32]>,
}

/// Peer gossip message (authenticated sender, unauthenticated hints)
///
/// The sender signs (from_node || blake3(peers_json)) with its Ed25519
/// identity key. Receivers verify the sender signature and apply key
/// continuity: a known node_id whose mix or identity key changes is
/// rejected (prevents hijack/overwrite). Gossiped peer entries themselves
/// are hints, not trust anchors.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PeerGossip {
    /// The sending node's ID
    pub from_node: NodeId,
    /// The peers being gossiped
    pub peers: Vec<KnownNode>,
    /// Ed25519 identity public key of the gossip sender
    #[serde(default)]
    pub identity_public_key: [u8; 32],
    /// Ed25519 signature over the gossip signing bytes
    #[serde(default)]
    pub signature: Vec<u8>,
}

impl PeerGossip {
    /// Bytes covered by the gossip signature.
    pub fn signing_bytes(&self) -> Vec<u8> {
        let peers_json = serde_json::to_vec(&self.peers).unwrap_or_default();
        let digest = blake3::hash(&peers_json);
        let mut buf = Vec::with_capacity(16 + 32);
        buf.extend_from_slice(&self.from_node);
        buf.extend_from_slice(digest.as_bytes());
        buf
    }

    /// Sign this gossip message.
    pub fn sign(&mut self, signing_key: &ed25519_dalek::SigningKey) {
        use ed25519_dalek::Signer;
        self.identity_public_key = signing_key.verifying_key().to_bytes();
        let sig = signing_key.sign(&self.signing_bytes());
        self.signature = sig.to_bytes().to_vec();
    }

    /// Verify sender signature (+ peer-count bound).
    pub fn verify(&self) -> bool {
        use ed25519_dalek::{Signature, Verifier, VerifyingKey};
        if self.peers.len() > MAX_GOSSIP_PEERS {
            return false;
        }
        if self.signature.len() != 64 {
            return false;
        }
        let Ok(pk) = VerifyingKey::from_bytes(&self.identity_public_key) else {
            return false;
        };
        let mut arr = [0u8; 64];
        arr.copy_from_slice(&self.signature);
        let sig = Signature::from_bytes(&arr);
        pk.verify(&self.signing_bytes(), &sig).is_ok()
    }
}

/// Routing table for storing known nodes
#[derive(Debug, Clone)]
pub struct RoutingTable {
    /// This node's ID
    pub our_node_id: NodeId,
    /// Known nodes (node_id -> KnownNode)
    pub nodes: HashMap<NodeId, KnownNode>,
}

impl RoutingTable {
    /// Create a new routing table
    pub fn new(our_node_id: NodeId) -> Self {
        Self {
            our_node_id,
            nodes: HashMap::new(),
        }
    }

    /// Add or update a node in the routing table
    pub fn add_node(&mut self, node: KnownNode) {
        // Don't add ourselves
        if node.node_id != self.our_node_id {
            self.nodes.insert(node.node_id, node);
        }
    }

    /// Remove a node from the routing table
    pub fn remove_node(&mut self, node_id: &NodeId) {
        self.nodes.remove(node_id);
    }

    /// Get a node by ID
    pub fn get_node(&self, node_id: &NodeId) -> Option<&KnownNode> {
        self.nodes.get(node_id)
    }

    /// Get all known node IDs
    pub fn known_ids(&self) -> Vec<NodeId> {
        self.nodes.keys().cloned().collect()
    }

    /// Get the number of known nodes
    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    /// Select N random nodes for a route (excluding ourselves)
    ///
    /// Returns None if there aren't enough nodes.
    pub fn random_route(&self, hop_count: usize) -> Option<Vec<KnownNode>> {
        if self.nodes.len() < hop_count {
            return None;
        }

        let mut nodes: Vec<&KnownNode> = self.nodes.values().collect();
        nodes.shuffle(&mut rand::thread_rng());

        Some(nodes.into_iter().take(hop_count).cloned().collect())
    }

    /// Build a Sphinx Route to a specific destination
    ///
    /// Selects `hop_count` random intermediate nodes and appends the
    /// destination as the final hop.
    pub fn build_route_to(
        &self,
        destination: NodeId,
        dest_public_key: [u8; 32],
        hop_count: usize,
    ) -> Option<Route> {
        let intermediates = self.random_route(hop_count)?;

        let mut hops: Vec<RouteHop> = intermediates
            .iter()
            .map(|n| RouteHop {
                public_key: n.public_key,
                node_id: n.node_id,
            })
            .collect();

        // Add the destination as the final hop
        hops.push(RouteHop {
            public_key: dest_public_key,
            node_id: destination,
        });

        Some(Route {
            hops,
            destination,
        })
    }

    /// Build a random route with no specific destination
    /// (useful for cover traffic that just needs to die in the network)
    pub fn build_cover_route(&self, hop_count: usize) -> Option<Route> {
        let nodes = self.random_route(hop_count)?;
        
        let hops: Vec<RouteHop> = nodes
            .iter()
            .map(|n| RouteHop {
                public_key: n.public_key,
                node_id: n.node_id,
            })
            .collect();

        // The last node is the destination (it will just drop the packet)
        let destination = nodes.last()?.node_id;

        Some(Route {
            hops,
            destination,
        })
    }

    /// Create a gossip message containing a random sample of known peers
    ///
    /// KEM public keys are stripped from gossiped entries to bound message
    /// size (each ML-KEM key is ~1 KiB). KEM keys propagate via direct
    /// handshake only; hybrid routes use handshake-known peers.
    /// Unsigned (for tests/back-compat); use `create_signed_gossip` in prod.
    pub fn create_gossip(&self, max_peers: usize) -> PeerGossip {
        let mut unsigned = self.unsigned_gossip(max_peers);
        // Leave unsigned: verify() will fail, callers must sign.
        let _ = &mut unsigned;
        unsigned
    }

    /// Create and Ed25519-sign a gossip message.
    pub fn create_signed_gossip(
        &self,
        max_peers: usize,
        signing_key: &ed25519_dalek::SigningKey,
    ) -> PeerGossip {
        let mut g = self.unsigned_gossip(max_peers);
        g.sign(signing_key);
        g
    }

    fn unsigned_gossip(&self, max_peers: usize) -> PeerGossip {
        let mut nodes: Vec<&KnownNode> = self.nodes.values().collect();
        nodes.shuffle(&mut rand::thread_rng());

        let peers: Vec<KnownNode> = nodes
            .into_iter()
            .take(max_peers.min(MAX_GOSSIP_PEERS))
            .map(|n| {
                let mut stripped = n.clone();
                stripped.kem_public_key = None;
                stripped
            })
            .collect();

        PeerGossip {
            from_node: self.our_node_id,
            peers,
            identity_public_key: [0u8; 32],
            signature: vec![],
        }
    }

    /// Build a hybrid Sphinx route to a destination
    ///
    /// Returns `None` unless every hop (intermediates plus destination)
    /// has a known ML-KEM public key. Callers fall back to classical
    /// [`RoutingTable::build_route_to`] when hybrid is unavailable, which
    /// is what keeps mixed-version networks working.
    pub fn build_hybrid_route_to(
        &self,
        destination: NodeId,
        dest_public_key: [u8; 32],
        dest_kem_public_key: &[u8],
        hop_count: usize,
    ) -> Option<static_sphinx::HybridRoute> {
        let intermediates = self.random_route(hop_count)?;
        for n in &intermediates {
            if n.kem_public_key.is_none() {
                return None;
            }
        }

        let mut hops: Vec<static_sphinx::HybridRouteHop> = intermediates
            .iter()
            .map(|n| static_sphinx::HybridRouteHop {
                node_id: n.node_id,
                classical_public_key: n.public_key,
                kem_public_key: n.kem_public_key.clone().unwrap_or_default(),
            })
            .collect();

        hops.push(static_sphinx::HybridRouteHop {
            node_id: destination,
            classical_public_key: dest_public_key,
            kem_public_key: dest_kem_public_key.to_vec(),
        });

        Some(static_sphinx::HybridRoute { hops, destination })
    }

    /// Process a received gossip message, adding new peers to our table
    ///
    /// Verifies the sender signature first; unverified gossip is dropped.
    /// Enforces key continuity: a known node_id with changed mix or
    /// identity keys is rejected (no overwrite). Returns new peers added.
    pub fn process_gossip(&mut self, gossip: &PeerGossip) -> usize {
        if !gossip.verify() {
            return 0;
        }
        // Sender key continuity: if we know the sender, its identity key
        // must match (prevents impersonation after first encounter).
        if let Some(known) = self.nodes.get(&gossip.from_node) {
            if let Some(stored) = known.identity_public_key {
                if stored != gossip.identity_public_key {
                    return 0;
                }
            }
        }
        let mut new_count = 0;
        for peer in &gossip.peers {
            if peer.node_id == self.our_node_id || self.nodes.contains_key(&peer.node_id) {
                continue;
            }
            // Bound per-entry sanity.
            if peer.address.len() > 256 {
                continue;
            }
            if let Some(kem) = &peer.kem_public_key {
                if kem.len() != static_sphinx::HYBRID_KEM_PUBLIC_KEY_SIZE {
                    continue;
                }
            }
            self.add_node(peer.clone());
            new_count += 1;
        }
        new_count
    }

    /// Create a KnownNode from a MixNode
    pub fn node_from_mix(node: &MixNode, address: String) -> KnownNode {
        KnownNode {
            node_id: node.node_id,
            public_key: node.public_key,
            address,
            kem_public_key: None,
            compute_enabled: false,
            compute_capacity: 0,
            identity_public_key: None,
        }
    }

    /// Create a KnownNode from a MixNode plus a KEM public key
    pub fn node_from_mix_hybrid(
        node: &MixNode,
        kem_public_key: Vec<u8>,
        address: String,
    ) -> KnownNode {
        KnownNode {
            node_id: node.node_id,
            public_key: node.public_key,
            address,
            kem_public_key: Some(kem_public_key),
            compute_enabled: false,
            compute_capacity: 0,
            identity_public_key: None,
        }
    }
}

/// Errors that can occur during routing operations
#[derive(Debug, thiserror::Error)]
pub enum RoutingError {
    /// Not enough known nodes to build a route
    #[error("not enough known nodes: have {have}, need {need}")]
    NotEnoughNodes {
        /// Nodes available
        have: usize,
        /// Nodes required
        need: usize,
    },
    /// Node not found
    #[error("node not found: {0:?}")]
    NodeNotFound(NodeId),
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::RngCore;

    fn random_node_id() -> NodeId {
        let mut id = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut id);
        id
    }

    fn random_known_node() -> KnownNode {
        let mut pub_key = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut pub_key);
        KnownNode {
            node_id: random_node_id(),
            public_key: pub_key,
            address: "127.0.0.1:9000".to_string(),
            kem_public_key: None,
            compute_enabled: false,
            compute_capacity: 0,
            identity_public_key: None,
        }
    }

    fn test_signing_key() -> ed25519_dalek::SigningKey {
        ed25519_dalek::SigningKey::from_bytes(&[0x11u8; 32])
    }

    #[test]
    fn test_routing_table_creation() {
        let our_id = random_node_id();
        let table = RoutingTable::new(our_id);
        assert_eq!(table.our_node_id, our_id);
        assert_eq!(table.node_count(), 0);
    }

    #[test]
    fn test_add_remove_node() {
        let our_id = random_node_id();
        let mut table = RoutingTable::new(our_id);
        let node = random_known_node();

        table.add_node(node.clone());
        assert_eq!(table.node_count(), 1);

        table.remove_node(&node.node_id);
        assert_eq!(table.node_count(), 0);
    }

    #[test]
    fn test_dont_add_ourselves() {
        let our_id = random_node_id();
        let mut table = RoutingTable::new(our_id);
        let node = KnownNode {
            node_id: our_id,
            public_key: [0u8; 32],
            address: "127.0.0.1:9000".to_string(),
            kem_public_key: None,
                compute_enabled: false,
                compute_capacity: 0,
                identity_public_key: None,
        };

        table.add_node(node);
        assert_eq!(table.node_count(), 0);
    }

    #[test]
    fn test_random_route() {
        let our_id = random_node_id();
        let mut table = RoutingTable::new(our_id);

        for _ in 0..10 {
            table.add_node(random_known_node());
        }

        let route = table.random_route(3).unwrap();
        assert_eq!(route.len(), 3);

        // Should be different nodes
        assert_ne!(route[0].node_id, route[1].node_id);
        assert_ne!(route[1].node_id, route[2].node_id);
    }

    #[test]
    fn test_random_route_not_enough_nodes() {
        let our_id = random_node_id();
        let mut table = RoutingTable::new(our_id);

        for _ in 0..2 {
            table.add_node(random_known_node());
        }

        let result = table.random_route(3);
        assert!(result.is_none());
    }

    #[test]
    fn test_build_route_to_destination() {
        let our_id = random_node_id();
        let mut table = RoutingTable::new(our_id);

        for _ in 0..5 {
            table.add_node(random_known_node());
        }

        let dest_id = random_node_id();
        let dest_pubkey = [0xFFu8; 32];

        let route = table.build_route_to(dest_id, dest_pubkey, 3).unwrap();

        assert_eq!(route.hops.len(), 4); // 3 intermediate + 1 destination
        assert_eq!(route.destination, dest_id);
        assert_eq!(route.hops.last().unwrap().node_id, dest_id);
        assert_eq!(route.hops.last().unwrap().public_key, dest_pubkey);
    }

    #[test]
    fn test_build_cover_route() {
        let our_id = random_node_id();
        let mut table = RoutingTable::new(our_id);

        for _ in 0..5 {
            table.add_node(random_known_node());
        }

        let route = table.build_cover_route(3).unwrap();

        assert_eq!(route.hops.len(), 3);
        // Destination should be the last node in the route
        assert_eq!(route.destination, route.hops.last().unwrap().node_id);
    }

    #[test]
    fn test_gossip_creation() {
        let our_id = random_node_id();
        let mut table = RoutingTable::new(our_id);

        for _ in 0..100 {
            table.add_node(random_known_node());
        }

        let gossip = table.create_gossip(20);
        assert_eq!(gossip.from_node, our_id);
        assert!(gossip.peers.len() <= 20);
    }

    #[test]
    fn test_process_gossip() {
        let our_id = random_node_id();
        let mut table1 = RoutingTable::new(our_id);
        let mut table2 = RoutingTable::new(random_node_id());

        // Table 1 knows 10 nodes
        for _ in 0..10 {
            table1.add_node(random_known_node());
        }

        // Table 2 knows 5 different nodes
        for _ in 0..5 {
            table2.add_node(random_known_node());
        }

        // Table 1 gossips to Table 2 (signed)
        let gossip = table1.create_signed_gossip(50, &test_signing_key());
        assert!(gossip.verify());
        let new_count = table2.process_gossip(&gossip);

        // Table 2 should have learned 10 new nodes (minus any overlap)
        assert!(new_count <= 10);
        assert_eq!(table2.node_count(), 5 + new_count);
    }

    #[test]
    fn test_gossip_no_duplicates() {
        let our_id = random_node_id();
        let mut table = RoutingTable::new(our_id.clone());

        let node = random_known_node();
        table.add_node(node.clone());

        let mut gossip = PeerGossip {
            from_node: random_node_id(),
            peers: vec![node.clone()],
            identity_public_key: [0u8; 32],
            signature: vec![],
        };
        gossip.sign(&test_signing_key());

        let new_count = table.process_gossip(&gossip);
        assert_eq!(new_count, 0); // Already knew this node
        assert_eq!(table.node_count(), 1);
    }

    #[test]
    fn test_gossip_doesnt_add_ourselves() {
        let our_id = random_node_id();
        let mut table = RoutingTable::new(our_id);

        let mut gossip = PeerGossip {
            from_node: random_node_id(),
            peers: vec![KnownNode {
                node_id: our_id,
                public_key: [0u8; 32],
                address: "127.0.0.1:9000".to_string(),
                kem_public_key: None,
                compute_enabled: false,
                compute_capacity: 0,
                identity_public_key: None,
            }],
            identity_public_key: [0u8; 32],
            signature: vec![],
        };
        gossip.sign(&test_signing_key());

        let new_count = table.process_gossip(&gossip);
        assert_eq!(new_count, 0);
        assert_eq!(table.node_count(), 0);
    }

    #[test]
    fn test_node_from_mix() {
        let mix = MixNode::new();
        let known = RoutingTable::node_from_mix(&mix, "127.0.0.1:9000".to_string());

        assert_eq!(known.node_id, mix.node_id);
        assert_eq!(known.public_key, mix.public_key);
    }

    #[test]
    fn test_multiple_routes_different() {
        let our_id = random_node_id();
        let mut table = RoutingTable::new(our_id);

        for _ in 0..20 {
            table.add_node(random_known_node());
        }

        let route1 = table.random_route(5).unwrap();
        let route2 = table.random_route(5).unwrap();

        // Should likely be different (probability of same is 1/15504)
        // We check at least the first node differs
        assert_ne!(route1[0].node_id, route2[0].node_id);
    }

    #[test]
    fn test_known_ids() {
        let our_id = random_node_id();
        let mut table = RoutingTable::new(our_id);

        let node1 = random_known_node();
        let node2 = random_known_node();
        table.add_node(node1.clone());
        table.add_node(node2.clone());

        let ids = table.known_ids();
        assert_eq!(ids.len(), 2);
        assert!(ids.contains(&node1.node_id));
        assert!(ids.contains(&node2.node_id));
    }

    #[test]
    fn test_gossip_strips_kem_keys() {
        let our_id = random_node_id();
        let mut table = RoutingTable::new(our_id);

        let mut node = random_known_node();
        node.kem_public_key = Some(vec![0xAAu8; 1184]);
        table.add_node(node);

        let gossip = table.create_gossip(10);
        assert_eq!(gossip.peers.len(), 1);
        assert!(gossip.peers[0].kem_public_key.is_none());
        // Local table retains the key.
        assert!(table.nodes.values().next().unwrap().kem_public_key.is_some());
    }

    #[test]
    fn test_build_hybrid_route_requires_kem_keys() {
        use static_crypto::KemKeypair;

        let dest_kem = KemKeypair::random().public_bytes();

        // Table with only a KEM-less peer: hybrid unavailable.
        let mut classical_only = RoutingTable::new(random_node_id());
        let mut plain = random_known_node();
        plain.node_id = [0x01u8; 16];
        classical_only.add_node(plain);
        assert!(classical_only
            .build_hybrid_route_to([0xFFu8; 16], [0xEEu8; 32], &dest_kem, 1)
            .is_none());
        // Classical route still works (backward compat).
        assert!(classical_only
            .build_route_to([0xFFu8; 16], [0xEEu8; 32], 1)
            .is_some());

        // Table where every peer has a KEM key: hybrid route builds.
        let mut hybrid_table = RoutingTable::new(random_node_id());
        for i in 0..3u8 {
            let mut keyed = random_known_node();
            keyed.node_id = [i + 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
            keyed.kem_public_key = Some(KemKeypair::random().public_bytes());
            hybrid_table.add_node(keyed);
        }
        let hybrid = hybrid_table
            .build_hybrid_route_to([0xFFu8; 16], [0xEEu8; 32], &dest_kem, 2)
            .unwrap();
        assert_eq!(hybrid.hops.len(), 3); // 2 intermediates + destination
        assert!(hybrid
            .hops
            .iter()
            .all(|h| h.kem_public_key.len() == 1184));
    }
}
