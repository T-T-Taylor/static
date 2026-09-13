//! static-sphinx - Sphinx packet format and mixnet logic

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use static_crypto::SymmetricKey;
use blake3;
use curve25519_dalek::montgomery::MontgomeryPoint;
use curve25519_dalek::scalar::Scalar;
use rand::rngs::OsRng;
use rand::RngCore;
use std::collections::HashSet;

/// Maximum number of hops in a route
pub const MAX_HOPS: usize = 5;

/// Size of a node ID in bytes
pub const NODE_ID_SIZE: usize = 16;

/// Size of routing flags in bytes
pub const FLAG_SIZE: usize = 1;

/// Size of a MAC in bytes
pub const MAC_SIZE: usize = 16;

/// Size of a routing slot in bytes
pub const SLOT_SIZE: usize = NODE_ID_SIZE + FLAG_SIZE + MAC_SIZE;

/// Total routing info size in bytes
pub const ROUTING_INFO_SIZE: usize = MAX_HOPS * SLOT_SIZE;

/// Size of the ephemeral key in bytes
pub const EPHEMERAL_KEY_SIZE: usize = 32;

/// Total header size
pub const HEADER_SIZE: usize = EPHEMERAL_KEY_SIZE + ROUTING_INFO_SIZE + MAC_SIZE;

/// Fixed body size in bytes
pub const BODY_SIZE: usize = 1024;

/// The Montgomery curve base point (u = 9)
const BASE_POINT: MontgomeryPoint = MontgomeryPoint([
    9, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0,
]);

/// A node ID (16 bytes)
pub type NodeId = [u8; NODE_ID_SIZE];

/// A MAC (16 bytes)
pub type Mac = [u8; MAC_SIZE];

/// A public key (32 bytes, Montgomery point)
pub type PubKeyBytes = [u8; 32];

/// Routing flags for a hop
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoutingFlag {
    /// Forward to the next mix node
    Forward = 0,
    /// This is the final destination
    Destination = 1,
}

impl TryFrom<u8> for RoutingFlag {
    type Error = SphinxError;
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(RoutingFlag::Forward),
            1 => Ok(RoutingFlag::Destination),
            _ => Err(SphinxError::InvalidRoutingFlag),
        }
    }
}

/// A hop in a route
#[derive(Debug, Clone)]
pub struct RouteHop {
    /// The mix node's public key (Montgomery point bytes)
    pub public_key: PubKeyBytes,
    /// The mix node's ID
    pub node_id: NodeId,
}

/// A route through the network
#[derive(Debug, Clone)]
pub struct Route {
    /// The mix nodes in order
    pub hops: Vec<RouteHop>,
    /// The final destination ID
    pub destination: NodeId,
}

/// A Sphinx packet header
#[derive(Debug, Clone)]
pub struct SphinxHeader {
    /// The ephemeral public key (blinded at each hop)
    pub ephemeral_key: [u8; EPHEMERAL_KEY_SIZE],
    /// The encrypted routing information
    pub routing_info: Vec<u8>,
    /// The MAC over (ephemeral_key || first_encrypted_slot)
    pub mac: Mac,
}

/// A Sphinx packet
#[derive(Debug, Clone)]
pub struct SphinxPacket {
    /// The packet header
    pub header: SphinxHeader,
    /// The encrypted body
    pub body: Vec<u8>,
}

/// Result of processing a packet at a mix node
#[derive(Debug)]
pub struct ProcessedPacket {
    /// The next hop's node ID
    pub next_hop: NodeId,
    /// The routing flag
    pub flag: RoutingFlag,
    /// The packet to forward (None if destination)
    pub forward_packet: Option<SphinxPacket>,
    /// The decrypted body (Some only at destination)
    pub body: Option<Vec<u8>>,
}

/// A mix node in the network
pub struct MixNode {
    /// The node's private key (scalar)
    pub private_key: Scalar,
    /// The node's public key (Montgomery point bytes)
    pub public_key: PubKeyBytes,
    /// The node's ID
    pub node_id: NodeId,
    /// Set of seen replay tags
    pub seen_tags: HashSet<[u8; MAC_SIZE]>,
}

/// Errors that can occur during Sphinx operations
#[derive(Debug, thiserror::Error)]
pub enum SphinxError {
    /// MAC verification failed
    #[error("MAC verification failed")]
    MacVerificationFailed,
    /// Replay detected
    #[error("replay detected")]
    ReplayDetected,
    /// Invalid packet size
    #[error("invalid packet size")]
    InvalidPacketSize,
    /// Invalid routing flag
    #[error("invalid routing flag")]
    InvalidRoutingFlag,
    /// Route too long
    #[error("route too long")]
    RouteTooLong,
    /// Body too large
    #[error("body too large")]
    BodyTooLarge,
}

// ---- Internal key derivation ----

struct HopKeys {
    stream_key: SymmetricKey,
    mac_key: SymmetricKey,
    body_key: SymmetricKey,
    tag: [u8; MAC_SIZE],
}

fn derive_hop_keys(shared: &SymmetricKey) -> HopKeys {
    let stream_key = shared.derive("sphinx/stream");
    let mac_key = shared.derive("sphinx/mac");
    let body_key = shared.derive("sphinx/body");
    let tag_key = shared.derive("sphinx/tag");
    let mut tag = [0u8; MAC_SIZE];
    tag.copy_from_slice(&tag_key.bytes[..MAC_SIZE]);
    HopKeys { stream_key, mac_key, body_key, tag }
}

// ---- MAC ----

fn compute_mac(mac_key: &SymmetricKey, ephemeral_key: &[u8], slot: &[u8]) -> Mac {
    let derived = mac_key.derive("sphinx/mac/compute");
    let mut input = Vec::with_capacity(ephemeral_key.len() + slot.len());
    input.extend_from_slice(ephemeral_key);
    input.extend_from_slice(slot);
    let hash = blake3::keyed_hash(&derived.bytes, &input);
    let mut mac = [0u8; MAC_SIZE];
    mac.copy_from_slice(&hash.as_bytes()[..MAC_SIZE]);
    mac
}

// ---- Slot encryption (XOR-based stream cipher) ----

fn slot_keystream(key: &SymmetricKey) -> [u8; SLOT_SIZE] {
    let block1 = key.derive("sphinx/slot:0");
    let block2 = key.derive("sphinx/slot:1");
    let mut keystream = [0u8; SLOT_SIZE];
    keystream[..32].copy_from_slice(&block1.bytes);
    keystream[32] = block2.bytes[0];
    keystream
}

fn xor_slot(key: &SymmetricKey, slot: &mut [u8; SLOT_SIZE]) {
    let keystream = slot_keystream(key);
    for i in 0..SLOT_SIZE {
        slot[i] ^= keystream[i];
    }
}

// ---- Body encryption (XOR-based stream cipher) ----

fn body_keystream(key: &SymmetricKey) -> Vec<u8> {
    let mut keystream = Vec::with_capacity(BODY_SIZE);
    let mut counter = 0u64;
    while keystream.len() < BODY_SIZE {
        let block = key.derive(&format!("sphinx/body:{}", counter));
        keystream.extend_from_slice(&block.bytes);
        counter += 1;
    }
    keystream.truncate(BODY_SIZE);
    keystream
}

fn xor_body(key: &SymmetricKey, body: &mut [u8]) {
    let keystream = body_keystream(key);
    for (i, byte) in body.iter_mut().enumerate() {
        *byte ^= keystream[i];
    }
}

// ---- Ephemeral key blinding ----

fn blinding_factor(shared: &SymmetricKey) -> Scalar {
    let blind_key = shared.derive("sphinx/blind");
    Scalar::from_bytes_mod_order(blind_key.bytes)
}

// ---- Random helpers ----

fn random_bytes(len: usize) -> Vec<u8> {
    let mut bytes = vec![0u8; len];
    OsRng.fill_bytes(&mut bytes);
    bytes
}

fn random_node_id() -> NodeId {
    let mut id = [0u8; NODE_ID_SIZE];
    OsRng.fill_bytes(&mut id);
    id
}

fn random_scalar() -> Scalar {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    Scalar::from_bytes_mod_order(bytes)
}

// ---- Public API: Packet creation ----

/// Create a Sphinx packet for a route.
///
/// Uses non-clamped scalar multiplication on Curve25519 for
/// correct ephemeral key blinding across multiple hops.
pub fn create_packet(route: &Route, body: &[u8]) -> Result<SphinxPacket, SphinxError> {
    let n = route.hops.len();
    if n == 0 || n > MAX_HOPS {
        return Err(SphinxError::RouteTooLong);
    }
    if body.len() > BODY_SIZE {
        return Err(SphinxError::BodyTooLarge);
    }

    // Generate ephemeral scalar and public key
    let ephemeral_scalar = random_scalar();
    let ephemeral_pub = (&BASE_POINT * &ephemeral_scalar).0;

    // Compute shared secrets with running scalar blinding
    let mut hop_keys = Vec::with_capacity(n);
    let mut alphas = Vec::with_capacity(n);
    let mut current_alpha = ephemeral_pub;
    let mut current_scalar = ephemeral_scalar.clone();

    for i in 0..n {
        // shared = current_scalar * hop_pubkey_point
        let pub_point = MontgomeryPoint(route.hops[i].public_key);
        let shared_point = &pub_point * &current_scalar;
        let shared = SymmetricKey::from_bytes(shared_point.0);
        let keys = derive_hop_keys(&shared);
        hop_keys.push(keys);

        alphas.push(current_alpha);

        if i < n - 1 {
            let blind = blinding_factor(&shared);
            current_scalar = &current_scalar * &blind;
            let alpha_point = MontgomeryPoint(current_alpha);
            current_alpha = (&alpha_point * &blind).0;
        }
    }

    // Build routing blocks and compute MACs from last hop to first
    let mut blocks: Vec<[u8; SLOT_SIZE]> = vec![[0u8; SLOT_SIZE]; n];
    let mut enc_blocks: Vec<[u8; SLOT_SIZE]> = vec![[0u8; SLOT_SIZE]; n];
    let mut macs: Vec<Mac> = vec![[0u8; MAC_SIZE]; n];

    for i in (0..n).rev() {
        if i == n - 1 {
            blocks[i][..NODE_ID_SIZE].copy_from_slice(&route.destination);
            blocks[i][NODE_ID_SIZE] = RoutingFlag::Destination as u8;
        } else {
            blocks[i][..NODE_ID_SIZE].copy_from_slice(&route.hops[i + 1].node_id);
            blocks[i][NODE_ID_SIZE] = RoutingFlag::Forward as u8;
            blocks[i][NODE_ID_SIZE + FLAG_SIZE..].copy_from_slice(&macs[i + 1]);
        }

        enc_blocks[i] = blocks[i];
        xor_slot(&hop_keys[i].stream_key, &mut enc_blocks[i]);
        macs[i] = compute_mac(&hop_keys[i].mac_key, &alphas[i], &enc_blocks[i]);
    }

    // Build routing info with padding
    let mut routing_info = vec![0u8; ROUTING_INFO_SIZE];
    for i in 0..n {
        routing_info[i * SLOT_SIZE..(i + 1) * SLOT_SIZE].copy_from_slice(&enc_blocks[i]);
    }
    routing_info[n * SLOT_SIZE..].copy_from_slice(&random_bytes(ROUTING_INFO_SIZE - n * SLOT_SIZE));

    // Build body: pad to BODY_SIZE, encrypt in layers
    let mut body_bytes = vec![0u8; BODY_SIZE];
    body_bytes[..body.len()].copy_from_slice(body);
    for i in (0..n).rev() {
        xor_body(&hop_keys[i].body_key, &mut body_bytes);
    }

    let header = SphinxHeader {
        ephemeral_key: alphas[0],
        routing_info,
        mac: macs[0],
    };

    Ok(SphinxPacket { header, body: body_bytes })
}

// ---- Public API: Packet processing ----

/// Process a Sphinx packet at a mix node.
///
/// Uses non-clamped scalar multiplication to match the sender's
/// blinding computation.
pub fn process_packet(node: &mut MixNode, packet: SphinxPacket) -> Result<ProcessedPacket, SphinxError> {
    if packet.header.routing_info.len() != ROUTING_INFO_SIZE {
        return Err(SphinxError::InvalidPacketSize);
    }
    if packet.body.len() != BODY_SIZE {
        return Err(SphinxError::InvalidPacketSize);
    }

    // Compute shared secret: private_key * ephemeral_pub
    let alpha_point = MontgomeryPoint(packet.header.ephemeral_key);
    let shared_point = &alpha_point * &node.private_key;
    let shared = SymmetricKey::from_bytes(shared_point.0);
    let keys = derive_hop_keys(&shared);

    // Check replay
    if node.seen_tags.contains(&keys.tag) {
        return Err(SphinxError::ReplayDetected);
    }
    node.seen_tags.insert(keys.tag);

    // Verify MAC
    let first_slot: &[u8; SLOT_SIZE] = packet.header.routing_info[..SLOT_SIZE]
        .try_into()
        .map_err(|_| SphinxError::InvalidPacketSize)?;
    let expected_mac = compute_mac(&keys.mac_key, &packet.header.ephemeral_key, first_slot);
    if packet.header.mac != expected_mac {
        return Err(SphinxError::MacVerificationFailed);
    }

    // Decrypt first routing block
    let mut block = *first_slot;
    xor_slot(&keys.stream_key, &mut block);

    let mut next_hop = [0u8; NODE_ID_SIZE];
    next_hop.copy_from_slice(&block[..NODE_ID_SIZE]);
    let flag = RoutingFlag::try_from(block[NODE_ID_SIZE])?;
    let mut next_mac = [0u8; MAC_SIZE];
    next_mac.copy_from_slice(&block[NODE_ID_SIZE + FLAG_SIZE..]);

    // Shift routing info left, fill with random padding
    let mut new_routing_info = vec![0u8; ROUTING_INFO_SIZE];
    new_routing_info[..ROUTING_INFO_SIZE - SLOT_SIZE]
        .copy_from_slice(&packet.header.routing_info[SLOT_SIZE..]);
    new_routing_info[ROUTING_INFO_SIZE - SLOT_SIZE..]
        .copy_from_slice(&random_bytes(SLOT_SIZE));

    // Blind ephemeral key for next hop
    let blind = blinding_factor(&shared);
    let new_ephemeral = (&alpha_point * &blind).0;

    // Peel one body encryption layer
    let mut new_body = packet.body;
    xor_body(&keys.body_key, &mut new_body);

    match flag {
        RoutingFlag::Destination => {
            Ok(ProcessedPacket {
                next_hop,
                flag,
                forward_packet: None,
                body: Some(new_body),
            })
        }
        RoutingFlag::Forward => {
            let forward_header = SphinxHeader {
                ephemeral_key: new_ephemeral,
                routing_info: new_routing_info,
                mac: next_mac,
            };
            let forward_packet = SphinxPacket {
                header: forward_header,
                body: new_body,
            };
            Ok(ProcessedPacket {
                next_hop,
                flag,
                forward_packet: Some(forward_packet),
                body: None,
            })
        }
    }
}

// ---- MixNode implementation ----

impl MixNode {
    /// Create a new mix node with random keys and random node ID
    pub fn new() -> Self {
        let private_key = random_scalar();
        let public_key = (&BASE_POINT * &private_key).0;
        let node_id = random_node_id();
        Self {
            private_key,
            public_key,
            node_id,
            seen_tags: HashSet::new(),
        }
    }

    /// Create a mix node from a private key scalar and node ID
    pub fn from_private_key(private_key_bytes: [u8; 32], node_id: NodeId) -> Self {
        let private_key = Scalar::from_bytes_mod_order(private_key_bytes);
        let public_key = (&BASE_POINT * &private_key).0;
        Self {
            private_key,
            public_key,
            node_id,
            seen_tags: HashSet::new(),
        }
    }
}

impl Default for MixNode {
    fn default() -> Self {
        Self::new()
    }
}

// ---- Tests ----

#[cfg(test)]
mod tests {
    use super::*;

    fn create_route(n: usize) -> (Vec<MixNode>, Route) {
        let mut nodes = Vec::with_capacity(n);
        let mut hops = Vec::with_capacity(n);
        for _ in 0..n {
            let node = MixNode::new();
            hops.push(RouteHop {
                public_key: node.public_key,
                node_id: node.node_id,
            });
            nodes.push(node);
        }
        let destination = random_node_id();
        let route = Route { hops, destination };
        (nodes, route)
    }

    #[test]
    fn test_single_hop() {
        let (mut nodes, route) = create_route(1);
        let body = b"hello world";
        let packet = create_packet(&route, body).unwrap();

        let result = process_packet(&mut nodes[0], packet).unwrap();

        assert_eq!(result.flag, RoutingFlag::Destination);
        assert_eq!(result.next_hop, route.destination);
        assert!(result.forward_packet.is_none());
        assert!(result.body.is_some());

        let decrypted = result.body.unwrap();
        assert_eq!(&decrypted[..body.len()], body);
    }

    #[test]
    fn test_multi_hop() {
        let (mut nodes, route) = create_route(3);
        let body = b"multi hop test message";
        let packet = create_packet(&route, body).unwrap();

        let result0 = process_packet(&mut nodes[0], packet).unwrap();
        assert_eq!(result0.flag, RoutingFlag::Forward);
        assert_eq!(result0.next_hop, nodes[1].node_id);

        let result1 = process_packet(&mut nodes[1], result0.forward_packet.unwrap()).unwrap();
        assert_eq!(result1.flag, RoutingFlag::Forward);
        assert_eq!(result1.next_hop, nodes[2].node_id);

        let result2 = process_packet(&mut nodes[2], result1.forward_packet.unwrap()).unwrap();
        assert_eq!(result2.flag, RoutingFlag::Destination);
        assert_eq!(result2.next_hop, route.destination);

        let decrypted = result2.body.unwrap();
        assert_eq!(&decrypted[..body.len()], body);
    }

    #[test]
    fn test_max_hops() {
        let (mut nodes, route) = create_route(MAX_HOPS);
        let body = b"max hops test";
        let packet = create_packet(&route, body).unwrap();

        let mut current_packet = packet;
        for i in 0..MAX_HOPS - 1 {
            let result = process_packet(&mut nodes[i], current_packet).unwrap();
            assert_eq!(result.flag, RoutingFlag::Forward);
            current_packet = result.forward_packet.unwrap();
        }

        let result = process_packet(&mut nodes[MAX_HOPS - 1], current_packet).unwrap();
        assert_eq!(result.flag, RoutingFlag::Destination);

        let decrypted = result.body.unwrap();
        assert_eq!(&decrypted[..body.len()], body);
    }

    #[test]
    fn test_replay_detection() {
        let (mut nodes, route) = create_route(1);
        let body = b"replay test";
        let packet = create_packet(&route, body).unwrap();

        let result1 = process_packet(&mut nodes[0], packet.clone()).unwrap();
        assert_eq!(&result1.body.unwrap()[..body.len()], body);

        let result2 = process_packet(&mut nodes[0], packet);
        assert!(matches!(result2, Err(SphinxError::ReplayDetected)));
    }

    #[test]
    fn test_mac_verification_failure() {
        let (mut nodes, route) = create_route(1);
        let body = b"mac test";
        let mut packet = create_packet(&route, body).unwrap();

        packet.header.mac[0] ^= 0xff;

        let result = process_packet(&mut nodes[0], packet);
        assert!(matches!(result, Err(SphinxError::MacVerificationFailed)));
    }

    #[test]
    fn test_routing_info_tamper_detected() {
        let (mut nodes, route) = create_route(2);
        let body = b"tamper test";
        let mut packet = create_packet(&route, body).unwrap();

        packet.header.routing_info[0] ^= 0xff;

        let result = process_packet(&mut nodes[0], packet);
        assert!(matches!(result, Err(SphinxError::MacVerificationFailed)));
    }

    #[test]
    fn test_route_too_long() {
        let (_nodes, mut route) = create_route(MAX_HOPS);
        let extra = MixNode::new();
        route.hops.push(RouteHop {
            public_key: extra.public_key,
            node_id: extra.node_id,
        });

        let result = create_packet(&route, b"too long");
        assert!(matches!(result, Err(SphinxError::RouteTooLong)));
    }

    #[test]
    fn test_empty_route() {
        let route = Route {
            hops: vec![],
            destination: random_node_id(),
        };

        let result = create_packet(&route, b"empty");
        assert!(matches!(result, Err(SphinxError::RouteTooLong)));
    }

    #[test]
    fn test_body_too_large() {
        let (_nodes, route) = create_route(1);
        let body = vec![0u8; BODY_SIZE + 1];

        let result = create_packet(&route, &body);
        assert!(matches!(result, Err(SphinxError::BodyTooLarge)));
    }

    #[test]
    fn test_ephemeral_key_blinding() {
        let (nodes, route) = create_route(3);
        let body = b"blinding test";
        let packet = create_packet(&route, body).unwrap();

        for node in &nodes {
            assert_ne!(packet.header.ephemeral_key, node.public_key);
        }
    }

    #[test]
    fn test_packet_indistinguishability() {
        let (_nodes, route) = create_route(3);
        let body = b"indistinguishability test message";
        let packet = create_packet(&route, body).unwrap();

        let body_bytes: &[u8] = body.as_ref();
        for i in 0..ROUTING_INFO_SIZE - body_bytes.len() {
            let window = &packet.header.routing_info[i..i + body_bytes.len()];
            assert_ne!(window, body_bytes, "body found in routing info at position {}", i);
        }

        let encrypted_body = &packet.body[..body_bytes.len()];
        assert_ne!(encrypted_body, body_bytes);

        assert!(packet.header.mac.iter().any(|&b| b != 0));
        assert!(packet.header.ephemeral_key.iter().any(|&b| b != 0));
    }

    #[test]
    fn test_body_roundtrip_max_size() {
        let (mut nodes, route) = create_route(2);
        let body = vec![0xABu8; BODY_SIZE];
        let packet = create_packet(&route, &body).unwrap();

        let result0 = process_packet(&mut nodes[0], packet).unwrap();
        let result1 = process_packet(&mut nodes[1], result0.forward_packet.unwrap()).unwrap();

        let decrypted = result1.body.unwrap();
        assert_eq!(decrypted, body);
    }

    #[test]
    fn test_empty_body() {
        let (mut nodes, route) = create_route(1);
        let body: Vec<u8> = vec![];
        let packet = create_packet(&route, &body).unwrap();

        let result = process_packet(&mut nodes[0], packet).unwrap();
        let decrypted = result.body.unwrap();
        assert_eq!(decrypted, vec![0u8; BODY_SIZE]);
    }

    #[test]
    fn test_different_routes_produce_different_packets() {
        let (_nodes1, route1) = create_route(3);
        let (_nodes2, route2) = create_route(3);
        let body = b"same body";

        let packet1 = create_packet(&route1, body).unwrap();
        let packet2 = create_packet(&route2, body).unwrap();

        assert_ne!(packet1.header.ephemeral_key, packet2.header.ephemeral_key);
        assert_ne!(packet1.header.routing_info, packet2.header.routing_info);
        assert_ne!(packet1.body, packet2.body);
    }

    #[test]
    fn test_same_route_different_packets() {
        let (_nodes, route) = create_route(3);
        let body = b"same body";

        let packet1 = create_packet(&route, body).unwrap();
        let packet2 = create_packet(&route, body).unwrap();

        assert_ne!(packet1.header.ephemeral_key, packet2.header.ephemeral_key);
        assert_ne!(packet1.header.routing_info, packet2.header.routing_info);
        assert_ne!(packet1.body, packet2.body);
    }

    #[test]
    fn test_node_creation() {
        let node = MixNode::new();
        assert_ne!(node.node_id, [0u8; NODE_ID_SIZE]);
        assert_ne!(node.public_key, [0u8; 32]);

        let node2 = MixNode::from_private_key([0x42u8; 32], [0x11u8; NODE_ID_SIZE]);
        assert_eq!(node2.node_id, [0x11u8; NODE_ID_SIZE]);
    }
}
