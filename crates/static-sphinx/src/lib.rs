//! static-sphinx - Sphinx packet format and mixnet logic

#![forbid(unsafe_code)]
#![deny(missing_docs)]

/// Single-Use Reply Blocks for anonymous responses
pub mod surb;

use static_crypto::SymmetricKey;
use static_crypto::{KemKeypair, derive_hybrid_shared_secret};
use static_crypto::{KEM_CIPHERTEXT_SIZE, KEM_PUBLIC_KEY_SIZE};
use blake3;
use curve25519_dalek::montgomery::MontgomeryPoint;
use curve25519_dalek::scalar::Scalar;
use rand::rngs::OsRng;
use rand::RngCore;
use std::collections::{HashSet, VecDeque};

/// Maximum number of hops in a route
pub const MAX_HOPS: usize = 5;

/// Size of a node ID in bytes
pub const NODE_ID_SIZE: usize = 16;

/// Size of routing flags in bytes
pub const FLAG_SIZE: usize = 1;

/// Size of a MAC in bytes
pub const MAC_SIZE: usize = 16;

/// Maximum number of replay tags retained per mix node.
///
/// Bounds the `seen_tags` set to prevent unbounded memory growth from
/// an attacker flooding distinct packets (DoS). Oldest tags are evicted
/// first (FIFO). Evicted tags may allow a very old packet to be replayed
/// again, which is the standard trade-off for a bounded replay cache.
pub const MAX_SEEN_TAGS: usize = 100_000;

/// Size of a routing slot in bytes
pub const SLOT_SIZE: usize = NODE_ID_SIZE + FLAG_SIZE + MAC_SIZE;

/// Total routing info size in bytes
pub const ROUTING_INFO_SIZE: usize = MAX_HOPS * SLOT_SIZE;

/// Size of the ephemeral key in bytes
pub const EPHEMERAL_KEY_SIZE: usize = 32;

/// Sphinx packet version: classical X25519-only key agreement
pub const SPHINX_VERSION_CLASSICAL: u8 = 0;

/// Sphinx packet version: hybrid X25519 + ML-KEM-768 key agreement
pub const SPHINX_VERSION_HYBRID: u8 = 1;

/// HKDF context for deriving per-hop keys from hybrid shared secrets
pub const HYBRID_HOP_CONTEXT: &str = "sphinx/hybrid-hop";

/// Size of one ML-KEM-768 ciphertext in bytes (re-exported for sizing)
pub const HYBRID_KEM_CIPHERTEXT_SIZE: usize = KEM_CIPHERTEXT_SIZE;

/// Size of one ML-KEM-768 public key in bytes (re-exported for sizing)
pub const HYBRID_KEM_PUBLIC_KEY_SIZE: usize = KEM_PUBLIC_KEY_SIZE;

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
    /// Packet version: 0 = classical (X25519), 1 = hybrid (X25519 + ML-KEM)
    pub version: u8,
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
    /// ML-KEM ciphertexts, one per remaining hop (hybrid v1 only)
    ///
    /// Flat concatenation (`n * KEM_CIPHERTEXT_SIZE` bytes). Each hop
    /// decapsulates and strips the first ciphertext before forwarding.
    /// Always empty for classical v0 packets.
    pub kem_ciphertexts: Vec<u8>,
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
    /// Set of seen replay tags (bounded by [`MAX_SEEN_TAGS`])
    pub seen_tags: HashSet<[u8; MAC_SIZE]>,
    /// Insertion order of `seen_tags` for FIFO eviction (oldest front)
    pub seen_order: VecDeque<[u8; MAC_SIZE]>,
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
    /// Packet version not supported by this operation
    ///
    /// Classical `process_packet` rejects v1 packets (use
    /// `process_packet_hybrid`); hybrid processing rejects unknown versions.
    #[error("unsupported sphinx packet version: {0}")]
    UnsupportedVersion(u8),
    /// ML-KEM ciphertext invalid or decapsulation failed
    #[error("invalid ML-KEM ciphertext")]
    InvalidKemCiphertext,
    /// ML-KEM public key has the wrong size
    #[error("invalid ML-KEM public key size")]
    InvalidKemPublicKey,
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

/// Generate a random node ID
pub fn random_node_id() -> NodeId {
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
        version: SPHINX_VERSION_CLASSICAL,
        ephemeral_key: alphas[0],
        routing_info,
        mac: macs[0],
    };

    Ok(SphinxPacket { header, kem_ciphertexts: Vec::new(), body: body_bytes })
}

// ---- Public API: Packet processing ----

/// Process a Sphinx packet at a mix node.
///
/// Uses non-clamped scalar multiplication to match the sender's
/// blinding computation.
///
/// Classical-only: rejects hybrid (v1) packets with
/// [`SphinxError::UnsupportedVersion`] — use [`process_packet_hybrid`].
pub fn process_packet(node: &mut MixNode, packet: SphinxPacket) -> Result<ProcessedPacket, SphinxError> {
    if packet.header.version == SPHINX_VERSION_HYBRID {
        return Err(SphinxError::UnsupportedVersion(packet.header.version));
    }
    if packet.header.version != SPHINX_VERSION_CLASSICAL {
        return Err(SphinxError::UnsupportedVersion(packet.header.version));
    }
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

    // Verify MAC BEFORE recording the replay tag. Recording first would let
    // an attacker fill the bounded cache with invalid packets (DoS) and
    // poison replay state. Invalid packets must not consume cache entries.
    let first_slot: &[u8; SLOT_SIZE] = packet.header.routing_info[..SLOT_SIZE]
        .try_into()
        .map_err(|_| SphinxError::InvalidPacketSize)?;
    let expected_mac = compute_mac(&keys.mac_key, &packet.header.ephemeral_key, first_slot);
    if packet.header.mac != expected_mac {
        return Err(SphinxError::MacVerificationFailed);
    }

    // Check replay (only valid packets reach here)
    if node.seen_tags.contains(&keys.tag) {
        return Err(SphinxError::ReplayDetected);
    }
    node.insert_seen_tag(keys.tag);

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
                version: packet.header.version,
                ephemeral_key: new_ephemeral,
                routing_info: new_routing_info,
                mac: next_mac,
            };
            let forward_packet = SphinxPacket {
                header: forward_header,
                kem_ciphertexts: Vec::new(),
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

// ---- Hybrid (post-quantum) key agreement ----

/// A hop in a hybrid route: classical X25519 key plus ML-KEM-768 key
#[derive(Debug, Clone)]
pub struct HybridRouteHop {
    /// The mix node's ID
    pub node_id: NodeId,
    /// The mix node's classical public key (Montgomery point bytes)
    pub classical_public_key: PubKeyBytes,
    /// The mix node's ML-KEM-768 public key bytes
    pub kem_public_key: Vec<u8>,
}

/// A route for hybrid Sphinx packets
#[derive(Debug, Clone)]
pub struct HybridRoute {
    /// The mix nodes in order
    pub hops: Vec<HybridRouteHop>,
    /// The final destination ID
    pub destination: NodeId,
}

/// A mix node that supports both classical and hybrid Sphinx packets
///
/// Holds the classical Curve25519 keys (via [`MixNode`]) plus a
/// post-quantum ML-KEM-768 keypair. Classical packets are processed
/// with the inner node; hybrid packets additionally decapsulate the
/// per-hop KEM ciphertext and combine both shared secrets.
pub struct HybridMixNode {
    /// Classical Curve25519 keys and replay tags
    pub classical: MixNode,
    /// Post-quantum ML-KEM-768 keys
    pub kem: KemKeypair,
}

/// Result of processing a hybrid packet at a mix node
#[derive(Debug)]
pub struct HybridProcessedPacket {
    /// The next hop's node ID
    pub next_hop: NodeId,
    /// The routing flag
    pub flag: RoutingFlag,
    /// The packet to forward (None if destination)
    pub forward_packet: Option<SphinxPacket>,
    /// The decrypted body (Some only at destination)
    pub body: Option<Vec<u8>>,
}

impl HybridMixNode {
    /// Create a new hybrid mix node with fresh classical and KEM keys
    pub fn new() -> Self {
        Self {
            classical: MixNode::new(),
            kem: KemKeypair::random(),
        }
    }

    /// Wrap an existing classical mix node, generating a fresh KEM keypair
    pub fn from_mix_node(classical: MixNode) -> Self {
        Self {
            classical,
            kem: KemKeypair::random(),
        }
    }

    /// This node's ID (same as the classical inner node)
    pub fn node_id(&self) -> NodeId {
        self.classical.node_id
    }

    /// This node's classical public key bytes
    pub fn classical_public_key(&self) -> PubKeyBytes {
        self.classical.public_key
    }

    /// This node's ML-KEM public key bytes (to advertise to peers)
    pub fn kem_public_key_bytes(&self) -> Vec<u8> {
        self.kem.public_bytes()
    }

    /// A route hop descriptor for this node
    pub fn as_hop(&self) -> HybridRouteHop {
        HybridRouteHop {
            node_id: self.classical.node_id,
            classical_public_key: self.classical.public_key,
            kem_public_key: self.kem.public_bytes(),
        }
    }
}

impl Default for HybridMixNode {
    fn default() -> Self {
        Self::new()
    }
}

/// Create a hybrid Sphinx packet for a route.
///
/// Per-hop keys combine X25519 (with the same running-scalar blinding
/// as classical packets) and a fresh ML-KEM encapsulation to that hop:
/// `hop_key = derive_hybrid_shared_secret(classical_dh, kem_ss)`.
/// Routing/MAC/body construction is otherwise identical to classical,
/// so cover properties are preserved. One KEM ciphertext per hop rides
/// in the packet; each hop strips its own before forwarding.
pub fn create_packet_hybrid(route: &HybridRoute, body: &[u8]) -> Result<SphinxPacket, SphinxError> {
    let n = route.hops.len();
    if n == 0 || n > MAX_HOPS {
        return Err(SphinxError::RouteTooLong);
    }
    if body.len() > BODY_SIZE {
        return Err(SphinxError::BodyTooLarge);
    }
    for hop in &route.hops {
        if hop.kem_public_key.len() != KEM_PUBLIC_KEY_SIZE {
            return Err(SphinxError::InvalidKemPublicKey);
        }
    }

    let ephemeral_scalar = random_scalar();
    let ephemeral_pub = (&BASE_POINT * &ephemeral_scalar).0;

    // Compute hybrid shared secrets with running scalar blinding
    let mut hop_keys = Vec::with_capacity(n);
    let mut alphas = Vec::with_capacity(n);
    let mut kem_ciphertexts: Vec<u8> = Vec::with_capacity(n * KEM_CIPHERTEXT_SIZE);
    let mut current_alpha = ephemeral_pub;
    let mut current_scalar = ephemeral_scalar.clone();

    for i in 0..n {
        // Classical component (blinded DH, as in create_packet)
        let pub_point = MontgomeryPoint(route.hops[i].classical_public_key);
        let shared_point = &pub_point * &current_scalar;
        let classical_shared = SymmetricKey::from_bytes(shared_point.0);

        // Post-quantum component (fresh encapsulation per hop)
        let (kem_shared, ciphertext) = KemKeypair::encapsulate_to(&route.hops[i].kem_public_key)
            .map_err(|_| SphinxError::InvalidKemPublicKey)?;
        kem_ciphertexts.extend_from_slice(&ciphertext);

        // Hybrid combination: both must break to recover hop keys
        let hybrid_shared =
            derive_hybrid_shared_secret(&classical_shared, &kem_shared, HYBRID_HOP_CONTEXT);
        hop_keys.push(derive_hop_keys(&hybrid_shared));

        alphas.push(current_alpha);

        if i < n - 1 {
            let blind = blinding_factor(&hybrid_shared);
            current_scalar = &current_scalar * &blind;
            let alpha_point = MontgomeryPoint(current_alpha);
            current_alpha = (&alpha_point * &blind).0;
        }
    }

    // Build routing blocks and MACs (identical construction, hybrid keys)
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

    let mut routing_info = vec![0u8; ROUTING_INFO_SIZE];
    for i in 0..n {
        routing_info[i * SLOT_SIZE..(i + 1) * SLOT_SIZE].copy_from_slice(&enc_blocks[i]);
    }
    routing_info[n * SLOT_SIZE..].copy_from_slice(&random_bytes(ROUTING_INFO_SIZE - n * SLOT_SIZE));

    let mut body_bytes = vec![0u8; BODY_SIZE];
    body_bytes[..body.len()].copy_from_slice(body);
    for i in (0..n).rev() {
        xor_body(&hop_keys[i].body_key, &mut body_bytes);
    }

    let header = SphinxHeader {
        version: SPHINX_VERSION_HYBRID,
        ephemeral_key: alphas[0],
        routing_info,
        mac: macs[0],
    };

    Ok(SphinxPacket { header, kem_ciphertexts, body: body_bytes })
}

/// Process a hybrid Sphinx packet at a mix node.
///
/// Decapsulates this hop's KEM ciphertext, recombines with the classical
/// DH share, and processes routing exactly like a classical hop.
/// Rejects non-hybrid packets with [`SphinxError::UnsupportedVersion`].
pub fn process_packet_hybrid(
    node: &mut HybridMixNode,
    packet: SphinxPacket,
) -> Result<HybridProcessedPacket, SphinxError> {
    let secret = node.kem.secret_bytes();
    process_packet_hybrid_with_keys(&mut node.classical, &secret, packet)
}

/// Process a hybrid packet with a split key store
///
/// Same as [`process_packet_hybrid`] but takes the classical [`MixNode`]
/// (replay tags live here, shared with the classical path) and the raw
/// ML-KEM secret bytes separately. Transports that keep one mix node
/// plus a standalone KEM pair use this entry point.
pub fn process_packet_hybrid_with_keys(
    classical: &mut MixNode,
    kem_secret: &[u8],
    packet: SphinxPacket,
) -> Result<HybridProcessedPacket, SphinxError> {
    if packet.header.version != SPHINX_VERSION_HYBRID {
        return Err(SphinxError::UnsupportedVersion(packet.header.version));
    }
    if packet.header.routing_info.len() != ROUTING_INFO_SIZE {
        return Err(SphinxError::InvalidPacketSize);
    }
    if packet.body.len() != BODY_SIZE {
        return Err(SphinxError::InvalidPacketSize);
    }
    if packet.kem_ciphertexts.len() < KEM_CIPHERTEXT_SIZE
        || packet.kem_ciphertexts.len() % KEM_CIPHERTEXT_SIZE != 0
    {
        return Err(SphinxError::InvalidKemCiphertext);
    }

    // Split off this hop's ciphertext; the rest forwards on.
    let (our_ct, rest_cts) = packet.kem_ciphertexts.split_at(KEM_CIPHERTEXT_SIZE);

    // Classical component
    let alpha_point = MontgomeryPoint(packet.header.ephemeral_key);
    let shared_point = &alpha_point * &classical.private_key;
    let classical_shared = SymmetricKey::from_bytes(shared_point.0);

    // Post-quantum component
    let kem_shared = static_crypto::KemKeypair::decapsulate_with(kem_secret, our_ct)
        .map_err(|_| SphinxError::InvalidKemCiphertext)?;

    let hybrid_shared =
        derive_hybrid_shared_secret(&classical_shared, &kem_shared, HYBRID_HOP_CONTEXT);
    let keys = derive_hop_keys(&hybrid_shared);

    // Verify MAC BEFORE recording the replay tag (see `process_packet`).
    let first_slot: &[u8; SLOT_SIZE] = packet.header.routing_info[..SLOT_SIZE]
        .try_into()
        .map_err(|_| SphinxError::InvalidPacketSize)?;
    let expected_mac = compute_mac(&keys.mac_key, &packet.header.ephemeral_key, first_slot);
    if packet.header.mac != expected_mac {
        return Err(SphinxError::MacVerificationFailed);
    }

    // Check replay (shared tag space with classical path)
    if classical.seen_tags.contains(&keys.tag) {
        return Err(SphinxError::ReplayDetected);
    }
    classical.insert_seen_tag(keys.tag);

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
    let blind = blinding_factor(&hybrid_shared);
    let new_ephemeral = (&alpha_point * &blind).0;

    // Peel one body encryption layer
    let mut new_body = packet.body;
    xor_body(&keys.body_key, &mut new_body);

    match flag {
        RoutingFlag::Destination => {
            Ok(HybridProcessedPacket {
                next_hop,
                flag,
                forward_packet: None,
                body: Some(new_body),
            })
        }
        RoutingFlag::Forward => {
            let forward_header = SphinxHeader {
                version: SPHINX_VERSION_HYBRID,
                ephemeral_key: new_ephemeral,
                routing_info: new_routing_info,
                mac: next_mac,
            };
            let forward_packet = SphinxPacket {
                header: forward_header,
                kem_ciphertexts: rest_cts.to_vec(),
                body: new_body,
            };
            Ok(HybridProcessedPacket {
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
            seen_order: VecDeque::new(),
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
            seen_order: VecDeque::new(),
        }
    }

    /// Number of replay tags currently retained.
    pub fn seen_count(&self) -> usize {
        self.seen_tags.len()
    }

    /// Insert a replay tag with bounded FIFO eviction.
    ///
    /// If the cache holds [`MAX_SEEN_TAGS`] entries, the oldest tag is
    /// evicted first. Duplicate tags are ignored (no order duplication).
    pub fn insert_seen_tag(&mut self, tag: [u8; MAC_SIZE]) {
        if self.seen_tags.contains(&tag) {
            return;
        }
        if self.seen_tags.len() >= MAX_SEEN_TAGS {
            if let Some(oldest) = self.seen_order.pop_front() {
                self.seen_tags.remove(&oldest);
            }
        }
        self.seen_tags.insert(tag);
        self.seen_order.push_back(tag);
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

    fn create_hybrid_route(n: usize) -> (Vec<HybridMixNode>, HybridRoute) {
        let mut nodes = Vec::with_capacity(n);
        let mut hops = Vec::with_capacity(n);
        for _ in 0..n {
            let node = HybridMixNode::new();
            hops.push(node.as_hop());
            nodes.push(node);
        }
        let destination = random_node_id();
        let route = HybridRoute { hops, destination };
        (nodes, route)
    }

    #[test]
    fn test_hybrid_sphinx_single_hop() {
        let (mut nodes, route) = create_hybrid_route(1);
        let body = b"hybrid hello";
        let packet = create_packet_hybrid(&route, body).unwrap();

        assert_eq!(packet.header.version, SPHINX_VERSION_HYBRID);
        assert_eq!(packet.kem_ciphertexts.len(), KEM_CIPHERTEXT_SIZE);

        let result = process_packet_hybrid(&mut nodes[0], packet).unwrap();
        assert_eq!(result.flag, RoutingFlag::Destination);
        assert_eq!(result.next_hop, route.destination);
        assert!(result.forward_packet.is_none());

        let decrypted = result.body.unwrap();
        assert_eq!(&decrypted[..body.len()], body);
    }

    #[test]
    fn test_hybrid_sphinx_multi_hop() {
        let (mut nodes, route) = create_hybrid_route(3);
        let body = b"hybrid multi hop";
        let packet = create_packet_hybrid(&route, body).unwrap();
        assert_eq!(packet.kem_ciphertexts.len(), 3 * KEM_CIPHERTEXT_SIZE);

        let result0 = process_packet_hybrid(&mut nodes[0], packet).unwrap();
        assert_eq!(result0.flag, RoutingFlag::Forward);
        assert_eq!(result0.next_hop, nodes[1].node_id());
        let fwd0 = result0.forward_packet.unwrap();
        assert_eq!(fwd0.kem_ciphertexts.len(), 2 * KEM_CIPHERTEXT_SIZE);

        let result1 = process_packet_hybrid(&mut nodes[1], fwd0).unwrap();
        assert_eq!(result1.flag, RoutingFlag::Forward);
        assert_eq!(result1.next_hop, nodes[2].node_id());

        let result2 =
            process_packet_hybrid(&mut nodes[2], result1.forward_packet.unwrap()).unwrap();
        assert_eq!(result2.flag, RoutingFlag::Destination);

        let decrypted = result2.body.unwrap();
        assert_eq!(&decrypted[..body.len()], body);
    }

    #[test]
    fn test_hybrid_sphinx_max_hops() {
        let (mut nodes, route) = create_hybrid_route(MAX_HOPS);
        let body = b"hybrid max hops";
        let packet = create_packet_hybrid(&route, body).unwrap();

        let mut current_packet = packet;
        for i in 0..MAX_HOPS - 1 {
            let result = process_packet_hybrid(&mut nodes[i], current_packet).unwrap();
            assert_eq!(result.flag, RoutingFlag::Forward);
            current_packet = result.forward_packet.unwrap();
        }

        let result = process_packet_hybrid(&mut nodes[MAX_HOPS - 1], current_packet).unwrap();
        assert_eq!(result.flag, RoutingFlag::Destination);
        assert_eq!(&result.body.unwrap()[..body.len()], body);
    }

    #[test]
    fn test_hybrid_sphinx_replay_detection() {
        let (mut nodes, route) = create_hybrid_route(1);
        let body = b"hybrid replay";
        let packet = create_packet_hybrid(&route, body).unwrap();

        let result1 = process_packet_hybrid(&mut nodes[0], packet.clone()).unwrap();
        assert_eq!(&result1.body.unwrap()[..body.len()], body);

        let result2 = process_packet_hybrid(&mut nodes[0], packet);
        assert!(matches!(result2, Err(SphinxError::ReplayDetected)));
    }

    #[test]
    fn test_hybrid_sphinx_indistinguishability() {
        let (_nodes, route) = create_hybrid_route(3);
        let body = b"hybrid indistinguishability probe";
        let packet = create_packet_hybrid(&route, body).unwrap();

        // Ciphertext blobs look random (not all zeros, differ per packet)
        assert!(packet.kem_ciphertexts.iter().any(|&b| b != 0));
        let packet2 = create_packet_hybrid(&route, body).unwrap();
        assert_ne!(packet.kem_ciphertexts, packet2.kem_ciphertexts);

        // Body and routing info hide the plaintext
        let body_bytes: &[u8] = body.as_ref();
        assert_ne!(&packet.body[..body_bytes.len()], body_bytes);
        assert!(packet.header.mac.iter().any(|&b| b != 0));
    }

    #[test]
    fn test_classical_backward_compat() {
        // Classical packets still route on plain MixNodes after versioning.
        let (mut nodes, route) = create_route(2);
        let body = b"legacy classical";
        let packet = create_packet(&route, body).unwrap();
        assert_eq!(packet.header.version, SPHINX_VERSION_CLASSICAL);
        assert!(packet.kem_ciphertexts.is_empty());

        let result0 = process_packet(&mut nodes[0], packet).unwrap();
        assert_eq!(result0.flag, RoutingFlag::Forward);
        let result1 =
            process_packet(&mut nodes[1], result0.forward_packet.unwrap()).unwrap();
        assert_eq!(&result1.body.unwrap()[..body.len()], body);

        // Classical processor rejects hybrid packets (version routing).
        let (mut hnodes, hroute) = create_hybrid_route(1);
        let hpacket = create_packet_hybrid(&hroute, body).unwrap();
        let err = process_packet(&mut nodes[0], hpacket).unwrap_err();
        assert!(matches!(err, SphinxError::UnsupportedVersion(1)));

        // Hybrid processor rejects classical packets.
        let cpacket = create_packet(&route, body).unwrap();
        let err = process_packet_hybrid(&mut hnodes[0], cpacket).unwrap_err();
        assert!(matches!(err, SphinxError::UnsupportedVersion(0)));
    }

    #[test]
    fn test_seen_tags_bounded_eviction() {
        let mut node = MixNode::new();
        assert_eq!(node.seen_count(), 0);

        // Insert MAX_SEEN_TAGS distinct tags.
        for i in 0..MAX_SEEN_TAGS {
            let mut tag = [0u8; MAC_SIZE];
            tag[..8].copy_from_slice(&(i as u64).to_be_bytes());
            tag[8..].copy_from_slice(&((i as u64).wrapping_mul(0x9E3779B97F4A7C15)).to_be_bytes());
            node.insert_seen_tag(tag);
        }
        assert_eq!(node.seen_count(), MAX_SEEN_TAGS);

        // First tag should be present before eviction.
        let mut first = [0u8; MAC_SIZE];
        first[..8].copy_from_slice(&0u64.to_be_bytes());
        first[8..].copy_from_slice(&0u64.to_be_bytes());
        assert!(node.seen_tags.contains(&first));

        // One more insert evicts the oldest, staying at the cap.
        let mut extra = [0xFFu8; MAC_SIZE];
        extra[0] = 0xAB;
        node.insert_seen_tag(extra);
        assert_eq!(node.seen_count(), MAX_SEEN_TAGS);
        assert_eq!(node.seen_count(), 100_000);
        assert!(!node.seen_tags.contains(&first));
        assert!(node.seen_tags.contains(&extra));

        // Duplicate insert does not grow or duplicate order entries.
        let order_len = node.seen_order.len();
        node.insert_seen_tag(extra);
        assert_eq!(node.seen_count(), MAX_SEEN_TAGS);
        assert_eq!(node.seen_order.len(), order_len);
    }

    #[test]
    fn test_invalid_mac_does_not_insert() {
        let (mut nodes, route) = create_route(1);
        let body = b"mac must not pollute replay cache";
        let packet = create_packet(&route, body).unwrap();

        // Corrupt the MAC and verify it is rejected without caching the tag.
        let mut bad = packet.clone();
        bad.header.mac[0] ^= 0xff;
        let err = process_packet(&mut nodes[0], bad).unwrap_err();
        assert!(matches!(err, SphinxError::MacVerificationFailed));
        assert_eq!(nodes[0].seen_count(), 0);

        // The original (valid) packet must still process — not flagged replay.
        let ok = process_packet(&mut nodes[0], packet.clone()).unwrap();
        assert_eq!(&ok.body.unwrap()[..body.len()], body);
        assert_eq!(nodes[0].seen_count(), 1);

        // Replaying the valid packet is still detected.
        let replay = process_packet(&mut nodes[0], packet);
        assert!(matches!(replay, Err(SphinxError::ReplayDetected)));
        assert_eq!(nodes[0].seen_count(), 1);
    }

    #[test]
    fn test_hybrid_invalid_mac_does_not_insert() {
        let (mut nodes, route) = create_hybrid_route(1);
        let body = b"hybrid mac must not pollute replay cache";
        let packet = create_packet_hybrid(&route, body).unwrap();

        let mut bad = packet.clone();
        bad.header.mac[0] ^= 0xff;
        let err = process_packet_hybrid(&mut nodes[0], bad).unwrap_err();
        assert!(matches!(err, SphinxError::MacVerificationFailed));
        assert_eq!(nodes[0].classical.seen_count(), 0);

        let ok = process_packet_hybrid(&mut nodes[0], packet.clone()).unwrap();
        assert_eq!(&ok.body.unwrap()[..body.len()], body);
        assert_eq!(nodes[0].classical.seen_count(), 1);

        let replay = process_packet_hybrid(&mut nodes[0], packet);
        assert!(matches!(replay, Err(SphinxError::ReplayDetected)));
    }
}
