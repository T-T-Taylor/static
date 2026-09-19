//! static-sphinx - Sphinx packet format and mixnet logic

#![forbid(unsafe_code)]
#![deny(missing_docs)]

/// Single-Use Reply Blocks for anonymous responses
pub mod surb;

pub use surb::{
    Surb, SurbSecret, create_surb, create_surb_hybrid,
    wrap_with_surb, wrap_with_surb_hybrid,
    create_surb_batch, create_surb_batch_hybrid,
    process_surb_hybrid,
};

use static_crypto::SymmetricKey;
use static_crypto::{KemKeypair, derive_hybrid_shared_secret};
use static_crypto::{KEM_CIPHERTEXT_SIZE, KEM_PUBLIC_KEY_SIZE};
use static_crypto::{encrypt_aad, decrypt_aad, NonceBytes};
use blake3;
use curve25519_dalek::montgomery::MontgomeryPoint;
use curve25519_dalek::scalar::Scalar;
use rand::rngs::OsRng;
use rand::RngCore;
use std::collections::{HashMap, HashSet, VecDeque};

/// Maximum number of hops in a route
pub const MAX_HOPS: usize = 5;

/// Size of a node ID in bytes
pub const NODE_ID_SIZE: usize = 16;

/// Size of routing flags in bytes
pub const FLAG_SIZE: usize = 1;

/// Size of a MAC in bytes
pub const MAC_SIZE: usize = 16;

/// Size of a reply-session identifier in bytes
pub const SESSION_ID_SIZE: usize = 32;

/// Maximum number of replay tags retained per mix node.
///
/// Bounds the `seen_tags` set to prevent unbounded memory growth from
/// an attacker flooding distinct packets (DoS). Oldest tags are evicted
/// first (FIFO). Evicted tags may allow a very old packet to be replayed
/// again, which is the standard trade-off for a bounded replay cache.
pub const MAX_SEEN_TAGS: usize = 100_000;

/// Maximum number of cached reply sessions per mix node.
///
/// Bounded FIFO: the oldest session is evicted when a new one is
/// inserted at capacity. Session creation is gated by per-hop MAC
/// verification, so only holders of a real SURB for a route through
/// this node can establish a session here.
pub const MAX_SESSION_CACHE: usize = 4096;

/// Reply-session time-to-live in seconds (1 hour).
///
/// Sessions older than this are rejected and lazily evicted;
/// [`MixNode::clean_expired_sessions`] performs bulk cleanup.
pub const SESSION_TTL_SECS: u64 = 3600;

/// Maximum anti-replay nonces tracked per cached session.
///
/// Bounds per-session memory (2048 x 32 B = 64 KiB worst case). Enough
/// for ~2 MiB of fragment responses in one session; later nonces evict
/// the oldest (FIFO).
pub const MAX_SESSION_NONCES: usize = 2048;

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

/// Total header size (version lives outside the header on the wire)
pub const HEADER_SIZE: usize = EPHEMERAL_KEY_SIZE + SESSION_ID_SIZE + ROUTING_INFO_SIZE + MAC_SIZE;

/// Fixed body size in bytes (plaintext capacity)
pub const BODY_SIZE: usize = 1024;

/// Authentication tag size for the AEAD body layer (ChaCha20-Poly1305)
pub const BODY_TAG_SIZE: usize = 16;

/// Wire body size: plaintext + AEAD tag (Phase 7, Task 4a)
///
/// The innermost body layer is ChaCha20-Poly1305 AEAD; outer onion layers
/// are size-preserving XOR. The wire body is always this size (fixed).
pub const WIRE_BODY_SIZE: usize = BODY_SIZE + BODY_TAG_SIZE;

/// Fixed-size KEM block: `MAX_HOPS * KEM_CIPHERTEXT_SIZE` (Phase 7, Task 4b)
///
/// Unused slots carry random bytes. Each hop decapsulates slot 0, shifts
/// left by one ciphertext, and fills the last slot with random bytes so
/// the packet size never changes (no hop-position leak).
pub const KEM_BLOCK_SIZE: usize = MAX_HOPS * KEM_CIPHERTEXT_SIZE;

/// HKDF context for the innermost body AEAD key
pub const BODY_AEAD_CONTEXT: &str = "sphinx/body-aead";

/// HKDF context for deriving the body AEAD nonce
pub const BODY_NONCE_CONTEXT: &str = "sphinx/body-nonce";

/// The Montgomery curve base point (u = 9)
pub(crate) const BASE_POINT: MontgomeryPoint = MontgomeryPoint([
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
    /// Reply-session identifier
    ///
    /// Random bytes for forward packets (carried opaquely). SURBs embed
    /// the session id chosen by the requester: during the first
    /// fragment's traversal every hop caches a reply session under this
    /// id, enabling lightweight session replies for subsequent
    /// fragments. Covered by the per-hop routing MAC.
    pub session_id: [u8; SESSION_ID_SIZE],
    /// The encrypted routing information
    pub routing_info: Vec<u8>,
    /// The MAC over (ephemeral_key || session_id || first_encrypted_slot)
    pub mac: Mac,
}

/// A Sphinx packet
#[derive(Debug, Clone)]
pub struct SphinxPacket {
    /// The packet header
    pub header: SphinxHeader,
    /// ML-KEM ciphertexts (hybrid v1 only)
    ///
    /// Phase 7 fixed-size block: always [`KEM_BLOCK_SIZE`] bytes for hybrid
    /// packets (real ciphertexts followed by random dummy slots). Each hop
    /// decapsulates slot 0, shifts left, and pads with random so the size
    /// never changes. Always empty for classical v0 packets.
    pub kem_ciphertexts: Vec<u8>,
    /// The encrypted body (always [`WIRE_BODY_SIZE`] bytes on the wire)
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
    /// Cached reply sessions (session_id -> session), bounded FIFO
    ///
    /// Populated during the first fragment's traversal of a SURB
    /// (detected internally via the placeholder-MAC path); consumed by
    /// [`process_session_reply`] for subsequent lightweight fragments.
    pub session_cache: HashMap<[u8; SESSION_ID_SIZE], CachedSession>,
    /// Insertion order of `session_cache` for FIFO eviction (oldest front)
    pub session_order: VecDeque<[u8; SESSION_ID_SIZE]>,
}

/// A reply session cached at a mix node during first-fragment traversal
///
/// Captures everything a hop needs to forward subsequent lightweight
/// session replies without KEM operations: the next hop, the per-hop
/// body key (XOR stream), whether this hop is the final one, and the
/// anti-replay nonce set.
pub struct CachedSession {
    /// The next hop's node ID (the destination node id when [`Self::is_final`])
    pub next_hop: NodeId,
    /// Per-hop body key (peels one XOR layer from each session reply)
    pub body_key: SymmetricKey,
    /// Whether this hop is the final destination of the reply session
    pub is_final: bool,
    /// Nonces seen in this session (anti-replay, bounded FIFO)
    pub seen_nonces: HashSet<[u8; SESSION_ID_SIZE]>,
    /// Insertion order of `seen_nonces` for FIFO eviction (oldest front)
    pub nonce_order: VecDeque<[u8; SESSION_ID_SIZE]>,
    /// When the session was established (unix seconds)
    pub created_at: u64,
}

impl CachedSession {
    /// Record a reply nonce with bounded FIFO eviction.
    ///
    /// Duplicate nonces are ignored (the caller rejects replays before
    /// recording).
    pub fn record_nonce(&mut self, nonce: [u8; SESSION_ID_SIZE]) {
        if self.seen_nonces.contains(&nonce) {
            return;
        }
        if self.seen_nonces.len() >= MAX_SESSION_NONCES {
            if let Some(oldest) = self.nonce_order.pop_front() {
                self.seen_nonces.remove(&oldest);
            }
        }
        self.seen_nonces.insert(nonce);
        self.nonce_order.push_back(nonce);
    }
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
    /// AEAD body authentication failed (tampering detected)
    #[error("AEAD body authentication failed")]
    BodyAuthFailed,
    /// No cached session for the given session id
    #[error("reply session not found")]
    SessionNotFound,
    /// Cached session is past its time-to-live
    #[error("reply session expired")]
    SessionExpired,
}

// ---- Internal key derivation ----

struct HopKeys {
    pub(crate) stream_key: SymmetricKey,
    pub(crate) mac_key: SymmetricKey,
    pub(crate) body_key: SymmetricKey,
    pub(crate) tag: [u8; MAC_SIZE],
}

pub(crate) fn derive_hop_keys(shared: &SymmetricKey) -> HopKeys {
    let stream_key = shared.derive("sphinx/stream");
    let mac_key = shared.derive("sphinx/mac");
    let body_key = shared.derive("sphinx/body");
    let tag_key = shared.derive("sphinx/tag");
    let mut tag = [0u8; MAC_SIZE];
    tag.copy_from_slice(&tag_key.bytes[..MAC_SIZE]);
    HopKeys { stream_key, mac_key, body_key, tag }
}

// ---- MAC (covers header + body, Phase 7 Task 4a) ----

/// Compute the per-hop routing MAC over version, ephemeral key, session id,
/// slot and body.
///
/// Binding the body into the routing MAC gives per-hop body authentication:
/// any bit-flip of the body invalidates the next hop's MAC check. Combined
/// with the innermost ChaCha20-Poly1305 layer (end-to-end), the body is
/// fully AEAD-protected (confidential + authenticated). The session id is
/// bound so a tampered session id invalidates the packet.
pub(crate) fn compute_mac(
    mac_key: &SymmetricKey,
    version: u8,
    ephemeral_key: &[u8],
    session_id: &[u8; SESSION_ID_SIZE],
    slot: &[u8],
    body: &[u8],
) -> Mac {
    let derived = mac_key.derive("sphinx/mac/compute");
    let mut input = Vec::with_capacity(
        1 + ephemeral_key.len() + session_id.len() + slot.len() + body.len(),
    );
    input.push(version);
    input.extend_from_slice(ephemeral_key);
    input.extend_from_slice(session_id);
    input.extend_from_slice(slot);
    input.extend_from_slice(body);
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

pub(crate) fn xor_slot(key: &SymmetricKey, slot: &mut [u8; SLOT_SIZE]) {
    let keystream = slot_keystream(key);
    for i in 0..SLOT_SIZE {
        slot[i] ^= keystream[i];
    }
}

// ---- Body encryption ----
//
// Two layers (Phase 7, Task 4a):
// 1. Innermost: full ChaCha20-Poly1305 AEAD (`body_aead_key`, AAD =
//    destination node ID). Plaintext 1024 -> ciphertext 1040 (fixed).
// 2. Outer onion: size-preserving XOR stream on the 1040-byte buffer.
// Per-hop routing MACs cover the body as seen at each hop, so tampering
// is detected immediately (MAC fail), and any tampering that somehow
// passes through is caught end-to-end (AEAD fail at destination).

/// Derive the innermost AEAD key from a hop shared secret.
pub(crate) fn derive_body_aead_key(shared: &SymmetricKey) -> SymmetricKey {
    shared.derive(BODY_AEAD_CONTEXT)
}

/// Deterministic AEAD nonce from the AEAD key (key is fresh per packet).
pub(crate) fn body_aead_nonce(aead_key: &SymmetricKey) -> NonceBytes {
    let derived = aead_key.derive(BODY_NONCE_CONTEXT);
    let mut bytes = [0u8; 12];
    bytes.copy_from_slice(&derived.bytes[..12]);
    NonceBytes::from_bytes(bytes)
}

/// AEAD-encrypt a padded 1024-byte plaintext into a 1040-byte wire body.
pub(crate) fn aead_encrypt_body(
    aead_key: &SymmetricKey,
    plaintext_padded: &[u8],
    aad_destination: &NodeId,
) -> Vec<u8> {
    debug_assert_eq!(plaintext_padded.len(), BODY_SIZE);
    let nonce = body_aead_nonce(aead_key);
    encrypt_aad(aead_key, &nonce, plaintext_padded, aad_destination)
}

/// AEAD-decrypt a 1040-byte wire body into a 1024-byte plaintext.
pub(crate) fn aead_decrypt_body(
    aead_key: &SymmetricKey,
    wire_body: &[u8],
    aad_destination: &NodeId,
) -> Result<Vec<u8>, SphinxError> {
    if wire_body.len() != WIRE_BODY_SIZE {
        return Err(SphinxError::InvalidPacketSize);
    }
    let nonce = body_aead_nonce(aead_key);
    decrypt_aad(aead_key, &nonce, wire_body, aad_destination)
        .map_err(|_| SphinxError::BodyAuthFailed)
}

fn body_keystream(key: &SymmetricKey, len: usize) -> Vec<u8> {    let mut keystream = Vec::with_capacity(len);
    let mut counter = 0u64;
    while keystream.len() < len {
        let block = key.derive(&format!("sphinx/body:{}", counter));
        keystream.extend_from_slice(&block.bytes);
        counter += 1;
    }
    keystream.truncate(len);
    keystream
}

pub(crate) fn xor_body(key: &SymmetricKey, body: &mut [u8]) {
    let keystream = body_keystream(key, body.len());
    for (i, byte) in body.iter_mut().enumerate() {
        *byte ^= keystream[i];
    }
}

/// Public XOR body-layer helper for session reply construction
///
/// The responder onion-encrypts session reply bodies with the SURB's
/// per-hop body keys using the same size-preserving stream cipher as
/// normal Sphinx bodies, so hops can peel layers with their cached
/// session keys.
pub fn xor_body_pub(key: &SymmetricKey, body: &mut [u8]) {
    xor_body(key, body)
}

// ---- Ephemeral key blinding ----

pub(crate) fn blinding_factor(shared: &SymmetricKey) -> Scalar {
    let blind_key = shared.derive("sphinx/blind");
    Scalar::from_bytes_mod_order(blind_key.bytes)
}

// ---- Random helpers ----

pub(crate) fn random_bytes(len: usize) -> Vec<u8> {
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

/// Generate a random reply-session identifier
pub fn random_session_id() -> [u8; SESSION_ID_SIZE] {
    let mut id = [0u8; SESSION_ID_SIZE];
    OsRng.fill_bytes(&mut id);
    id
}

/// Current unix time in seconds (0 fallback when the clock is before
/// the epoch).
pub(crate) fn current_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

pub(crate) fn random_scalar() -> Scalar {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    Scalar::from_bytes_mod_order(bytes)
}

// ---- Public API: Packet creation ----

/// Create a Sphinx packet for a route.
///
/// Body protection (Phase 7): plaintext is padded to [`BODY_SIZE`], AEAD-
/// encrypted with the innermost hop's body-AEAD key (AAD = destination),
/// then onion-layered with size-preserving XOR. Routing MACs cover the
/// body as seen at each hop, so tampering fails fast with
/// [`SphinxError::MacVerificationFailed`]; residual tampering fails
/// end-to-end with [`SphinxError::BodyAuthFailed`].
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

    // Random session id: forward packets carry opaque random bytes so
    // the header layout is uniform across packet kinds.
    let packet_session_id = random_session_id();

    // Generate ephemeral scalar and public key
    let ephemeral_scalar = random_scalar();
    let ephemeral_pub = (&BASE_POINT * &ephemeral_scalar).0;

    // Compute shared secrets with running scalar blinding
    let mut hop_keys = Vec::with_capacity(n);
    let mut alphas = Vec::with_capacity(n);
    let mut current_alpha = ephemeral_pub;
    let mut current_scalar = ephemeral_scalar.clone();
    let mut shared_secrets: Vec<SymmetricKey> = Vec::with_capacity(n);

    for i in 0..n {
        // shared = current_scalar * hop_pubkey_point
        let pub_point = MontgomeryPoint(route.hops[i].public_key);
        let shared_point = &pub_point * &current_scalar;
        let shared = SymmetricKey::from_bytes(shared_point.0);
        shared_secrets.push(shared.clone());
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

    // Innermost AEAD: pad to BODY_SIZE, encrypt to WIRE_BODY_SIZE.
    let mut padded = vec![0u8; BODY_SIZE];
    padded[..body.len()].copy_from_slice(body);
    let inner_aead = derive_body_aead_key(&shared_secrets[n - 1]);
    let inner = aead_encrypt_body(&inner_aead, &padded, &route.destination);
    debug_assert_eq!(inner.len(), WIRE_BODY_SIZE);

    // Onion XOR layers (outermost last applied); record body as seen per hop.
    // body_seen[i] = inner XOR keys[n-1] ... XOR keys[i].
    let mut body_seen: Vec<Vec<u8>> = vec![Vec::new(); n];
    let mut buf = inner;
    for i in (0..n).rev() {
        xor_body(&hop_keys[i].body_key, &mut buf);
        body_seen[i] = buf.clone();
    }

    // Build routing blocks and compute MACs (covering per-hop body).
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
        macs[i] = compute_mac(
            &hop_keys[i].mac_key,
            SPHINX_VERSION_CLASSICAL,
            &alphas[i],
            &packet_session_id,
            &enc_blocks[i],
            &body_seen[i],
        );
    }

    // Build routing info with padding
    let mut routing_info = vec![0u8; ROUTING_INFO_SIZE];
    for i in 0..n {
        routing_info[i * SLOT_SIZE..(i + 1) * SLOT_SIZE].copy_from_slice(&enc_blocks[i]);
    }
    routing_info[n * SLOT_SIZE..].copy_from_slice(&random_bytes(ROUTING_INFO_SIZE - n * SLOT_SIZE));

    let header = SphinxHeader {
        version: SPHINX_VERSION_CLASSICAL,
        ephemeral_key: alphas[0],
        session_id: packet_session_id,
        routing_info,
        mac: macs[0],
    };

    Ok(SphinxPacket { header, kem_ciphertexts: Vec::new(), body: body_seen[0].clone() })
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
    if packet.body.len() != WIRE_BODY_SIZE {
        return Err(SphinxError::InvalidPacketSize);
    }

    // Compute shared secret: private_key * ephemeral_pub
    let alpha_point = MontgomeryPoint(packet.header.ephemeral_key);
    let shared_point = &alpha_point * &node.private_key;
    let shared = SymmetricKey::from_bytes(shared_point.0);
    let keys = derive_hop_keys(&shared);

    // Verify MAC (covers body) BEFORE recording the replay tag. Recording
    // first would let an attacker fill the bounded cache with invalid
    // packets (DoS) and poison replay state. Invalid packets must not
    // consume cache entries.
    let first_slot: &[u8; SLOT_SIZE] = packet.header.routing_info[..SLOT_SIZE]
        .try_into()
        .map_err(|_| SphinxError::InvalidPacketSize)?;
    let expected_mac = compute_mac(
        &keys.mac_key,
        packet.header.version,
        &packet.header.ephemeral_key,
        &packet.header.session_id,
        first_slot,
        &packet.body,
    );
    // True when the MAC only matched via the SURB placeholder fallback
    // (headers pre-built before the payload existed). This is the
    // internal signal that the packet is a SURB first fragment; it is
    // never visible on the wire.
    let mut matched_surb = false;
    if packet.header.mac != expected_mac {
        // SURB fallback: SURB headers are pre-built before the payload is
        // known, so their MACs cover a zero placeholder body. A tampered
        // normal packet matches neither; a legitimate SURB matches here.
        // Body integrity for SURBs still holds end-to-end via AEAD.
        let placeholder = vec![0u8; WIRE_BODY_SIZE];
        let surb_mac = compute_mac(
            &keys.mac_key,
            packet.header.version,
            &packet.header.ephemeral_key,
            &packet.header.session_id,
            first_slot,
            &placeholder,
        );
        if packet.header.mac != surb_mac {
            return Err(SphinxError::MacVerificationFailed);
        }
        matched_surb = true;
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

    // Cache the reply session when this packet is a SURB first fragment:
    // subsequent fragments use lightweight session replies instead of
    // full Sphinx packets. Session creation is gated by the MAC check
    // above, so only a real SURB holder can establish a session here.
    if matched_surb {
        node.insert_session(
            packet.header.session_id,
            CachedSession {
                next_hop,
                body_key: keys.body_key.clone(),
                is_final: flag == RoutingFlag::Destination,
                seen_nonces: HashSet::new(),
                nonce_order: VecDeque::new(),
                created_at: current_timestamp(),
            },
        );
    }

    // Shift routing info left, fill with random padding
    let mut new_routing_info = vec![0u8; ROUTING_INFO_SIZE];
    new_routing_info[..ROUTING_INFO_SIZE - SLOT_SIZE]
        .copy_from_slice(&packet.header.routing_info[SLOT_SIZE..]);
    new_routing_info[ROUTING_INFO_SIZE - SLOT_SIZE..]
        .copy_from_slice(&random_bytes(SLOT_SIZE));

    // Blind ephemeral key for next hop
    let blind = blinding_factor(&shared);
    let new_ephemeral = (&alpha_point * &blind).0;

    // Peel one body encryption layer (stays WIRE_BODY_SIZE)
    let mut peeled_body = packet.body;
    xor_body(&keys.body_key, &mut peeled_body);

    match flag {
        RoutingFlag::Destination => {
            // End-to-end AEAD: last layer decrypts to BODY_SIZE plaintext.
            let aead_key = derive_body_aead_key(&shared);
            let plaintext = aead_decrypt_body(&aead_key, &peeled_body, &next_hop)?;
            Ok(ProcessedPacket {
                next_hop,
                flag,
                forward_packet: None,
                body: Some(plaintext),
            })
        }
        RoutingFlag::Forward => {
            let forward_header = SphinxHeader {
                version: packet.header.version,
                ephemeral_key: new_ephemeral,
                session_id: packet.header.session_id,
                routing_info: new_routing_info,
                mac: next_mac,
            };
            let forward_packet = SphinxPacket {
                header: forward_header,
                kem_ciphertexts: Vec::new(),
                body: peeled_body,
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

/// Create a valid dummy Sphinx packet for cover traffic (Phase 7, Task 4c).
///
/// Builds a real hybrid packet over fresh random nodes with a random body,
/// so cover is structurally valid and indistinguishable from real traffic
/// by size and layout. The packet routes nowhere meaningful (random
/// destination); mix nodes that receive it process it normally and drop it.
pub fn create_dummy_sphinx_packet() -> SphinxPacket {
    let n = 3;
    let mut hops = Vec::with_capacity(n);
    for _ in 0..n {
        let node = HybridMixNode::new();
        hops.push(node.as_hop());
    }
    let route = HybridRoute { hops, destination: random_node_id() };
    let body = random_bytes(BODY_SIZE);
    create_packet_hybrid(&route, &body)
        .expect("dummy packet construction with fresh keys must succeed")
}

/// Create a hybrid Sphinx packet for a route.
///
/// Per-hop keys combine X25519 (with the same running-scalar blinding
/// as classical packets) and a fresh ML-KEM encapsulation to that hop:
/// `hop_key = derive_hybrid_shared_secret(classical_dh, kem_ss)`.
/// Body protection mirrors [`create_packet`] (AEAD inner + XOR onion +
/// body-covering MACs). The KEM section is a fixed [`KEM_BLOCK_SIZE`]
/// block (real ciphertexts + random dummies) so size never leaks position.
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

    // Random session id (opaque, uniform header layout — see create_packet)
    let packet_session_id = random_session_id();

    let ephemeral_scalar = random_scalar();
    let ephemeral_pub = (&BASE_POINT * &ephemeral_scalar).0;

    // Compute hybrid shared secrets with running scalar blinding
    let mut hop_keys = Vec::with_capacity(n);
    let mut alphas = Vec::with_capacity(n);
    let mut hybrid_secrets: Vec<SymmetricKey> = Vec::with_capacity(n);
    let mut real_cts: Vec<Vec<u8>> = Vec::with_capacity(n);
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
        real_cts.push(ciphertext);

        // Hybrid combination: both must break to recover hop keys
        let hybrid_shared =
            derive_hybrid_shared_secret(&classical_shared, &kem_shared, HYBRID_HOP_CONTEXT);
        hybrid_secrets.push(hybrid_shared.clone());
        hop_keys.push(derive_hop_keys(&hybrid_shared));

        alphas.push(current_alpha);

        if i < n - 1 {
            let blind = blinding_factor(&hybrid_shared);
            current_scalar = &current_scalar * &blind;
            let alpha_point = MontgomeryPoint(current_alpha);
            current_alpha = (&alpha_point * &blind).0;
        }
    }

    // Fixed KEM block: real ciphertexts + random dummies.
    let mut kem_block: Vec<u8> = Vec::with_capacity(KEM_BLOCK_SIZE);
    for ct in &real_cts {
        kem_block.extend_from_slice(ct);
    }
    let dummy_len = KEM_BLOCK_SIZE - n * KEM_CIPHERTEXT_SIZE;
    kem_block.extend_from_slice(&random_bytes(dummy_len));

    // Innermost AEAD + XOR onion (same as classical, hybrid keys).
    let mut padded = vec![0u8; BODY_SIZE];
    padded[..body.len()].copy_from_slice(body);
    let inner_aead = derive_body_aead_key(&hybrid_secrets[n - 1]);
    let inner = aead_encrypt_body(&inner_aead, &padded, &route.destination);
    debug_assert_eq!(inner.len(), WIRE_BODY_SIZE);

    let mut body_seen: Vec<Vec<u8>> = vec![Vec::new(); n];
    let mut buf = inner;
    for i in (0..n).rev() {
        xor_body(&hop_keys[i].body_key, &mut buf);
        body_seen[i] = buf.clone();
    }

    // Build routing blocks and MACs (covering per-hop body).
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
        macs[i] = compute_mac(
            &hop_keys[i].mac_key,
            SPHINX_VERSION_HYBRID,
            &alphas[i],
            &packet_session_id,
            &enc_blocks[i],
            &body_seen[i],
        );
    }

    let mut routing_info = vec![0u8; ROUTING_INFO_SIZE];
    for i in 0..n {
        routing_info[i * SLOT_SIZE..(i + 1) * SLOT_SIZE].copy_from_slice(&enc_blocks[i]);
    }
    routing_info[n * SLOT_SIZE..].copy_from_slice(&random_bytes(ROUTING_INFO_SIZE - n * SLOT_SIZE));

    let header = SphinxHeader {
        version: SPHINX_VERSION_HYBRID,
        ephemeral_key: alphas[0],
        session_id: packet_session_id,
        routing_info,
        mac: macs[0],
    };

    Ok(SphinxPacket { header, kem_ciphertexts: kem_block, body: body_seen[0].clone() })
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
    if packet.body.len() != WIRE_BODY_SIZE {
        return Err(SphinxError::InvalidPacketSize);
    }
    // Fixed-size KEM block (Phase 7): hybrid packets always carry
    // KEM_BLOCK_SIZE bytes; classical variable-length packets are rejected.
    if packet.kem_ciphertexts.len() != KEM_BLOCK_SIZE {
        return Err(SphinxError::InvalidKemCiphertext);
    }

    // This hop's ciphertext is always slot 0; the rest shifts forward.
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

    // Verify MAC (covers body) BEFORE recording the replay tag.
    let first_slot: &[u8; SLOT_SIZE] = packet.header.routing_info[..SLOT_SIZE]
        .try_into()
        .map_err(|_| SphinxError::InvalidPacketSize)?;
    let expected_mac = compute_mac(
        &keys.mac_key,
        packet.header.version,
        &packet.header.ephemeral_key,
        &packet.header.session_id,
        first_slot,
        &packet.body,
    );
    // Internal SURB first-fragment signal (see process_packet)
    let mut matched_surb = false;
    if packet.header.mac != expected_mac {
        // SURB fallback (see `process_packet`): pre-built headers cover a
        // zero placeholder body; end-to-end AEAD still protects the payload.
        let placeholder = vec![0u8; WIRE_BODY_SIZE];
        let surb_mac = compute_mac(
            &keys.mac_key,
            packet.header.version,
            &packet.header.ephemeral_key,
            &packet.header.session_id,
            first_slot,
            &placeholder,
        );
        if packet.header.mac != surb_mac {
            return Err(SphinxError::MacVerificationFailed);
        }
        matched_surb = true;
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

    // Cache the reply session (SURB first fragment only — see process_packet)
    if matched_surb {
        classical.insert_session(
            packet.header.session_id,
            CachedSession {
                next_hop,
                body_key: keys.body_key.clone(),
                is_final: flag == RoutingFlag::Destination,
                seen_nonces: HashSet::new(),
                nonce_order: VecDeque::new(),
                created_at: current_timestamp(),
            },
        );
    }

    // Shift routing info left, fill with random padding
    let mut new_routing_info = vec![0u8; ROUTING_INFO_SIZE];
    new_routing_info[..ROUTING_INFO_SIZE - SLOT_SIZE]
        .copy_from_slice(&packet.header.routing_info[SLOT_SIZE..]);
    new_routing_info[ROUTING_INFO_SIZE - SLOT_SIZE..]
        .copy_from_slice(&random_bytes(SLOT_SIZE));

    // Blind ephemeral key for next hop
    let blind = blinding_factor(&hybrid_shared);
    let new_ephemeral = (&alpha_point * &blind).0;

    // Peel one body layer (stays WIRE_BODY_SIZE)
    let mut peeled_body = packet.body;
    xor_body(&keys.body_key, &mut peeled_body);

    // Shift KEM block left by one ciphertext, pad last slot with random
    // so the size never changes (no position leak).
    let mut new_kem_block: Vec<u8> = Vec::with_capacity(KEM_BLOCK_SIZE);
    new_kem_block.extend_from_slice(rest_cts);
    new_kem_block.extend_from_slice(&random_bytes(KEM_CIPHERTEXT_SIZE));
    debug_assert_eq!(new_kem_block.len(), KEM_BLOCK_SIZE);

    match flag {
        RoutingFlag::Destination => {
            let aead_key = derive_body_aead_key(&hybrid_shared);
            let plaintext = aead_decrypt_body(&aead_key, &peeled_body, &next_hop)?;
            Ok(HybridProcessedPacket {
                next_hop,
                flag,
                forward_packet: None,
                body: Some(plaintext),
            })
        }
        RoutingFlag::Forward => {
            let forward_header = SphinxHeader {
                version: SPHINX_VERSION_HYBRID,
                ephemeral_key: new_ephemeral,
                session_id: packet.header.session_id,
                routing_info: new_routing_info,
                mac: next_mac,
            };
            let forward_packet = SphinxPacket {
                header: forward_header,
                kem_ciphertexts: new_kem_block,
                body: peeled_body,
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

// ---- Session replies (lightweight reply-session fragments) ----

/// Packet version marker for session replies (wire payload discriminator)
///
/// Sphinx payloads start with version 0 (classical) or 1 (hybrid);
/// session replies use 2. Same wire type byte, framing and payload size
/// as Sphinx packets — indistinguishable to an observer, deterministic
/// to distinguish for the receiving mix node.
pub const SPHINX_VERSION_SESSION_REPLY: u8 = 2;

/// Total wire payload size of a session reply (identical to a hybrid
/// Sphinx packet payload) for wire uniformity.
pub const SESSION_REPLY_WIRE_SIZE: usize = 1
    + EPHEMERAL_KEY_SIZE
    + SESSION_ID_SIZE
    + 4
    + KEM_BLOCK_SIZE
    + ROUTING_INFO_SIZE
    + MAC_SIZE
    + WIRE_BODY_SIZE;

/// Session reply wire size minus the version/session/nonce prefix
pub const SESSION_REPLY_BODY_SIZE: usize = SESSION_REPLY_WIRE_SIZE
    - (1 + SESSION_ID_SIZE + SESSION_ID_SIZE);

/// A lightweight session reply packet (used after session establishment)
///
/// Same wire payload size as a Sphinx packet for indistinguishability:
/// an observer cannot tell a session reply from a Sphinx packet (same
/// wire type byte, framing and length). Mix nodes distinguish
/// internally by the version byte. The body is onion-XOR encrypted with
/// the per-hop body keys of the SURB's return route (exactly like a
/// SURB-wrapped Sphinx body); each hop peels one layer with its cached
/// session key. The innermost layer is the responder's ChaCha20-Poly1305
/// AEAD ciphertext, which only the requester can decrypt.
#[derive(Debug, Clone)]
pub struct SessionReply {
    /// Session identifier (from the SURB that established the session)
    pub session_id: [u8; SESSION_ID_SIZE],
    /// Unique nonce per fragment (anti-replay at every hop; also the
    /// AEAD nonce prefix at the endpoints)
    pub nonce: [u8; SESSION_ID_SIZE],
    /// Encrypted body (onion XOR layers over the innermost AEAD
    /// ciphertext, one layer peeled per hop)
    pub body: Vec<u8>,
}

impl SessionReply {
    /// Serialize to wire bytes (exactly [`SESSION_REPLY_WIRE_SIZE`])
    ///
    /// Layout: `[1 version=2][32 session_id][32 nonce][body][random pad]`.
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(SESSION_REPLY_WIRE_SIZE);
        buf.push(SPHINX_VERSION_SESSION_REPLY);
        buf.extend_from_slice(&self.session_id);
        buf.extend_from_slice(&self.nonce);
        debug_assert_eq!(self.body.len(), WIRE_BODY_SIZE);
        let mut body = vec![0u8; WIRE_BODY_SIZE];
        let n = self.body.len().min(WIRE_BODY_SIZE);
        body[..n].copy_from_slice(&self.body[..n]);
        buf.extend_from_slice(&body);
        while buf.len() < SESSION_REPLY_WIRE_SIZE {
            buf.push(OsRng.next_u32() as u8);
        }
        buf
    }

    /// Deserialize from wire bytes (trailing padding ignored)
    pub fn deserialize(data: &[u8]) -> Result<Self, SphinxError> {
        let min = 1 + SESSION_ID_SIZE + SESSION_ID_SIZE + WIRE_BODY_SIZE;
        if data.len() < min {
            return Err(SphinxError::InvalidPacketSize);
        }
        if data[0] != SPHINX_VERSION_SESSION_REPLY {
            return Err(SphinxError::UnsupportedVersion(data[0]));
        }
        let mut session_id = [0u8; SESSION_ID_SIZE];
        session_id.copy_from_slice(&data[1..1 + SESSION_ID_SIZE]);
        let mut nonce = [0u8; SESSION_ID_SIZE];
        nonce.copy_from_slice(&data[1 + SESSION_ID_SIZE..1 + 2 * SESSION_ID_SIZE]);
        let body = data[1 + 2 * SESSION_ID_SIZE..1 + 2 * SESSION_ID_SIZE + WIRE_BODY_SIZE].to_vec();
        Ok(Self { session_id, nonce, body })
    }
}

/// Result of processing a session reply at a mix node
#[derive(Debug)]
pub struct SessionReplyResult {
    /// The next hop's node ID (the reply destination when `is_final`)
    pub next_hop: NodeId,
    /// The reply with this hop's body layer peeled, ready to forward
    /// (or deliver to the application when `is_final`)
    pub reply: SessionReply,
    /// Whether this node is the final destination of the reply session
    pub is_final: bool,
}

/// Process a lightweight session reply packet at a mix node
///
/// Used for every response fragment after the first: no KEM, no routing
/// MAC — just session lookup, nonce anti-replay, one XOR body layer peel
/// and forward (or delivery at the final hop). Fails closed on unknown
/// or expired sessions ([`SphinxError::SessionNotFound`] /
/// [`SphinxError::SessionExpired`]) and replays
/// ([`SphinxError::ReplayDetected`]).
pub fn process_session_reply(
    mix_node: &mut MixNode,
    reply: SessionReply,
    current_time: u64,
) -> Result<SessionReplyResult, SphinxError> {
    if reply.body.len() != WIRE_BODY_SIZE {
        return Err(SphinxError::InvalidPacketSize);
    }
    // Lazy expiry: drop stale sessions on contact.
    let expired = mix_node
        .session_cache
        .get(&reply.session_id)
        .is_some_and(|s| current_time.saturating_sub(s.created_at) >= SESSION_TTL_SECS);
    if expired {
        mix_node.session_cache.remove(&reply.session_id);
        mix_node.session_order.retain(|id| *id != reply.session_id);
        return Err(SphinxError::SessionExpired);
    }
    let session = mix_node
        .session_cache
        .get_mut(&reply.session_id)
        .ok_or(SphinxError::SessionNotFound)?;

    // Anti-replay: every fragment carries a fresh nonce.
    if session.seen_nonces.contains(&reply.nonce) {
        return Err(SphinxError::ReplayDetected);
    }
    session.record_nonce(reply.nonce);

    // Peel one XOR body layer (size-preserving; the innermost layer is
    // the responder's end-to-end AEAD ciphertext).
    let mut body = reply.body;
    xor_body(&session.body_key, &mut body);

    let is_final = session.is_final;
    let next_hop = session.next_hop;
    Ok(SessionReplyResult {
        next_hop,
        reply: SessionReply { session_id: reply.session_id, nonce: reply.nonce, body },
        is_final,
    })
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
            session_cache: HashMap::new(),
            session_order: VecDeque::new(),
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
            session_cache: HashMap::new(),
            session_order: VecDeque::new(),
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

    /// Insert (or refresh) a cached reply session with bounded FIFO eviction.
    ///
    /// At [`MAX_SESSION_CACHE`] sessions the oldest is evicted first.
    /// Refreshing an existing session keeps its cache slot (it stays
    /// evictable in insertion order).
    pub fn insert_session(&mut self, session_id: [u8; SESSION_ID_SIZE], session: CachedSession) {
        if self.session_cache.contains_key(&session_id) {
            self.session_cache.insert(session_id, session);
            return;
        }
        if self.session_cache.len() >= MAX_SESSION_CACHE {
            if let Some(oldest) = self.session_order.pop_front() {
                self.session_cache.remove(&oldest);
            }
        }
        self.session_cache.insert(session_id, session);
        self.session_order.push_back(session_id);
    }

    /// Remove expired reply sessions (older than [`SESSION_TTL_SECS`]).
    ///
    /// Called periodically by the node lifecycle loop; session replies
    /// also lazily reject+evict individual expired sessions.
    pub fn clean_expired_sessions(&mut self, current_time: u64) {
        self.session_cache.retain(|_, session| {
            current_time.saturating_sub(session.created_at) < SESSION_TTL_SECS
        });
        self.session_order.retain(|id| self.session_cache.contains_key(id));
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
        // Phase 7: fixed KEM block (no position leak).
        assert_eq!(packet.kem_ciphertexts.len(), KEM_BLOCK_SIZE);

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
        assert_eq!(packet.kem_ciphertexts.len(), KEM_BLOCK_SIZE);

        let result0 = process_packet_hybrid(&mut nodes[0], packet).unwrap();
        assert_eq!(result0.flag, RoutingFlag::Forward);
        assert_eq!(result0.next_hop, nodes[1].node_id());
        let fwd0 = result0.forward_packet.unwrap();
        // Phase 7: size never changes per hop (shift + random pad).
        assert_eq!(fwd0.kem_ciphertexts.len(), KEM_BLOCK_SIZE);

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

    #[test]
    fn test_sphinx_body_aead() {
        // Phase 7 Task 4a: body tampering is detected. Flipping a body
        // bit breaks the next hop's MAC (fast fail); even if a tamper
        // slipped through per-hop MACs, the destination AEAD would fail.
        let (mut nodes, route) = create_hybrid_route(2);
        let body = b"aead body test";
        let mut packet = create_packet_hybrid(&route, body).unwrap();

        // Tamper with the body (first hop sees it).
        packet.body[0] ^= 0xFF;
        let err = process_packet_hybrid(&mut nodes[0], packet).unwrap_err();
        assert!(matches!(err, SphinxError::MacVerificationFailed));

        // Untampered packet decrypts end-to-end via AEAD.
        let (mut nodes2, route2) = create_hybrid_route(1);
        let packet2 = create_packet_hybrid(&route2, body).unwrap();
        let result = process_packet_hybrid(&mut nodes2[0], packet2).unwrap();
        assert_eq!(&result.body.unwrap()[..body.len()], body);
    }

    #[test]
    fn test_kem_block_fixed_size() {
        // Phase 7 Task 4b: packet size never changes per hop (no
        // position leak). Create a 3-hop packet; after each hop the
        // serialized size is identical.
        let (mut nodes, route) = create_hybrid_route(3);
        let packet = create_packet_hybrid(&route, b"fixed kem").unwrap();
        let size0 = packet.body.len() + packet.kem_ciphertexts.len();
        assert_eq!(packet.kem_ciphertexts.len(), KEM_BLOCK_SIZE);

        let r0 = process_packet_hybrid(&mut nodes[0], packet).unwrap();
        let fwd0 = r0.forward_packet.unwrap();
        let size1 = fwd0.body.len() + fwd0.kem_ciphertexts.len();
        assert_eq!(size0, size1);
        assert_eq!(fwd0.kem_ciphertexts.len(), KEM_BLOCK_SIZE);

        let r1 = process_packet_hybrid(&mut nodes[1], fwd0).unwrap();
        let fwd1 = r1.forward_packet.unwrap();
        assert_eq!(fwd1.kem_ciphertexts.len(), KEM_BLOCK_SIZE);
        assert_eq!(fwd1.body.len() + fwd1.kem_ciphertexts.len(), size0);
    }

    #[test]
    fn test_dummy_sphinx_valid() {
        // Phase 7 Task 4c: cover traffic is a structurally valid packet
        // (not random bytes). A mix node processes it without error.
        let mut node = HybridMixNode::new();
        // Build a dummy routed THROUGH this node so it can process it.
        let peer_hop = node.as_hop();
        let r1 = HybridMixNode::new();
        let r2 = HybridMixNode::new();
        let route = HybridRoute {
            hops: vec![peer_hop, r1.as_hop(), r2.as_hop()],
            destination: random_node_id(),
        };
        let packet = create_packet_hybrid(&route, &[0u8; BODY_SIZE]).unwrap();
        // Valid: processes cleanly (forwards, no MAC failure).
        let result = process_packet_hybrid(&mut node, packet).unwrap();
        assert_eq!(result.flag, RoutingFlag::Forward);
        // The public helper also produces a well-formed packet.
        let dummy = create_dummy_sphinx_packet();
        assert_eq!(dummy.header.version, SPHINX_VERSION_HYBRID);
        assert_eq!(dummy.kem_ciphertexts.len(), KEM_BLOCK_SIZE);
        assert_eq!(dummy.body.len(), WIRE_BODY_SIZE);
    }

    // ---- Reply-session tests (SURB per-fragment compression) ----

    /// Build a hybrid SURB over `n` intermediate hops plus the requester
    /// (as the final routing hop), returning the intermediates, the
    /// requester's mix node, and the SURB.
    fn create_hybrid_surb(n: usize) -> (Vec<HybridMixNode>, HybridMixNode, Surb) {
        let mut nodes = Vec::with_capacity(n + 1);
        let mut hops = Vec::with_capacity(n + 1);
        for _ in 0..=n {
            let node = HybridMixNode::new();
            hops.push(node.as_hop());
            nodes.push(node);
        }
        let requester = nodes.pop().unwrap();
        let route = HybridRoute { hops, destination: requester.node_id() };
        let (surb, _secret) = surb::create_surb_hybrid(&route).unwrap();
        (nodes, requester, surb)
    }

    /// Establish the reply session end-to-end: process the first
    /// fragment (a SURB-wrapped Sphinx packet) through the intermediates
    /// and the requester's own mix node.
    fn establish_session(
        nodes: &mut [HybridMixNode],
        requester: &mut HybridMixNode,
        surb: &Surb,
    ) {
        let packet = wrap_with_surb_hybrid(surb, b"first fragment").unwrap();
        let mut current = packet;
        for node in nodes.iter_mut() {
            current = process_packet_hybrid(node, current).unwrap().forward_packet.unwrap();
        }
        let result = process_packet_hybrid(requester, current).unwrap();
        assert_eq!(result.flag, RoutingFlag::Destination);
    }

    /// Build one responder-side session reply for `payload`.
    fn build_reply(surb: &Surb, payload: &[u8], nonce_byte: u8) -> SessionReply {
        assert!(payload.len() <= BODY_SIZE);
        let mut nonce = [nonce_byte; SESSION_ID_SIZE];
        OsRng.fill_bytes(&mut nonce);
        let aead_nonce = NonceBytes::from_bytes(nonce[..12].try_into().unwrap());
        let mut padded = vec![0u8; BODY_SIZE];
        padded[..payload.len()].copy_from_slice(payload);
        let mut body =
            encrypt_aad(&surb.body_aead_key, &aead_nonce, &padded, &surb.aad_destination);
        assert_eq!(body.len(), WIRE_BODY_SIZE);
        for i in (0..surb.body_keys.len()).rev() {
            xor_body_pub(&surb.body_keys[i], &mut body);
        }
        SessionReply { session_id: surb.session_id(), nonce, body }
    }

    #[test]
    fn test_session_establishment() {
        // The first response fragment (a normal SURB-wrapped Sphinx
        // packet) caches the reply session at EVERY hop: next hop,
        // per-hop body key, and final-hop marking.
        let (mut nodes, mut requester, surb) = create_hybrid_surb(3);
        let session_id = surb.session_id();
        assert_ne!(session_id, [0u8; SESSION_ID_SIZE]);

        let packet = wrap_with_surb_hybrid(&surb, b"first fragment").unwrap();
        let mut current = packet;
        let mut next_hops: Vec<NodeId> = nodes[1..].iter().map(|n| n.node_id()).collect();
        next_hops.push(requester.node_id());
        for (i, node) in nodes.iter_mut().enumerate() {
            let result = process_packet_hybrid(node, current).unwrap();
            assert_eq!(result.flag, RoutingFlag::Forward);
            current = result.forward_packet.unwrap();
            let session = node.classical.session_cache.get(&session_id)
                .expect("session cached at intermediate hop");
            assert_eq!(session.next_hop, next_hops[i]);
            assert!(!session.is_final);
        }
        let result = process_packet_hybrid(&mut requester, current).unwrap();
        assert_eq!(result.flag, RoutingFlag::Destination);
        let session = requester.classical.session_cache.get(&session_id)
            .expect("session cached at the final hop");
        assert!(session.is_final);

        // Forward packets must NOT create sessions: the cache stays at
        // the single entry established above.
        let route = HybridRoute {
            hops: vec![nodes[0].as_hop()],
            destination: random_node_id(),
        };
        let normal = create_packet_hybrid(&route, b"normal").unwrap();
        let _ = process_packet_hybrid(&mut nodes[0], normal).unwrap();
        assert_eq!(nodes[0].classical.session_cache.len(), 1);
    }

    #[test]
    fn test_session_reply_processing() {
        // Subsequent fragments travel as lightweight session replies:
        // each hop peels one XOR layer (no KEM), the final hop delivers,
        // and the requester recovers the exact payload end-to-end.
        let (mut nodes, mut requester, surb) = create_hybrid_surb(3);
        establish_session(&mut nodes, &mut requester, &surb);

        let reply = build_reply(&surb, b"reply body", 0x01);
        let mut current_reply = reply;
        for node in nodes.iter_mut() {
            let outcome = process_session_reply(&mut node.classical, current_reply, 0).unwrap();
            assert!(!outcome.is_final);
            current_reply = outcome.reply;
        }
        let outcome = process_session_reply(&mut requester.classical, current_reply, 0).unwrap();
        assert!(outcome.is_final);
        let aead_nonce = NonceBytes::from_bytes(
            reply_nonce_of(&outcome.reply)[..12].try_into().unwrap(),
        );
        let plaintext = decrypt_aad(
            &surb.body_aead_key,
            &aead_nonce,
            &outcome.reply.body,
            &surb.aad_destination,
        )
        .unwrap();
        assert_eq!(&plaintext[..10], b"reply body");
    }

    #[test]
    fn test_session_anti_replay() {
        // A captured session reply replayed at a hop is rejected.
        let (mut nodes, mut requester, surb) = create_hybrid_surb(1);
        establish_session(&mut nodes, &mut requester, &surb);

        let reply = build_reply(&surb, b"frag", 0x55);
        let first = process_session_reply(&mut requester.classical, reply.clone(), 0).unwrap();
        assert!(first.is_final);
        let replay = process_session_reply(&mut requester.classical, reply, 0);
        assert!(matches!(replay, Err(SphinxError::ReplayDetected)));
    }

    #[test]
    fn test_session_expiry() {
        // A session past its TTL is rejected on contact and evicted.
        let (mut nodes, mut requester, surb) = create_hybrid_surb(1);
        establish_session(&mut nodes, &mut requester, &surb);

        let reply = build_reply(&surb, b"frag", 0x66);
        let far_future = u64::MAX / 2;
        let err = process_session_reply(&mut requester.classical, reply, far_future);
        assert!(matches!(err, Err(SphinxError::SessionExpired)));
        assert!(!requester.classical.session_cache.contains_key(&surb.session_id()));
    }

    #[test]
    fn test_session_reply_anonymity() {
        // The SURB holder (responder) cannot identify the requester: the
        // serialized SURB contains no plaintext destination node id, and
        // only the first hop's id is exposed.
        let (nodes, requester, surb) = create_hybrid_surb(3);
        let requester_id = requester.node_id();
        let bytes = surb.serialize();
        let hex: String = requester_id.iter().map(|b| format!("{:02x}", b)).collect();
        assert!(!String::from_utf8_lossy(&bytes).contains(&hex));
        // The first hop is visible (needed for delivery) but the final
        // destination is not the first hop.
        assert_ne!(surb.first_hop, requester_id);
        let _ = nodes;
    }

    /// Helper: read a reply's nonce (test-only convenience).
    fn reply_nonce_of(reply: &SessionReply) -> [u8; SESSION_ID_SIZE] {
        reply.nonce
    }
}
