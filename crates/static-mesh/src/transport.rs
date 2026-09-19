//! Pluggable transport layer for the Static network
//!
//! Defines the [`Transport`] and [`Connection`] traits that abstract
//! the raw byte-level link between peers, with TCP as the default
//! implementation (`TcpTransport`). Alternative transports (WebSocket,
//! QUIC, Bluetooth mesh) can be added by implementing the traits
//! without touching the protocol layer above.
//!
//! On top of the transport traits, implements:
//! - Listener for incoming peer connections
//! - Connector for outgoing peer connections
//! - Frame-based message reading/writing using the wire protocol
//! - Connection management (track active connections by node ID)
//! - Background cover traffic loop (constant-rate sending)
//! - Sphinx packet forwarding (mixnode processing + forward)
//!
//! The transport layer maintains the "always hot" property by running
//! a cover traffic loop that sends dummy packets at a fixed rate,
//! multiplexing real traffic in with the cover traffic.

use crate::routing::{RoutingTable, KnownNode, PeerGossip};
use crate::retrieval::{
    handle_retrieval_request, create_hybrid_payload_packets,
    handle_retrieval_request_with_surb, MSG_SURB_CHUNK_REQUEST,
};
use static_storage::swap::{
    SwapState, StorageCapacity, PendingSwap, decide_on_swap,
    create_swap_accept, create_swap_reject, create_swap_commit, create_swap_abort,
    SwapProposal, SwapAccept, SwapReject, SwapCommit, SwapAbort,
    MAX_PENDING_SWAPS,
};
use static_storage::heartbeat::LeaseManager;
use static_storage::retrieval::ChunkHolder;
use crate::wire;
use crate::wire::{
    WireMessage, Handshake, Hello, Welcome,
    try_read_message, write_message, HYBRID_MAX_MESSAGE_SIZE,
    handshake_session_aad, derive_handshake_secret,
    encrypt_identity, decrypt_identity, wrap_maintenance_payload,
    MSG_BODY_GOSSIP, MSG_BODY_SWAP_ACCEPT,
    MSG_BODY_SWAP_REJECT, MSG_BODY_PREPAYMENT, MSG_BODY_RECONCILIATION,
    MSG_BODY_SWAP_COMMIT, MSG_BODY_SWAP_ABORT,
};
use static_sphinx::{
    SphinxPacket, MixNode, RoutingFlag,
    NodeId, SESSION_ID_SIZE,
};
use async_trait::async_trait;
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, RwLock, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time;
use tracing::{info, warn, error, debug};

/// Timeout for reassembly of fragmented SURB chunk requests (seconds).
///
/// Requests are a handful of back-to-back fragments; anything older is
/// junk or a stalled peer.
pub const SURB_REQUEST_TIMEOUT_SECS: u64 = 120;

/// A connection to a peer (transport-agnostic)
///
/// Abstracts the raw byte-level link to one peer. The protocol layer
/// (framing, handshakes, cover traffic) operates on top of this trait
/// and never sees transport-specific types.
///
/// Implementations must support concurrent send and receive (full
/// duplex): the connection loop reads and writes simultaneously, and
/// cover traffic must keep flowing even while waiting for inbound
/// bytes. A transport that serializes reads and writes would stall
/// cover traffic whenever the peer is silent. (TCP is full duplex; a
/// half-duplex transport should buffer internally.)
#[async_trait]
pub trait Connection: Send + Sync {
    /// Send raw bytes to the peer
    async fn send_bytes(&self, data: &[u8]) -> Result<(), TransportError>;

    /// Receive raw bytes from the peer
    ///
    /// Returns the number of bytes read, or `None` if the connection
    /// is closed by the peer.
    async fn recv_bytes(&self, buf: &mut [u8]) -> Result<Option<usize>, TransportError>;

    /// Close the connection
    async fn close(&self) -> Result<(), TransportError>;

    /// Get the peer's address as a string
    fn peer_addr(&self) -> String;
}

/// A transport implementation (TCP, WebSocket, Bluetooth, etc.)
///
/// Abstracts connection management: listening, accepting, and dialing.
/// Each transport handles its own MTU/fragmentation; the protocol
/// layer only ever deals with complete messages via the framing layer.
///
/// All methods take `&self`: implementations use interior mutability
/// so that a listening node can still dial out (and vice versa) without
/// any lock held across an await.
#[async_trait]
pub trait Transport: Send + Sync {
    /// Start listening for incoming connections
    async fn listen(&self, addr: &str) -> Result<(), TransportError>;

    /// Accept an incoming connection
    ///
    /// Returns the new connection and the peer's address.
    async fn accept(&self) -> Result<(Box<dyn Connection>, String), TransportError>;

    /// Connect to a peer
    async fn connect(&self, addr: &str) -> Result<Box<dyn Connection>, TransportError>;

    /// Get the transport name (e.g. "tcp", "websocket", "bluetooth")
    fn name(&self) -> &str;

    /// Get the maximum message size this transport can carry
    ///
    /// The protocol layer uses this to decide if fragmentation is
    /// needed. Transports with a small MTU handle fragmentation and
    /// reassembly internally; the protocol layer never sees partial
    /// messages.
    fn max_message_size(&self) -> usize;
}

/// TCP transport implementation
///
/// The default [`Transport`]. The listener is held behind interior
/// mutability, so `listen`, `accept`, and `connect` never block each
/// other: a node that listens can still dial out immediately.
pub struct TcpTransport {
    /// Bound listener (set by [`Transport::listen`])
    listener: std::sync::Mutex<Option<Arc<TcpListener>>>,
}

impl TcpTransport {
    /// Create a new TCP transport (not yet listening)
    pub fn new() -> Self {
        Self {
            listener: std::sync::Mutex::new(None),
        }
    }
}

impl Default for TcpTransport {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Transport for TcpTransport {
    async fn listen(&self, addr: &str) -> Result<(), TransportError> {
        let socket_addr: SocketAddr = addr
            .parse()
            .map_err(|_| TransportError::HandshakeFailed(format!("Invalid address: {}", addr)))?;
        let listener = TcpListener::bind(socket_addr).await?;
        *self.listener.lock().unwrap() = Some(Arc::new(listener));
        Ok(())
    }

    async fn accept(&self) -> Result<(Box<dyn Connection>, String), TransportError> {
        let listener = self
            .listener
            .lock()
            .unwrap()
            .clone()
            .ok_or_else(|| TransportError::HandshakeFailed("Not listening".into()))?;
        let (stream, addr) = listener.accept().await?;
        Ok((Box::new(TcpConnection::new(stream)), addr.to_string()))
    }

    async fn connect(&self, addr: &str) -> Result<Box<dyn Connection>, TransportError> {
        let socket_addr: SocketAddr = addr
            .parse()
            .map_err(|_| TransportError::HandshakeFailed(format!("Invalid address: {}", addr)))?;
        let stream = TcpStream::connect(socket_addr).await?;
        Ok(Box::new(TcpConnection::new(stream)))
    }

    fn name(&self) -> &str {
        "tcp"
    }

    fn max_message_size(&self) -> usize {
        HYBRID_MAX_MESSAGE_SIZE
    }
}

/// TCP connection implementation
///
/// The stream is split into independently locked read and write halves
/// so the connection stays full duplex: waiting for inbound bytes never
/// blocks outgoing sends (and vice versa).
pub struct TcpConnection {
    /// Read half (locked only by receivers)
    reader: Mutex<tokio::net::tcp::OwnedReadHalf>,
    /// Write half (locked only by senders)
    writer: Mutex<tokio::net::tcp::OwnedWriteHalf>,
}

impl TcpConnection {
    /// Wrap an established TCP stream
    pub fn new(stream: TcpStream) -> Self {
        let (reader, writer) = stream.into_split();
        Self {
            reader: Mutex::new(reader),
            writer: Mutex::new(writer),
        }
    }
}

#[async_trait]
impl Connection for TcpConnection {
    async fn send_bytes(&self, data: &[u8]) -> Result<(), TransportError> {
        let mut writer = self.writer.lock().await;
        writer.write_all(data).await?;
        writer.flush().await?;
        Ok(())
    }

    async fn recv_bytes(&self, buf: &mut [u8]) -> Result<Option<usize>, TransportError> {
        let mut reader = self.reader.lock().await;
        let n = reader.read(buf).await?;
        if n == 0 {
            Ok(None)
        } else {
            Ok(Some(n))
        }
    }

    async fn close(&self) -> Result<(), TransportError> {
        // Dropping the halves closes the socket
        Ok(())
    }

    fn peer_addr(&self) -> String {
        self.reader
            .try_lock()
            .ok()
            .and_then(|reader| reader.peer_addr().ok())
            .map(|a| a.to_string())
            .unwrap_or_default()
    }
}

/// Size of a node ID
pub const NODE_ID_SIZE: usize = 16;

/// Channel buffer size for messages
pub const CHANNEL_BUFFER: usize = 256;

/// Read buffer size (fits the largest hybrid message plus framing slack)
pub const READ_BUFFER_SIZE: usize = HYBRID_MAX_MESSAGE_SIZE + 1024;

/// A connection to a peer
pub struct PeerConnection {
    /// The peer's node ID (set after handshake)
    pub node_id: Option<NodeId>,
    /// The peer's address
    pub addr: SocketAddr,
    /// Sender channel for outgoing messages to this peer
    pub sender: mpsc::Sender<WireMessage>,
    /// Bytes sent to this peer
    pub bytes_sent: u64,
    /// Bytes received from this peer
    pub bytes_received: u64,
}

/// Per-node token bucket for constant-rate cover shaping (Phase 0, C1).
///
/// A single bucket shared across all connections. Real traffic must
/// consume tokens; when empty, real messages queue instead of bursting.
/// Cover fills the remainder each interval. Kept tiny on purpose: the
/// hot `select!` loop only calls `try_consume`.
#[derive(Debug, Clone)]
pub struct TokenBucket {
    /// Current tokens (bytes available)
    pub tokens: u64,
    /// Bucket capacity (max burst, bytes)
    pub max_tokens: u64,
    /// Refill rate (bytes per second)
    pub refill_rate: u64,
    /// Last refill timestamp (unix millis; P1-cover ms granularity).
    ///
    /// Historically seconds; now millis so 100 ms cover ticks refill
    /// smoothly instead of bursting once per second. `new()` still
    /// accepts seconds for backwards compatibility and converts.
    pub last_refill: u64,
}

impl TokenBucket {
    /// Create a new bucket, full.
    pub fn new(max_tokens: u64, refill_rate: u64, now_secs: u64) -> Self {
        Self {
            tokens: max_tokens,
            max_tokens,
            refill_rate,
            last_refill: now_secs.saturating_mul(1000),
        }
    }

    fn now_millis() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64
    }

    /// Refill based on elapsed wall time (ms granularity).
    pub fn refill(&mut self) {
        let now = Self::now_millis();
        let elapsed_ms = now.saturating_sub(self.last_refill);
        if elapsed_ms > 0 {
            self.tokens = self
                .tokens
                .saturating_add(elapsed_ms.saturating_mul(self.refill_rate) / 1000)
                .min(self.max_tokens);
            self.last_refill = now;
        }
    }

    /// Try to consume `bytes`; returns true if sent immediately.
    pub fn try_consume(&mut self, bytes: u64) -> bool {
        self.refill();
        if self.tokens >= bytes {
            self.tokens -= bytes;
            true
        } else {
            false
        }
    }

    /// Update rate/capacity (tier or CLI change).
    pub fn set_rate(&mut self, refill_rate: u64, max_tokens: u64) {
        self.refill_rate = refill_rate;
        self.max_tokens = max_tokens;
        self.tokens = self.tokens.min(max_tokens);
    }
}

/// Handshake nonce replay window (seconds).
pub const HANDSHAKE_NONCE_TTL_SECS: u64 = 300;
/// Maximum cached handshake nonces (bounded LRU-ish, FIFO eviction).
pub const MAX_HANDSHAKE_NONCES: usize = 4096;

/// Shared state for the transport layer
pub struct TransportState {
    /// This node's ID
    pub node_id: NodeId,
    /// This node's mix node (for Sphinx processing)
    pub mix_node: Arc<Mutex<MixNode>>,
    /// Active peer connections (node_id -> connection info)
    pub connections: Arc<RwLock<HashMap<NodeId, mpsc::Sender<WireMessage>>>>,
    /// Pending connections (addr -> sender)
    pub pending: Arc<RwLock<HashMap<SocketAddr, mpsc::Sender<WireMessage>>>>,
    /// Cover traffic configuration
    pub cover_config: Arc<RwLock<crate::CoverTrafficConfig>>,
    /// Per-node token bucket for cover shaping (shared across connections)
    pub cover_bucket: Arc<Mutex<TokenBucket>>,
    /// Total bytes sent (real + cover)
    pub total_bytes_sent: Arc<std::sync::atomic::AtomicU64>,
    /// Total real bytes sent
    pub total_real_bytes_sent: Arc<std::sync::atomic::AtomicU64>,
    /// Total cover bytes sent
    pub total_cover_bytes_sent: Arc<std::sync::atomic::AtomicU64>,
    /// Inbound message channel (for the node to process)
    pub inbound_tx: mpsc::Sender<InboundMessage>,
    /// Routing table for known nodes
    pub routing_table: Arc<RwLock<RoutingTable>>,
    /// Swap state for tracking pending and active swaps
    ///
    /// Shared with the node runner (a single `Arc` passed into
    /// [`create_transport_state`]) so the transport-side swap flow and
    /// runner-side consumers (verification challenges, heartbeat
    /// propagation) observe one registry.
    pub swap_state: Arc<Mutex<SwapState>>,
    /// Lease manager for chunks accepted via 2-phase swaps
    ///
    /// `Some` in production (the runner's manager): swap commit
    /// finalization inserts a lease carrying the content owner's public
    /// key so signed heartbeats verify. `None` in mesh unit tests,
    /// which do not exercise lease bookkeeping.
    pub lease_manager: Option<Arc<Mutex<LeaseManager>>>,
    /// Timeout for pending 2-phase swaps (seconds)
    ///
    /// Defaults to [`static_storage::swap::DEFAULT_PENDING_SWAP_TIMEOUT_
    /// SECS`]; tests shorten it via `Arc::get_mut` before sharing.
    pub pending_swap_timeout_secs: u64,
    /// Storage capacity for swap decisions
    pub storage_capacity: Arc<Mutex<StorageCapacity>>,
    /// Storage master key for our chunks
    pub storage_key: Arc<Mutex<static_crypto::SymmetricKey>>,
    /// Chunks this node is holding
    pub chunk_holder: Arc<Mutex<ChunkHolder>>,
    /// This node's ML-KEM-768 keypair (advertised in handshakes)
    pub kem: Arc<Mutex<static_crypto::KemKeypair>>,
    /// This node's Ed25519 identity signing key (handshake/gossip auth)
    pub identity_key: Arc<ed25519_dalek::SigningKey>,
    /// Cached Ed25519 identity public key bytes
    pub identity_public_key: [u8; 32],
    /// Per-peer swapped-chunk counts (1:1 TooManyFromPeer enforcement)
    pub peer_chunk_counts: Arc<Mutex<HashMap<NodeId, usize>>>,
    /// Node IDs previously connected but since disconnected
    ///
    /// Used to distinguish partition heals (reconnections) from
    /// first-time connections. Populated on disconnect, consumed on
    /// the next successful handshake with the same node ID.
    pub previously_connected: Arc<RwLock<HashSet<NodeId>>>,
    /// Whether this node is currently allowed to serve chunks
    ///
    /// Full nodes always serve. Backup-only nodes start dormant
    /// (`false`) and flip this to `true` when they activate after the
    /// primary's heartbeats (inbound activity) stop. Every other kind
    /// of traffic keeps flowing while dormant, so a dormant backup is
    /// indistinguishable from any other peer on the wire.
    pub serve_enabled: Arc<std::sync::atomic::AtomicBool>,
    /// Per-peer last inbound activity (heartbeat proxy)
    ///
    /// Every inbound message refreshes the sender's timestamp, so the
    /// map tracks "when did we last hear from this peer". Backup-only
    /// nodes monitor their primary's entry: once it exceeds the
    /// heartbeat timeout, the backup activates. Gossip (60 s cadence)
    /// keeps entries fresh for any connected, living peer.
    pub peer_activity: Arc<std::sync::Mutex<HashMap<NodeId, u64>>>,
    /// Whether this node accepts compute requests (advertised in handshakes)
    pub compute_enabled: bool,
    /// Maximum concurrent compute executions (advertised in handshakes)
    pub compute_capacity: u8,
    /// The transport implementation (TCP by default)
    pub transport: Arc<dyn Transport>,
    /// Recently seen handshake nonces (replay cache, nonce -> unix secs).
    ///
    /// Bounded at [`MAX_HANDSHAKE_NONCES`] with [`HANDSHAKE_NONCE_TTL_SECS`]
    /// TTL; std mutex (never held across await).
    pub handshake_nonces: Arc<std::sync::Mutex<HashMap<[u8; 32], u64>>>,
    /// Recently seen maintenance nonces (swap accept/commit/abort replay
    /// cache, nonce -> unix secs). Same bounds as handshakes.
    pub maintenance_nonces: Arc<std::sync::Mutex<HashMap<[u8; 32], u64>>>,
    /// Reassembly sessions for fragmented SURB chunk requests
    ///
    /// Session-based chunk requests embed a full SURB (~5.7 KiB) and do
    /// not fit a single Sphinx body, so they arrive as fragments keyed
    /// by the request's session id. Bounded: the manager caps at 64
    /// concurrent sessions with FIFO eviction and TTL cleanup.
    pub pending_requests: Arc<Mutex<crate::fragment::ReassemblyManager>>,
}

impl TransportState {
    /// Record inbound liveness for a peer (heartbeat proxy)
    ///
    /// Cheap, synchronous, and safe to call from async contexts: the
    /// lock is never held across an await.
    pub fn note_peer_activity(&self, peer: NodeId) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        self.peer_activity.lock().unwrap().insert(peer, now);
    }

    /// Expire pending 2-phase swaps that exceeded the timeout
    ///
    /// Called periodically by the node runner's lifecycle loop. For each
    /// expired swap: the reserved capacity is released (nothing was
    /// stored) and a `SwapAbort` is sent to the peer if a connection
    /// exists. Returns the number of swaps aborted.
    pub async fn expire_pending_swaps(&self) -> usize {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let expired = {
            let mut swaps = self.swap_state.lock().await;
            swaps.expire_pending_swaps(now, self.pending_swap_timeout_secs)
        };
        for swap in &expired {
            {
                let mut capacity = self.storage_capacity.lock().await;
                capacity.release_reserved(swap.reserved_bytes, false);
            }
            // Phase 7: signed abort, Sphinx-wrapped (no clear-text identity).
            let mut abort = create_swap_abort(
                swap.proposal_id,
                self.node_id,
                "pending swap timed out".to_string(),
                None,
            );
            abort.sign(&self.identity_key);
            if let Ok(json) = serde_json::to_vec(&abort) {
                send_swap_control_sphinx(self, swap.peer, MSG_BODY_SWAP_ABORT, &json).await;
            }
        }
        if !expired.is_empty() {
            debug!("Expired {} pending swap(s) past timeout", expired.len());
        }
        expired.len()
    }

    /// Begin a 2-phase swap as the proposer
    ///
    /// Records a pending swap for the proposal we are about to send so
    /// the peer's `SwapAccept` can be matched back to it. Call this
    /// immediately before sending the `SwapProposal`; the returned ID is
    /// the proposal ID the accept/commit/abort messages will carry. The
    /// pending swap waits for the retrieval phase (the return chunk's
    /// data arrives via `ChunkResponse` after the accept names it).
    pub async fn begin_swap_proposal(
        &self,
        peer: NodeId,
        proposal: &static_storage::swap::SwapProposal,
    ) -> [u8; 32] {
        let pid = static_storage::swap::proposal_id(proposal);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let mut swaps = self.swap_state.lock().await;
        swaps.start_pending_swap(PendingSwap {
            proposal_id: pid,
            peer,
            our_chunk_id: proposal.chunk_id,
            their_chunk_id: [0u8; 32],
            their_chunk_data: Vec::new(),
            reserved_bytes: 0,
            received_their_chunk: false,
            retrieval_requested: false,
            // The proposal's root/proof bind OUR offered chunk (which
            // the PEER will verify against). The return chunk we are
            // about to receive has no content binding in chunk-level
            // barter, so the all-zero root marks "no Merkle gate" for
            // our own retrieval.
            content_root: [0u8; 32],
            merkle_proof: static_storage::integrity::MerkleProof {
                leaf_index: 0,
                siblings: vec![],
            },
            sent_commit: false,
            received_commit: false,
            // The proposal's terms describe OUR offered chunk; the
            // return chunk's lease terms arrive with the peer's accept
            // and overwrite these. `content_pub_key` stays zero: the
            // return chunk carries no content binding in chunk-level
            // barter (the lease adopts the owner key on the first
            // signed heartbeat).
            renewal_token: [0u8; 32],
            lease_expires_at: 0,
            content_pub_key: [0u8; 32],
            started_at: now,
        });
        pid
    }

    /// Snapshot of per-peer last-activity timestamps
    ///
    /// Callers get an owned copy so the shared map is never locked
    /// across awaits or while other locks are held.
    pub fn peer_activity_snapshot(&self) -> HashMap<NodeId, u64> {
        self.peer_activity.lock().unwrap().clone()
    }

    /// Build a signed handshake for this node (unified format, no tier).
    pub async fn signed_handshake(&self) -> Handshake {
        use rand::RngCore;
        let mut nonce = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut nonce);
        let mut hs = Handshake {
            node_id: self.node_id,
            public_key: self.mix_node.lock().await.public_key,
            kem_public_key: Some(self.kem.lock().await.public_bytes()),
            compute_enabled: self.compute_enabled,
            compute_capacity: self.compute_capacity,
            identity_public_key: self.identity_public_key,
            nonce,
            signature: vec![],
        };
        {
            use ed25519_dalek::Signer;
            let sig = self.identity_key.sign(&hs.signing_bytes());
            hs.signature = sig.to_bytes().to_vec();
        }
        hs
    }

    /// Check-and-insert a handshake nonce (replay cache).
    ///
    /// Returns true if fresh (inserted), false if replayed. Prunes expired
    /// entries and bounds memory (FIFO eviction at cap).
    pub fn check_handshake_nonce(&self, nonce: &[u8; 32]) -> bool {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        if let Ok(mut cache) = self.handshake_nonces.lock() {
            cache.retain(|_, ts| now.saturating_sub(*ts) <= HANDSHAKE_NONCE_TTL_SECS);
            if cache.contains_key(nonce) {
                return false;
            }
            if cache.len() >= MAX_HANDSHAKE_NONCES {
                // FIFO-ish eviction: drop one arbitrary oldest entry.
                if let Some(oldest) = cache
                    .iter()
                    .min_by_key(|(_, ts)| **ts)
                    .map(|(k, _)| *k)
                {
                    cache.remove(&oldest);
                }
            }
            cache.insert(*nonce, now);
            true
        } else {
            true
        }
    }

    /// Check-and-insert a maintenance nonce (swap replay cache).
    ///
    /// Returns true if fresh (inserted), false if replayed. Same
    /// TTL/bounds as [`TransportState::check_handshake_nonce`].
    pub fn check_maintenance_nonce(&self, nonce: &[u8; 32]) -> bool {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        if let Ok(mut cache) = self.maintenance_nonces.lock() {
            cache.retain(|_, ts| now.saturating_sub(*ts) <= HANDSHAKE_NONCE_TTL_SECS);
            if cache.contains_key(nonce) {
                return false;
            }
            if cache.len() >= MAX_HANDSHAKE_NONCES {
                if let Some(oldest) = cache
                    .iter()
                    .min_by_key(|(_, ts)| **ts)
                    .map(|(k, _)| *k)
                {
                    cache.remove(&oldest);
                }
            }
            cache.insert(*nonce, now);
            true
        } else {
            true
        }
    }

    /// Build a hybrid route to `dest` (Phase 7, Task 2).
    ///
    /// Prefers a [`MIN_HOPS`]-intermediate anonymous route via
    /// [`RoutingTable::build_hybrid_route`]. Falls back to a direct 1-hop
    /// route only when the routing table cannot supply 3 KEM-capable
    /// intermediates (bootstrapping / 2-node test networks); production
    /// networks with enough peers always get 3 intermediates + dest.
    pub async fn build_route_to_destination(
        &self,
        dest: NodeId,
    ) -> Option<static_sphinx::HybridRoute> {
        let snapshot = {
            let table = self.routing_table.read().await;
            let dest_node = table.get_node(&dest).cloned()?;
            (dest_node.public_key, dest_node.kem_public_key.clone()?)
        };
        let (dest_pub, dest_kem) = snapshot;
        {
            let table = self.routing_table.read().await;
            if let Some(route) = table.build_hybrid_route(dest, dest_pub, &dest_kem) {
                return Some(route);
            }
        }
        // Fallback (documented MVP trade-off): direct route when the
        // network is too small for 3 intermediates.
        Some(static_sphinx::HybridRoute {
            hops: vec![static_sphinx::HybridRouteHop {
                node_id: dest,
                classical_public_key: dest_pub,
                kem_public_key: dest_kem,
            }],
            destination: dest,
        })
    }

    /// Build an anonymous return route to ourselves (Phase 7, Task 2).
    ///
    /// [`MIN_HOPS`] random KEM-capable intermediates + ourselves as the
    /// destination, so a responder sees only a random first hop — never
    /// our identity or address. Falls back to a direct self-route only
    /// when the table cannot supply 3 intermediates (bootstrap / small
    /// test networks).
    pub async fn build_self_return_route(&self) -> static_sphinx::HybridRoute {
        let our_pub = self.mix_node.lock().await.public_key;
        let our_kem = self.kem.lock().await.public_bytes();
        let intermediates: Vec<static_sphinx::HybridRouteHop> = {
            let table = self.routing_table.read().await;
            let mut candidates: Vec<&KnownNode> = table
                .nodes
                .values()
                .filter(|n| {
                    n.node_id != self.node_id && n.kem_public_key.is_some()
                })
                .collect();
            if candidates.len() < crate::routing::MIN_HOPS {
                Vec::new()
            } else {
                use rand::seq::SliceRandom;
                candidates.shuffle(&mut rand::thread_rng());
                candidates
                    .into_iter()
                    .take(crate::routing::MIN_HOPS)
                    .map(|n| static_sphinx::HybridRouteHop {
                        node_id: n.node_id,
                        classical_public_key: n.public_key,
                        kem_public_key: n.kem_public_key.clone().unwrap_or_default(),
                    })
                    .collect()
            }
        };
        let mut hops = intermediates;
        hops.push(static_sphinx::HybridRouteHop {
            node_id: self.node_id,
            classical_public_key: our_pub,
            kem_public_key: our_kem,
        });
        static_sphinx::HybridRoute { hops, destination: self.node_id }
    }

    /// Verify an inbound handshake + key continuity against routing table.
    ///
    /// Returns true if signature valid and no known-key mismatch.
    /// New peers are TOFU-pinned on first encounter. Handshake nonces
    /// are replay-cached (bounded, 5-min TTL): a replayed handshake
    /// byte-string is rejected.
    pub async fn verify_handshake(&self, hs: &Handshake) -> bool {
        if !hs.verify() {
            return false;
        }
        // Hybrid mandate: KEM required.
        if hs.kem_public_key.as_ref().map(|k: &Vec<u8>| k.len()).unwrap_or(0)
            != static_sphinx::HYBRID_KEM_PUBLIC_KEY_SIZE
        {
            return false;
        }
        // Nonce replay cache (H5, non-breaking): reject recently seen
        // nonces, prune expired, bound memory.
        if !self.check_handshake_nonce(&hs.nonce) {
            return false;
        }
        // Key continuity: known node_id must present same mix + identity keys.
        if let Some(known) = self.routing_table.read().await.get_node(&hs.node_id) {
            if known.public_key != hs.public_key {
                return false;
            }
            if let Some(stored) = known.identity_public_key {
                if stored != hs.identity_public_key {
                    return false;
                }
            }
        }
        true
    }
}

/// An inbound message from a peer
#[derive(Debug)]
pub struct InboundMessage {
    /// The sending peer's node ID
    pub from: NodeId,
    /// The message content
    pub message: WireMessage,
    /// Whether this peer was previously connected (partition heal)
    ///
    /// When true, the receiver should trigger accounting reconciliation
    /// with this peer. Transport sets this on the handshake-echo signal
    /// sent after a reconnection; all regular messages carry false.
    pub is_reconnection: bool,
}

/// Errors that can occur during transport operations
#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    /// I/O error
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    /// Wire protocol error
    #[error("wire protocol error: {0}")]
    Wire(#[from] wire::WireError),
    /// Sphinx processing error
    #[error("sphinx error: {0}")]
    Sphinx(#[from] static_sphinx::SphinxError),
    /// Connection not found
    #[error("connection not found for node: {0:?}")]
    ConnectionNotFound(NodeId),
    /// Handshake failed
    #[error("handshake failed: {0}")]
    HandshakeFailed(String),
    /// Channel send error
    #[error("channel send error")]
    ChannelSend,
}

/// Handle an incoming connection
///
/// Phase 7 encrypted handshake (mutual privacy):
/// 1. Read Hello (ephemeral keys + nonce, no identity)
/// 2. Send Welcome (server ephemeral + KEM ciphertext, no identity)
/// 3. Read client's encrypted identity (AEAD, identity hidden from observers)
/// 4. Send server's encrypted identity (AEAD, mutual privacy)
/// All messages share one padded size (indistinguishable).
pub async fn handle_incoming_connection(
    connection: Box<dyn Connection>,
    addr: String,
    state: Arc<TransportState>,
) {
    debug!("Incoming connection from {}", addr);

    // Message 1: read Hello.
    let hello = match read_wire_message(&connection, &addr).await {
        Some(WireMessage::Hello(h)) => h,
        Some(_) => {
            warn!("Expected hello, got other message from {}", addr);
            return;
        }
        None => {
            warn!("Peer {} disconnected during handshake (hello)", addr);
            return;
        }
    };
    // Replay-cache the ephemeral nonce.
    if !state.check_handshake_nonce(&hello.nonce) {
        warn!("Rejected hello with replayed nonce from {}", addr);
        return;
    }

    // Server ephemeral keys + encapsulation to client's ephemeral KEM key.
    let server_dh = static_crypto::DhKeypair::random();
    let server_kem = static_crypto::KemKeypair::random();
    let (kem_shared, kem_ct) =
        match static_crypto::KemKeypair::encapsulate_to(&hello.eph_kem_pub_key) {
            Ok(v) => v,
            Err(_) => {
                warn!("Bad ephemeral KEM key in hello from {}", addr);
                return;
            }
        };
    let peer_eph_pub = x25519_dalek::PublicKey::from(hello.eph_pub_key);
    let dh_shared = server_dh.dh(&peer_eph_pub);
    let handshake_secret = derive_handshake_secret(&dh_shared, &kem_shared);
    let mut server_nonce = [0u8; 32];
    {
        use rand::RngCore;
        rand::rngs::OsRng.fill_bytes(&mut server_nonce);
    }

    // Message 2: send Welcome.
    let welcome = Welcome {
        eph_pub_key: server_dh.public.as_bytes().to_owned(),
        eph_kem_pub_key: server_kem.public_bytes(),
        nonce: server_nonce,
        kem_ciphertext: kem_ct,
    };
    if send_wire_message(&connection, &WireMessage::Welcome(welcome.clone()), &addr).await.is_err() {
        return;
    }

    // Message 3: read client's encrypted identity.
    let client_enc = match read_wire_message(&connection, &addr).await {
        Some(WireMessage::AuthIdentity(a)) => a,
        Some(_) => {
            warn!("Expected encrypted identity, got other from {}", addr);
            return;
        }
        None => {
            warn!("Peer {} disconnected during handshake (identity)", addr);
            return;
        }
    };
    let aad = handshake_session_aad(&hello.nonce, &server_nonce);
    let Some(client_hs) = decrypt_identity(&handshake_secret, &client_enc, &aad) else {
        warn!("Failed to decrypt client identity from {}", addr);
        return;
    };
    if !state.verify_handshake(&client_hs).await {
        warn!("Rejected client identity with bad signature/KEM from {}", addr);
        return;
    }

    // Message 4: send server's encrypted identity (mutual privacy).
    let our_hs = state.signed_handshake().await;
    let server_enc = encrypt_identity(&handshake_secret, &our_hs, &aad);
    if send_wire_message(&connection, &WireMessage::AuthIdentity(server_enc), &addr)
        .await
        .is_err()
    {
        return;
    }

    finish_inbound_handshake(connection, addr, state, client_hs).await;
}

/// Complete an inbound handshake after authentication.
///
/// Shared tail for the Phase 7 flow: routing-table insert, connection
/// setup, reconnection signal, and spawn of the connection loop.
async fn finish_inbound_handshake(
    connection: Box<dyn Connection>,
    addr: String,
    state: Arc<TransportState>,
    hs: Handshake,
) {
    // Add to routing table
    state.routing_table.write().await.add_node(KnownNode {
        node_id: hs.node_id,
        public_key: hs.public_key,
        address: addr.clone(),
        kem_public_key: hs.kem_public_key.clone(),
        compute_enabled: hs.compute_enabled,
        compute_capacity: hs.compute_capacity,
        identity_public_key: Some(hs.identity_public_key),
    });

    // Set up connection
    let (tx, rx) = mpsc::channel::<WireMessage>(CHANNEL_BUFFER);
    state.connections.write().await.insert(hs.node_id, tx.clone());
    // The handshake itself proves the peer is alive.
    state.note_peer_activity(hs.node_id);

    // Partition-heal detection: if this node ID was connected
    // before, this handshake is a reconnection. Signal the
    // runner via a handshake-echo InboundMessage so it can
    // trigger accounting reconciliation.
    if state.previously_connected.write().await.remove(&hs.node_id) {
        let _ = state
            .inbound_tx
            .send(InboundMessage {
                from: hs.node_id,
                message: WireMessage::Handshake(hs.clone()),
                is_reconnection: true,
            })
            .await;
    }

    // Enter the connection loop
    let shared: Arc<dyn Connection> = Arc::from(connection);
    let write_state = state.clone();
    let peer_id = hs.node_id;
    tokio::spawn(async move {
        connection_loop(shared, rx, write_state, peer_id).await;
    });
}

/// Read a single framed wire message (helper for handshakes).
async fn read_wire_message(
    connection: &Box<dyn Connection>,
    addr: &str,
) -> Option<WireMessage> {
    let mut buf = vec![0u8; READ_BUFFER_SIZE];
    let mut read_buf = bytes::BytesMut::with_capacity(READ_BUFFER_SIZE);
    loop {
        let n = match connection.recv_bytes(&mut buf).await {
            Ok(Some(n)) => n,
            Ok(None) => {
                warn!("Peer {} disconnected during handshake", addr);
                return None;
            }
            Err(e) => {
                warn!("Error reading handshake from {}: {}", addr, e);
                return None;
            }
        };
        read_buf.extend_from_slice(&buf[..n]);
        match try_read_message(&mut read_buf) {
            Ok(Some(msg)) => return Some(msg),
            Ok(None) => continue,
            Err(e) => {
                warn!("Wire error from {}: {}", addr, e);
                return None;
            }
        }
    }
}

/// Send a single framed wire message (helper for handshakes).
async fn send_wire_message(
    connection: &Box<dyn Connection>,
    msg: &WireMessage,
    addr: &str,
) -> Result<(), ()> {
    let mut write_buf = bytes::BytesMut::new();
    if let Err(e) = write_message(&mut write_buf, msg) {
        warn!("Failed to serialize handshake for {}: {}", addr, e);
        return Err(());
    }
    if let Err(e) = connection.send_bytes(&write_buf).await {
        warn!("Failed to send handshake to {}: {}", addr, e);
        return Err(());
    }
    Ok(())
}

/// Connect to a peer
///
/// Phase 7 encrypted handshake (mirrors [`handle_incoming_connection`]):
/// Hello -> Welcome -> ClientAuth -> ServerAuth. Identities stay AEAD-
/// encrypted; an observer learns nothing about either peer.
pub async fn connect_to_peer(
    addr: SocketAddr,
    state: Arc<TransportState>,
) -> Result<(), TransportError> {
    debug!("Connecting to {}", addr);

    let connection = state.transport.connect(&addr.to_string()).await?;

    // Message 1: send Hello (fresh ephemeral keys + nonce).
    let client_dh = static_crypto::DhKeypair::random();
    let client_kem = static_crypto::KemKeypair::random();
    let mut client_nonce = [0u8; 32];
    {
        use rand::RngCore;
        rand::rngs::OsRng.fill_bytes(&mut client_nonce);
    }
    let hello = Hello {
        eph_pub_key: client_dh.public.as_bytes().to_owned(),
        eph_kem_pub_key: client_kem.public_bytes(),
        nonce: client_nonce,
    };
    {
        let mut write_buf = bytes::BytesMut::new();
        write_message(&mut write_buf, &WireMessage::Hello(hello.clone()))?;
        connection
            .send_bytes(&write_buf)
            .await
            .map_err(|e| TransportError::HandshakeFailed(format!("hello send: {}", e)))?;
    }

    // Message 2: read Welcome.
    let welcome = match read_wire_message(&connection, &addr.to_string()).await {
        Some(WireMessage::Welcome(w)) => w,
        Some(_) => {
            return Err(TransportError::HandshakeFailed("expected welcome".into()));
        }
        None => return Err(TransportError::HandshakeFailed("peer disconnected".into())),
    };
    if !state.check_handshake_nonce(&welcome.nonce) {
        return Err(TransportError::HandshakeFailed("welcome nonce replay".into()));
    }
    // Derive the shared secret: DH + decapsulated KEM.
    let server_eph_pub = x25519_dalek::PublicKey::from(welcome.eph_pub_key);
    let dh_shared = client_dh.dh(&server_eph_pub);
    let kem_shared = client_kem
        .decapsulate(&welcome.kem_ciphertext)
        .map_err(|_| TransportError::HandshakeFailed("KEM decapsulation failed".into()))?;
    let handshake_secret = derive_handshake_secret(&dh_shared, &kem_shared);
    let aad = handshake_session_aad(&client_nonce, &welcome.nonce);

    // Message 3: send client's encrypted identity.
    let our_hs = state.signed_handshake().await;
    let client_enc = encrypt_identity(&handshake_secret, &our_hs, &aad);
    {
        let mut write_buf = bytes::BytesMut::new();
        write_message(&mut write_buf, &WireMessage::AuthIdentity(client_enc))?;
        connection
            .send_bytes(&write_buf)
            .await
            .map_err(|e| TransportError::HandshakeFailed(format!("identity send: {}", e)))?;
    }

    // Message 4: read server's encrypted identity.
    let server_hs = match read_wire_message(&connection, &addr.to_string()).await {
        Some(WireMessage::AuthIdentity(a)) => {
            decrypt_identity(&handshake_secret, &a, &aad).ok_or_else(|| {
                TransportError::HandshakeFailed("server identity decrypt failed".into())
            })?
        }
        Some(_) => {
            return Err(TransportError::HandshakeFailed("expected server identity".into()));
        }
        None => return Err(TransportError::HandshakeFailed("peer disconnected".into())),
    };
    if !state.verify_handshake(&server_hs).await {
        return Err(TransportError::HandshakeFailed("bad server identity/KEM".into()));
    }
    let hs = server_hs;

    // Add to routing table
    state.routing_table.write().await.add_node(KnownNode {
        node_id: hs.node_id,
        public_key: hs.public_key,
        address: addr.to_string(),
        kem_public_key: hs.kem_public_key.clone(),
        compute_enabled: hs.compute_enabled,
        compute_capacity: hs.compute_capacity,
        identity_public_key: Some(hs.identity_public_key),
    });

    let (tx, rx) = mpsc::channel::<WireMessage>(CHANNEL_BUFFER);
    state.connections.write().await.insert(hs.node_id, tx.clone());
    // The handshake itself proves the peer is alive.
    state.note_peer_activity(hs.node_id);

    // Partition-heal detection (outbound side).
    if state.previously_connected.write().await.remove(&hs.node_id) {
        debug!("Partition heal detected (outbound) with {:02x?}", hs.node_id);
        let _ = state
            .inbound_tx
            .send(InboundMessage {
                from: hs.node_id,
                message: WireMessage::Handshake(hs.clone()),
                is_reconnection: true,
            })
            .await;
    }

    let shared: Arc<dyn Connection> = Arc::from(connection);
    let write_state = state.clone();
    let peer_id = hs.node_id;
    tokio::spawn(async move {
        connection_loop(shared, rx, write_state, peer_id).await;
    });

    Ok(())
}

/// Connection loop for an established peer connection
///
/// Multiplexes, via `tokio::select!`: outgoing real messages from the
/// channel, constant-rate cover traffic, and incoming wire frames from
/// the peer. Real traffic is shaped through the per-node token bucket:
/// when empty, messages queue locally instead of bursting (constant-rate
/// invariant). Runs until the connection dies.
async fn connection_loop(
    connection: Arc<dyn Connection>,
    mut rx: mpsc::Receiver<WireMessage>,
    state: Arc<TransportState>,
    peer_id: NodeId,
) {
    // Refresh config each tick (tier/CLI changes propagate without restart).
    let mut interval = time::interval(Duration::from_millis(
        state.cover_config.read().await.interval_ms.max(10),
    ));
    let mut bytes_this_interval: u64 = 0;
    let mut read_buf = bytes::BytesMut::with_capacity(READ_BUFFER_SIZE);
    let mut read_chunk = vec![0u8; READ_BUFFER_SIZE];
    // Bounded local queue for shaped real traffic (backpressure, no OOM).
    let mut pending_real: std::collections::VecDeque<WireMessage> = std::collections::VecDeque::new();
    const MAX_PENDING: usize = 512;

    async fn flush_pending(
        connection: &Arc<dyn Connection>,
        state: &Arc<TransportState>,
        _peer_id: &NodeId,
        pending_real: &mut std::collections::VecDeque<WireMessage>,
        bytes_this_interval: &mut u64,
    ) {
        while let Some(front) = pending_real.front() {
            let mut wire_buf = bytes::BytesMut::new();
            if write_message(&mut wire_buf, front).is_err() {
                pending_real.pop_front();
                continue;
            }
            let msg_bytes = wire_buf.len() as u64;
            let can_send = { state.cover_bucket.lock().await.try_consume(msg_bytes) };
            if !can_send {
                break;
            }
            let msg = pending_real.pop_front().unwrap();
            let mut wire_buf = bytes::BytesMut::new();
            if write_message(&mut wire_buf, &msg).is_err() {
                continue;
            }
            if connection.send_bytes(&wire_buf).await.is_err() {
                break;
            }
            *bytes_this_interval += msg_bytes;
            state.total_bytes_sent.fetch_add(msg_bytes, std::sync::atomic::Ordering::Relaxed);
            state.total_real_bytes_sent.fetch_add(msg_bytes, std::sync::atomic::Ordering::Relaxed);
        }
    }

    'conn: loop {
        tokio::select! {
            // Real message to send (shaped)
            Some(msg) = rx.recv() => {
                let mut wire_buf = bytes::BytesMut::new();
                if let Err(e) = write_message(&mut wire_buf, &msg) {
                    warn!("Failed to serialize message: {}", e);
                    continue;
                }

                let msg_bytes = wire_buf.len() as u64;
                let can_send = { state.cover_bucket.lock().await.try_consume(msg_bytes) };
                if can_send {
                    if let Err(e) = connection.send_bytes(&wire_buf).await {
                        warn!("Write error: {}", e);
                        break;
                    }
                    bytes_this_interval += msg_bytes;
                    state.total_bytes_sent.fetch_add(msg_bytes, std::sync::atomic::Ordering::Relaxed);
                    state.total_real_bytes_sent.fetch_add(msg_bytes, std::sync::atomic::Ordering::Relaxed);
                } else {
                    // Queue instead of bursting (constant-rate invariant).
                    if pending_real.len() >= MAX_PENDING {
                        pending_real.pop_front();
                        warn!("Shaper queue full, dropping oldest");
                    }
                    pending_real.push_back(msg);
                }
            }

            // Cover traffic tick (P1-cover: per-node fair share).
            _ = interval.tick() => {
                let cfg = state.cover_config.read().await.clone();
                // Keep bucket rate in sync with config.
                {
                    let mut bucket = state.cover_bucket.lock().await;
                    let cap = cfg.target_rate_bps.saturating_mul(2).max(4096);
                    bucket.set_rate(cfg.target_rate_bps, cap);
                }
                // Per-node total stays constant: divide the interval
                // budget by peer count so C=100 does not send 100x cover.
                // Single lock, dropped before any send.
                let peer_count = {
                    let conns = state.connections.read().await;
                    conns.len().max(1) as u64
                };
                let total_target = (cfg.target_rate_bps * cfg.interval_ms) / 1000;
                let target_bytes_per_interval = total_target / peer_count.max(1);
                // Drain queued real traffic first (still rate-limited).
                flush_pending(&connection, &state, &peer_id, &mut pending_real, &mut bytes_this_interval).await;
                let remaining = target_bytes_per_interval.saturating_sub(bytes_this_interval);

                if remaining > 0 && cfg.enabled {
                    // Hybrid-only cover (Phase 7): valid Sphinx when the
                    // peer's keys are known, size-realistic dummy otherwise.
                    let dummy_msg = {
                        let table = state.routing_table.read().await;
                        valid_cover_message(&peer_id, &table, remaining as usize)
                            .unwrap_or_else(|| dummy_sphinx_message(true, remaining as usize))
                    };
                    let mut wire_buf = bytes::BytesMut::new();

                    if write_message(&mut wire_buf, &dummy_msg).is_err() {
                        bytes_this_interval = 0;
                        continue;
                    }

                    let cover_bytes = wire_buf.len() as u64;
                    // Cover also consumes bucket so long-term rate holds.
                    { state.cover_bucket.lock().await.try_consume(cover_bytes); }
                    if connection.send_bytes(&wire_buf).await.is_err() {
                        break;
                    }

                    state.total_bytes_sent.fetch_add(cover_bytes, std::sync::atomic::Ordering::Relaxed);
                    state.total_cover_bytes_sent.fetch_add(cover_bytes, std::sync::atomic::Ordering::Relaxed);
                }

                // Reset interval
                bytes_this_interval = 0;
            }

            // Incoming bytes from the peer
            read_result = connection.recv_bytes(&mut read_chunk) => {
                match read_result {
                    Ok(Some(n)) => {
                        read_buf.extend_from_slice(&read_chunk[..n]);
                        // Process all complete messages in the buffer
                        loop {
                            match try_read_message(&mut read_buf) {
                                Ok(Some(msg)) => {
                                    if let Err(e) = handle_message(msg, &state, peer_id).await {
                                        warn!("Error handling message: {}", e);
                                    }
                                }
                                Ok(None) => break, // Need more data
                                Err(e) => {
                                    warn!("Wire error: {}", e);
                                    break 'conn;
                                }
                            }
                        }
                    }
                    Ok(None) => {
                        info!("Peer disconnected");
                        break;
                    }
                    Err(e) => {
                        warn!("Read error: {}", e);
                        break;
                    }
                }
            }
        }
    }

    // Clean up connection and remember the peer for heal detection.
    // A later handshake with the same node ID is a partition heal,
    // not a first-time connection.
    state.previously_connected.write().await.insert(peer_id);
    state.connections.write().await.remove(&peer_id);
    let _ = connection.close().await;
}

/// Normalized result of one Sphinx hop (classical or hybrid)
///
/// Both [`process_packet`] and `process_packet_hybrid_with_keys` produce
/// the same routing outcome; this lets the delivery logic below stay
/// version-agnostic.
struct HopOutcome {
    /// The routing flag
    flag: RoutingFlag,
    /// The next hop's node ID
    next_hop: NodeId,
    /// The packet to forward (None if destination)
    forward_packet: Option<SphinxPacket>,
    /// The decrypted body (Some only at destination)
    body: Option<Vec<u8>>,
}

/// Handle an incoming message from a peer
/// Dispatch one inbound wire message against a transport state
///
/// Public so tests (and the node runner) can drive the protocol state
/// machine directly, including the swap retrieval hook
/// ([`handle_swap_chunk_retrieval`]).
pub async fn handle_message(
    msg: WireMessage,
    state: &Arc<TransportState>,
    from: NodeId,
) -> Result<(), TransportError> {
    // Any inbound message is proof of life: refresh the peer's
    // liveness timestamp (backup nodes use this as the heartbeat).
    state.note_peer_activity(from);
    match msg {
        WireMessage::Handshake(_) => {
            warn!("Unexpected handshake from connected peer");
        }
        WireMessage::Hello(_)| WireMessage::Welcome(_) | WireMessage::AuthIdentity(_) => {
            warn!("Unexpected handshake-phase message from connected peer");
        }
        WireMessage::Sphinx(packet) => {
            // Hybrid-only mandate (Phase 0, Q2): classical v0 rejected.
            if packet.header.version != static_sphinx::SPHINX_VERSION_HYBRID {
                return Ok(());
            }
            let kem_secret = state.kem.lock().await.secret_bytes();
            let outcome = {
                let mut mix_node = state.mix_node.lock().await;
                let result = static_sphinx::process_packet_hybrid_with_keys(
                    &mut mix_node,
                    &kem_secret,
                    packet,
                )?;
                drop(mix_node);
                HopOutcome {
                    flag: result.flag,
                    next_hop: result.next_hop,
                    forward_packet: result.forward_packet,
                    body: result.body,
                }
            };

            match outcome.flag {
                RoutingFlag::Destination => {
                    // We are the destination - try to handle as chunk request
                    if let Some(body) = outcome.body {
                        // Try to parse as a single-body chunk request
                        if static_storage::retrieval::deserialize_request(&body).is_ok() {
                            // Building and sending the response runs in a
                            // detached task: this handler executes INLINE
                            // in the peer connection's read loop, and
                            // blocking here on the node's own outbound
                            // channel would deadlock (the connection loop
                            // is the only drainer).
                            let state_for_serve = state.clone();
                            tokio::spawn(async move {
                                serve_chunk_request(state_for_serve, body).await;
                            });
                        } else {
                            match try_feed_surb_request_fragment(state, &body).await {
                                // Not a fragmented SURB request: app channel.
                                None => {
                                    let _ = state.inbound_tx.send(InboundMessage {
                                        from,
                                        message: WireMessage::Sphinx(SphinxPacket {
                                            header: static_sphinx::SphinxHeader {
                                                version: static_sphinx::SPHINX_VERSION_HYBRID,
                                                ephemeral_key: [0u8; 32],
                                                session_id: [0u8; SESSION_ID_SIZE],
                                                routing_info: vec![],
                                                mac: [0u8; 16],
                                            },
                                            kem_ciphertexts: Vec::new(),
                                            body,
                                        }),
                                        is_reconnection: false,
                                    }).await;
                                }
                                // Consumed; request still incomplete.
                                Some(None) => {}
                                Some(Some(request_bytes)) => {
                                    // Completed fragmented SURB chunk
                                    // request — serve it (detached task).
                                    let state_for_serve = state.clone();
                                    tokio::spawn(async move {
                                        serve_chunk_request(state_for_serve, request_bytes).await;
                                    });
                                }
                            }
                        }
                    }
                }
                RoutingFlag::Forward => {
                    // Forward to the next hop
                    if let Some(forward_packet) = outcome.forward_packet {
                        let next_hop = outcome.next_hop;
                        let connections = state.connections.read().await;
                        
                        if let Some(sender) = connections.get(&next_hop) {
                            if sender.send(WireMessage::Sphinx(forward_packet)).await.is_err() {
                                warn!("Failed to forward: channel closed");
                            }
                        }
                    }
                }
            }
        }
        WireMessage::SessionReply(reply) => {
            // Lightweight reply-session processing (no KEM, no routing
            // MAC): session lookup, nonce anti-replay, one XOR body
            // layer peel, forward or deliver. Single mix-node lock, no
            // nesting.
            let result = {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                let mut mix_node = state.mix_node.lock().await;
                static_sphinx::process_session_reply(&mut mix_node, reply, now)
            };
            match result {
                Ok(outcome) => {
                    if outcome.is_final {
                        // We are the reply destination: deliver the
                        // end-to-end AEAD ciphertext to the application.
                        let _ = state.inbound_tx.send(InboundMessage {
                            from: outcome.next_hop,
                            message: WireMessage::SessionReply(outcome.reply),
                            is_reconnection: false,
                        }).await;
                    } else {
                        // Intermediate hop: forward to the cached next hop.
                        let connections = state.connections.read().await;
                        if let Some(sender) = connections.get(&outcome.next_hop) {
                            if sender
                                .send(WireMessage::SessionReply(outcome.reply))
                                .await
                                .is_err()
                            {
                                debug!("Session reply forward failed: channel closed");
                            }
                        }
                    }
                }
                Err(e) => {
                    debug!("Session reply dropped: {}", e);
                }
            }
        }
    }
    Ok(())
}

/// Serve a chunk request at this node (holder side)
///
/// Handles both return-path kinds:
/// - SURB-based: the request embeds a serialized SURB; the first
///   response fragment travels as a normal Sphinx packet wrapped with
///   the full SURB (establishing the session at every hop), subsequent
///   fragments travel as lightweight session replies. All are sent to
///   the SURB's first hop.
/// - Return-route (legacy): every fragment is a full Sphinx packet over
///   the plaintext return route.
///
/// Dormant backup nodes (serve_enabled false) do not serve.
async fn serve_chunk_request(state: Arc<TransportState>, request_body: Vec<u8>) {
    // Dormant backup nodes hold chunks but do not serve them. All other
    // traffic keeps flowing, so a dormant backup remains
    // indistinguishable from any other peer.
    if !state.serve_enabled.load(std::sync::atomic::Ordering::Relaxed) {
        return;
    }
    let Ok(request) = static_storage::retrieval::deserialize_request(&request_body) else {
        return;
    };

    // Look up the chunk in our holder
    let chunk_data = {
        let holder = state.chunk_holder.lock().await;
        holder.get_chunk(&request.chunk_id).map(|d| d.clone())
    };

    if request.surb.is_some() {
        // Session-based response path (no return route needed).
        match handle_retrieval_request_with_surb(&request_body, chunk_data.as_deref()) {
            Ok(packets) => {
                let connections = state.connections.read().await;
                if let Some(sender) = connections.get(&packets.first_hop) {
                    let _ = sender.send(WireMessage::Sphinx(packets.first_packet)).await;
                    for reply in packets.session_replies {
                        let _ = sender.send(WireMessage::SessionReply(reply)).await;
                    }
                }
            }
            Err(_) => {}
        }
        return;
    }

    // Return-route path (Phase 0 hybrid mandate): resolve KEM keys for
    // the return route from our routing table.
    let kem_map: HashMap<NodeId, Vec<u8>> = {
        let table = state.routing_table.read().await;
        table
            .nodes
            .iter()
            .filter_map(|(id, n)| n.kem_public_key.as_ref().map(|k| (*id, k.clone())))
            .collect()
    };
    let kem_lookup = move |id: &NodeId| kem_map.get(id).cloned();
    if let Ok(response_packets) = handle_retrieval_request(
        &request_body,
        chunk_data.as_deref(),
        &kem_lookup,
    ) {
        if request.return_route.hops.is_empty() {
            return;
        }
        let first_hop = request.return_route.hops[0].node_id;
        for resp_packet in response_packets {
            let connections = state.connections.read().await;
            if let Some(sender) = connections.get(&first_hop) {
                let _ = sender.send(WireMessage::Sphinx(resp_packet)).await;
            }
        }
    }
}

/// Feed a Sphinx destination body into the SURB chunk-request reassembler
///
/// Bodies in the fragmented SURB chunk-request format
/// (`[MSG_SURB_CHUNK_REQUEST][32-byte session id][fragment]`) are keyed
/// by the request's session id. Returns `None` when the body is not a
/// fragmented SURB chunk request (the caller falls through to the
/// application inbound channel); `Some(None)` when the fragment was
/// buffered but the request is incomplete; `Some(Some(bytes))` when the
/// full request has been reassembled.
async fn try_feed_surb_request_fragment(
    state: &Arc<TransportState>,
    body: &[u8],
) -> Option<Option<Vec<u8>>> {
    // Wrapper layout inside one Sphinx plaintext body: 1 type byte +
    // 32-byte session id + compact fragment (12-byte header + data).
    // The plaintext is always BODY_SIZE (zero-padded); only the marker
    // and minimum length discriminate.
    if body.len() < 1 + SESSION_ID_SIZE + crate::fragment::FRAGMENT_HEADER_SIZE {
        return None;
    }
    if body[0] != MSG_SURB_CHUNK_REQUEST {
        return None;
    }
    let mut session_id = [0u8; SESSION_ID_SIZE];
    session_id.copy_from_slice(&body[1..1 + SESSION_ID_SIZE]);
    let fragment =
        crate::fragment::deserialize_fragment(&body[1 + SESSION_ID_SIZE..]).ok()?;
    let key = u64::from_be_bytes(session_id[..8].try_into().ok()?);
    let mut mgr = state.pending_requests.lock().await;
    mgr.cleanup_expired(SURB_REQUEST_TIMEOUT_SECS);
    if !mgr.add_fragment(key, fragment) {
        return Some(None);
    }
    let complete = mgr.get(key)?.is_complete();
    if !complete {
        return Some(None);
    }
    let data = mgr.get(key)?.reassemble().ok()?;
    mgr.remove(key);
    Some(Some(data))
}

/// Check sender key continuity for a maintenance message (Phase 7).
///
/// When the claimed sender is a known routing-table entry with a pinned
/// identity key, the message's key must match; otherwise the message is
/// rejected (impersonation). Unknown senders pass here — the message
/// signature itself is still verified by the caller.
async fn check_maintenance_sender(
    state: &Arc<TransportState>,
    claimed: &NodeId,
    presented_identity: &[u8; 32],
) -> bool {
    let table = state.routing_table.read().await;
    match table.get_node(claimed) {
        Some(known) => match known.identity_public_key {
            Some(stored) => stored == *presented_identity,
            None => true,
        },
        None => true,
    }
}

/// Send a signed swap rejection Sphinx-wrapped (helper for handlers).
async fn send_maintenance_reject(
    state: &Arc<TransportState>,
    dest: NodeId,
    proposal_id: [u8; 32],
    reason: static_storage::swap::SwapRejectReason,
) {
    let reject = create_swap_reject(state.node_id, proposal_id, reason);
    if let Ok(json) = serde_json::to_vec(&reject) {
        send_maintenance_sphinx(state, dest, MSG_BODY_SWAP_REJECT, &json).await;
    }
}

/// Handle a Sphinx-delivered gossip message (Phase 7, Task 1).
///
/// Sender authentication is the Ed25519 gossip signature (verified inside
/// `process_gossip`) — no TCP-connection binding, which Sphinx delivery
/// cannot provide by design.
pub async fn handle_maintenance_gossip(
    state: &Arc<TransportState>,
    gossip: PeerGossip,
) {
    state.note_peer_activity(gossip.from_node);
    let new_peers = state.routing_table.write().await.process_gossip(&gossip);
    if new_peers > 0 {
        debug!("Added {} new peers from Sphinx gossip", new_peers);
    }
}

/// Handle a Sphinx-delivered swap proposal (Phase 7, Task 1).
///
/// Same prepare-phase logic as the former direct-wire handler, except:
/// sender identity rests on the content signature (not the TCP peer),
/// and the accept/reject goes back Sphinx-wrapped to the claimed sender.
/// A forged `from_node` only misdirects our response (the victim drops
/// it for want of a matching pending proposal), so spoofing gains nothing.
pub async fn handle_maintenance_proposal(
    state: &Arc<TransportState>,
    proposal: SwapProposal,
) {
    let sender = proposal.from_node;
    state.note_peer_activity(sender);
    // Validate the proposal (lease + content signature; no content_id).
    let current_time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    // Reconcile the shared capacity counter with holder reality
    // before deciding (incremental counter hygiene).
    let actual_bytes = {
        let holder = state.chunk_holder.lock().await;
        holder.total_bytes()
    };
    {
        let mut capacity = state.storage_capacity.lock().await;
        capacity.reconcile(actual_bytes);
    }

    let peer_chunks = {
        state.peer_chunk_counts.lock().await.get(&sender).copied().unwrap_or(0)
    };
    let capacity = state.storage_capacity.lock().await;
    let result = decide_on_swap(
        &proposal,
        &capacity,
        peer_chunks,
        static_storage::CHUNK_SIZE + 16,
        current_time,
    );
    drop(capacity);

    match result {
        Ok(()) => {
            // Select a real return chunk (first held, excluding offered).
            let return_entry: Option<static_storage::ChunkId> = {
                let holder = state.chunk_holder.lock().await;
                holder
                    .chunks
                    .iter()
                    .find(|(id, _)| **id != proposal.chunk_id)
                    .map(|(id, _data)| *id)
            };
            let Some(ret_id) = return_entry else {
                let pid = static_storage::swap::proposal_id(&proposal);
                send_maintenance_reject(
                    state,
                    sender,
                    pid,
                    static_storage::swap::SwapRejectReason::NoCapacity,
                )
                .await;
                return;
            };
            // DoS bound: too many pending swaps pin too much memory.
            {
                let swaps = state.swap_state.lock().await;
                if swaps.pending_swaps.len() >= MAX_PENDING_SWAPS {
                    let pid = static_storage::swap::proposal_id(&proposal);
                    send_maintenance_reject(
                        state,
                        sender,
                        pid,
                        static_storage::swap::SwapRejectReason::NoCapacity,
                    )
                    .await;
                    return;
                }
            }
            // Prepare phase: reserve capacity atomically (re-check under
            // the same lock that reserves) but store nothing.
            let chunk_len = (static_storage::CHUNK_SIZE + 16) as u64;
            {
                let mut capacity = state.storage_capacity.lock().await;
                if !capacity.can_accept(chunk_len, peer_chunks) {
                    let pid = static_storage::swap::proposal_id(&proposal);
                    send_maintenance_reject(
                        state,
                        sender,
                        pid,
                        static_storage::swap::SwapRejectReason::NoCapacity,
                    )
                    .await;
                    return;
                }
                capacity.reserve(chunk_len);
            }
            // Track the pending 2-phase swap (data arrives via retrieval).
            let pid = static_storage::swap::proposal_id(&proposal);
            {
                let mut swaps = state.swap_state.lock().await;
                swaps.remove_proposal(&pid);
                swaps.start_pending_swap(PendingSwap {
                    proposal_id: pid,
                    peer: sender,
                    our_chunk_id: ret_id,
                    their_chunk_id: proposal.chunk_id,
                    their_chunk_data: Vec::new(),
                    reserved_bytes: chunk_len,
                    received_their_chunk: false,
                    retrieval_requested: false,
                    content_root: proposal.content_root,
                    merkle_proof: proposal.merkle_proof.clone(),
                    sent_commit: false,
                    received_commit: false,
                    renewal_token: proposal.lease.renewal_token,
                    lease_expires_at: proposal.lease.expires_at,
                    content_pub_key: proposal.content_public_key,
                    started_at: current_time,
                });
            }

            // Signed accept (Phase 7, H2-H3), Sphinx-wrapped.
            let master_key = state.storage_key.lock().await.clone();
            let mut accept = create_swap_accept(state.node_id, ret_id, &master_key, pid, 86400);
            accept.sign(&state.identity_key);
            if let Ok(json) = serde_json::to_vec(&accept) {
                send_maintenance_sphinx(state, sender, MSG_BODY_SWAP_ACCEPT, &json).await;
            }
        }
        Err(reason) => {
            let pid = static_storage::swap::proposal_id(&proposal);
            state.swap_state.lock().await.remove_proposal(&pid);
            state.swap_state.lock().await.rejected_swaps += 1;
            send_maintenance_reject(state, sender, pid, reason).await;
        }
    }
}

/// Handle a Sphinx-delivered swap accept (Phase 7, Tasks 1+6).
///
/// Verifies the acceptor signature + continuity + nonce replay, binds to
/// the pending swap's peer (not the TCP connection), reserves capacity,
/// and waits for the retrieval phase. Failures send a signed abort.
pub async fn handle_maintenance_accept(
    state: &Arc<TransportState>,
    accept: SwapAccept,
) {
    let sender = accept.from_node;
    state.note_peer_activity(sender);
    // Auth: signature, continuity, replay.
    if !accept.verify_signature() {
        return;
    }
    if !check_maintenance_sender(state, &sender, &accept.identity_public_key).await {
        return;
    }
    if !state.check_maintenance_nonce(&accept.nonce) {
        return;
    }
    let pid = accept.proposal_id;
    // Bind to our pending proposal AND its peer (anti-spoof).
    let peer_ok = {
        let swaps = state.swap_state.lock().await;
        swaps
            .get_pending_swap(&pid)
            .is_some_and(|swap| swap.peer == sender)
    };
    if !peer_ok {
        return;
    }
    let chunk_len = (static_storage::CHUNK_SIZE + 16) as u64;
    let fits = {
        let mut capacity = state.storage_capacity.lock().await;
        let fits = capacity.can_accept(chunk_len, 0);
        if fits {
            capacity.reserve(chunk_len);
        }
        fits
    };
    if !fits {
        let swap = state.swap_state.lock().await.abort_swap(&pid);
        if let Some(swap) = swap {
            state.storage_capacity.lock().await.release_reserved(swap.reserved_bytes, false);
        }
        let mut abort = create_swap_abort(
            pid,
            state.node_id,
            "no capacity for return chunk".to_string(),
            None,
        );
        abort.sign(&state.identity_key);
        if let Ok(json) = serde_json::to_vec(&abort) {
            send_maintenance_sphinx(state, sender, MSG_BODY_SWAP_ABORT, &json).await;
        }
        return;
    }
    {
        let mut swaps = state.swap_state.lock().await;
        if let Some(swap) = swaps.pending_swaps.get_mut(&pid) {
            swap.their_chunk_id = accept.chunk_id;
            swap.reserved_bytes = chunk_len;
            // Return-chunk lease terms come from the accepter; adopt the
            // return content binding when present (zero root = barter).
            swap.renewal_token = accept.lease.renewal_token;
            swap.lease_expires_at = accept.lease.expires_at;
            if accept.return_content_root != [0u8; 32] {
                swap.content_root = accept.return_content_root;
                swap.merkle_proof = accept.return_merkle_proof.clone();
            }
        }
    }
    // No commit yet: retrieve their chunk first (retrieval phase).
}

/// Handle a Sphinx-delivered swap commit (Phase 7, Tasks 1+6).
pub async fn handle_maintenance_commit(
    state: &Arc<TransportState>,
    commit: SwapCommit,
) {
    let sender = commit.from_node;
    state.note_peer_activity(sender);
    if !commit.verify_signature() {
        return;
    }
    if !check_maintenance_sender(state, &sender, &commit.identity_public_key).await {
        return;
    }
    if !state.check_maintenance_nonce(&commit.nonce) {
        return;
    }
    let pid = commit.proposal_id;
    {
        // Auth: the commit must belong to a pending swap with this peer.
        let swaps = state.swap_state.lock().await;
        if !swaps
            .get_pending_swap(&pid)
            .is_some_and(|swap| swap.peer == sender)
        {
            return;
        }
    }
    {
        let mut swaps = state.swap_state.lock().await;
        swaps.mark_commit_received(&pid);
    }
    finalize_swap_if_ready(state, &pid).await;
}

/// Handle a Sphinx-delivered swap abort (Phase 7, Tasks 1+6).
pub async fn handle_maintenance_abort(
    state: &Arc<TransportState>,
    abort: SwapAbort,
) {
    let sender = abort.from_node;
    state.note_peer_activity(sender);
    if !abort.verify_signature() {
        return;
    }
    if !check_maintenance_sender(state, &sender, &abort.identity_public_key).await {
        return;
    }
    if !state.check_maintenance_nonce(&abort.nonce) {
        return;
    }
    let pid = abort.proposal_id;
    // Bind to the pending swap's peer (anti-spoof).
    let peer_ok = {
        let swaps = state.swap_state.lock().await;
        swaps
            .get_pending_swap(&pid)
            .is_some_and(|swap| swap.peer == sender)
    };
    if !peer_ok {
        // Still allow cleanup of proposer-side proposal records.
        state.swap_state.lock().await.remove_proposal(&pid);
        return;
    }
    let swap = state.swap_state.lock().await.abort_swap(&pid);
    if let Some(swap) = swap {
        state
            .storage_capacity
            .lock()
            .await
            .release_reserved(swap.reserved_bytes, false);
        debug!(
            "Swap {:02x?} aborted by peer {:02x?}: {}",
            pid, sender, abort.reason
        );
    }
}

/// Handle a Sphinx-delivered swap rejection (Phase 7, Task 1).
///
/// Rejections carry no signature (auth risk accepted: handling only
/// cleans local proposal state). The proposal ID must match a record we
/// created, so blind forgeries hit nothing.
pub async fn handle_maintenance_reject(
    state: &Arc<TransportState>,
    reject: SwapReject,
) {
    state.swap_state.lock().await.rejected_swaps += 1;
    state.swap_state.lock().await.remove_proposal(&reject.proposal_id);
}

/// Feed a chunk retrieved via the Sphinx retrieval protocol into a
/// pending 2-phase swap
///
/// Called by the node runner when a `ChunkResponse` completes: if the
/// response's chunk ID matches a pending swap still waiting for data,
/// the chunk is verified against the swap's stashed Merkle
/// proof/root and buffered in the pending swap. On success we send our
/// signed commit Sphinx-wrapped (if not already sent) and
/// finalize when both commits are in. On verification failure the swap
/// is aborted, the reservation released, and a signed abort sent to the
/// peer — nothing is ever stored.
///
/// Returns `true` when the chunk was consumed by a pending swap (the
/// caller must then skip its normal retrieval path); `false` when the
/// data belongs to an ordinary content retrieval.
pub async fn handle_swap_chunk_retrieval(
    state: &Arc<TransportState>,
    chunk_id: &static_storage::ChunkId,
    data: Vec<u8>,
) -> bool {
    // A swap chunk is always a full encrypted chunk; anything else
    // belongs to the normal content retrieval path.
    if data.len() != static_storage::CHUNK_SIZE + 16 {
        return false;
    }
    // Find the pending swap waiting for this chunk (never nested locks:
    // the swap lock is dropped before any other lock or send).
    let (pid, peer, root, proof) = {
        let swaps = state.swap_state.lock().await;
        match swaps
            .pending_swaps
            .values()
            .find(|s| !s.received_their_chunk && s.their_chunk_id == *chunk_id)
        {
            Some(swap) => (
                swap.proposal_id,
                swap.peer,
                swap.content_root,
                swap.merkle_proof.clone(),
            ),
            None => return false,
        }
    };
    // Integrity gate (deferred from proposal time, where no data was
    // present): the retrieved chunk must hash up the proposal's Merkle
    // proof to its content root. An all-zero root marks a barter return
    // chunk with no content binding (the proposer's side): the data is
    // accepted as-is, exactly like the in-band accepts it replaces.
    if root != [0u8; 32] {
        let chunk = static_storage::EncryptedChunk {
            id: *chunk_id,
            data: data.clone(),
        };
        if !static_storage::integrity::verify_chunk(&chunk, &proof, &root) {
            let swap = state.swap_state.lock().await.abort_swap(&pid);
            if let Some(swap) = swap {
                state
                    .storage_capacity
                    .lock()
                    .await
                    .release_reserved(swap.reserved_bytes, false);
            }
            let mut abort =
                create_swap_abort(pid, state.node_id, "retrieved chunk failed integrity verification".to_string(), None);
            abort.sign(&state.identity_key);
            if let Ok(json) = serde_json::to_vec(&abort) {
                send_swap_control_sphinx(state, peer, MSG_BODY_SWAP_ABORT, &json).await;
            }
            warn!(
                "Swap {:02x?}: retrieved chunk {:02x?} failed Merkle verification; aborted",
                pid, chunk_id
            );
            return true;
        }
    }
    let mut swaps = state.swap_state.lock().await;
    if !swaps.receive_their_chunk(&pid, data) {
        return false;
    }
    drop(swaps);
    // We now hold their chunk: send our commit (unless it is already
    // in flight), then finalize if their commit also arrived.
    let need_commit = {
        let mut swaps = state.swap_state.lock().await;
        let already = swaps
            .get_pending_swap(&pid)
            .map(|s| s.sent_commit)
            .unwrap_or(false);
        if !already {
            swaps.mark_commit_sent(&pid);
            true
        } else {
            false
        }
    };
    if need_commit {
        let mut commit = create_swap_commit(pid, state.node_id, None);
        commit.sign(&state.identity_key);
        if let Ok(json) = serde_json::to_vec(&commit) {
            send_swap_control_sphinx(state, peer, MSG_BODY_SWAP_COMMIT, &json).await;
        }
    }
    finalize_swap_if_ready(state, &pid).await;
    true
}

/// Finalize a pending 2-phase swap when both commits are in
///
/// Called from the retrieval hook (`handle_swap_chunk_retrieval`) and
/// the `SwapCommit` handler: whichever completes the (sent_commit &&
/// received_commit && received_their_chunk) condition finalizes. Stores
/// the peer's chunk, converts the reserved capacity into stored bytes,
/// records the barter and inserts the owner-keyed lease. Locks are taken
/// one at a time (never nested). Returns `true` if the swap was
/// finalized here.
async fn finalize_swap_if_ready(state: &Arc<TransportState>, pid: &[u8; 32]) -> bool {
    let Some(swap) = ({
        let mut swaps = state.swap_state.lock().await;
        let ready = swaps
            .get_pending_swap(pid)
            .map(|s| s.sent_commit && s.received_commit && s.received_their_chunk)
            .unwrap_or(false);
        if ready {
            swaps.complete_swap(pid)
        } else {
            None
        }
    }) else {
        return false;
    };
    let peer = swap.peer;
    // Finalize: store their chunk, convert the reservation into stored
    // bytes, and record the barter.
    let stored_new = {
        let mut holder = state.chunk_holder.lock().await;
        let already = holder.has_chunk(&swap.their_chunk_id);
        if !already {
            holder.add_chunk(
                swap.their_chunk_id,
                swap.their_chunk_data.clone(),
                [0u8; 32],
            );
        }
        !already
    };
    {
        let mut capacity = state.storage_capacity.lock().await;
        capacity.release_reserved(swap.reserved_bytes, stored_new);
    }
    if stored_new {
        let mut counts = state.peer_chunk_counts.lock().await;
        *counts.entry(peer).or_insert(0) += 1;
        // Lease for the held chunk: carries the content owner's public
        // key from the swap proposal so signed heartbeats verify
        // (Phase 2). Chunks without a content binding (barter return
        // chunks) carry an all-zero key that adopts on the first signed
        // heartbeat.
        if let Some(leases) = &state.lease_manager {
            let mut lm = leases.lock().await;
            lm.add_lease(
                swap.their_chunk_id,
                static_storage::ChunkLease {
                    chunk_id: swap.their_chunk_id,
                    expires_at: swap.lease_expires_at,
                    renewal_token: swap.renewal_token,
                    content_pub_key: swap.content_pub_key,
                },
            );
        }
    }
    debug!(
        "Swap {:02x?} committed: storing chunk {:02x?} for peer {:02x?}",
        pid,
        swap.their_chunk_id,
        peer
    );
    true
}

/// Generate a dummy packet for cover traffic (kept for tests).
#[cfg(test)]
fn generate_cover_packet(size: usize) -> Vec<u8> {
    use rand::RngCore;
    let mut packet = vec![0u8; size];
    rand::rngs::OsRng.fill_bytes(&mut packet);
    packet
}

/// Build a dummy Sphinx message for cover traffic (hybrid-only, Phase 0).
///
/// Phase 7 (Task 4c): prefer a structurally valid packet so cover is
/// indistinguishable from real traffic; fall back to size-realistic
/// random bytes when the peer's keys are unknown (tests/early boot).
fn dummy_sphinx_message(_use_hybrid: bool, budget: usize) -> WireMessage {
    use rand::RngCore;

    // Hybrid dummy: fixed KEM block + AEAD wire body (Phase 7 sizes).
    let fixed = 32 + static_sphinx::ROUTING_INFO_SIZE + 16 + static_sphinx::WIRE_BODY_SIZE;
    let kem_len = static_sphinx::KEM_BLOCK_SIZE;
    let total = fixed + kem_len;
    let _ = budget;
    let mut dummy = vec![0u8; total.max(32)];
    rand::rngs::OsRng.fill_bytes(&mut dummy);
    let routing_end = 32 + static_sphinx::ROUTING_INFO_SIZE;
    let mac_end = routing_end + 16;
    let mut session_id = [0u8; SESSION_ID_SIZE];
    rand::rngs::OsRng.fill_bytes(&mut session_id);

    WireMessage::Sphinx(SphinxPacket {
        header: static_sphinx::SphinxHeader {
            version: static_sphinx::SPHINX_VERSION_HYBRID,
            ephemeral_key: dummy[..32].try_into().unwrap_or([0u8; 32]),
            session_id,
            routing_info: dummy.get(32..routing_end).unwrap_or(&[]).to_vec(),
            mac: dummy.get(routing_end..mac_end).unwrap_or(&[]).try_into().unwrap_or([0u8; 16]),
        },
        kem_ciphertexts: dummy.get(mac_end..mac_end + kem_len).unwrap_or(&[]).to_vec(),
        body: dummy.get(mac_end + kem_len..).unwrap_or(&[]).to_vec(),
    })
}

/// Build valid cover for a peer: a real 3-hop hybrid packet routed through
/// the peer as first hop (Phase 7, Task 4c).
///
/// Returns `None` when the peer's KEM key is unknown; the caller falls back
/// to [`dummy_sphinx_message`]. Random intermediates fill hops 2-3 so the
/// packet is fully formed; it dies in the network after the peer forwards.
fn valid_cover_message(
    peer_id: &NodeId,
    routing_table: &RoutingTable,
    _budget: usize,
) -> Option<WireMessage> {
    use rand::RngCore;
    let peer = routing_table.get_node(peer_id)?;
    let peer_kem = peer.kem_public_key.clone()?;
    if peer_kem.len() != static_sphinx::HYBRID_KEM_PUBLIC_KEY_SIZE {
        return None;
    }
    // Two fresh random intermediates (their secrets are unknown; the packet
    // is cover and is allowed to die after the first real hop forwards).
    let r1 = static_sphinx::HybridMixNode::new();
    let r2 = static_sphinx::HybridMixNode::new();
    let route = static_sphinx::HybridRoute {
        hops: vec![
            static_sphinx::HybridRouteHop {
                node_id: peer.node_id,
                classical_public_key: peer.public_key,
                kem_public_key: peer_kem,
            },
            r1.as_hop(),
            r2.as_hop(),
        ],
        destination: {
            let mut d = [0u8; 16];
            rand::rngs::OsRng.fill_bytes(&mut d);
            d
        },
    };
    let mut body = [0u8; static_sphinx::BODY_SIZE];
    rand::rngs::OsRng.fill_bytes(&mut body);
    static_sphinx::create_packet_hybrid(&route, &body)
        .map(WireMessage::Sphinx)
        .ok()
}

/// Background loop to periodically gossip known peers (Phase 7: Sphinx).
///
/// Gossip content is signed (sender auth) and Sphinx-wrapped per
/// destination. Fan-out is capped at 10 random connected peers (Task 2,
/// gossip cap 10) instead of broadcasting to all connections.
pub async fn gossip_loop(state: Arc<TransportState>, interval_secs: u64) {
    use rand::seq::SliceRandom;
    let mut interval = time::interval(Duration::from_secs(interval_secs));

    loop {
        interval.tick().await;

        // Signed gossip (sender auth).
        let gossip = {
            let table = state.routing_table.read().await;
            let sk_bytes = state.identity_key.to_bytes();
            let sk = ed25519_dalek::SigningKey::from_bytes(&sk_bytes);
            table.create_signed_gossip(50, &sk)
        };
        let Ok(json) = serde_json::to_vec(&gossip) else {
            continue;
        };

        // Random subset of connected peers (cap 10), snapshot then send.
        let peers: Vec<NodeId> = {
            let connections = state.connections.read().await;
            let mut ids: Vec<NodeId> = connections.keys().copied().collect();
            ids.shuffle(&mut rand::thread_rng());
            ids.truncate(10);
            ids
        };
        if peers.is_empty() {
            continue;
        }

        for peer in peers {
            send_maintenance_sphinx(&state, peer, MSG_BODY_GOSSIP, &json).await;
        }
    }
}

/// Start the listener
///
/// Binds the transport's listener and loops accepting incoming
/// connections, handing each to [`handle_incoming_connection`]. No
/// lock is held across awaits, so a listening node can still dial out.
pub async fn start_listener(
    addr: SocketAddr,
    state: Arc<TransportState>,
) -> Result<(), TransportError> {
    state.transport.listen(&addr.to_string()).await?;
    info!("Listening on {}", addr);

    loop {
        match state.transport.accept().await {
            Ok((connection, peer_addr)) => {
                let state = state.clone();
                tokio::spawn(async move {
                    handle_incoming_connection(connection, peer_addr, state).await;
                });
            }
            Err(e) => {
                error!("Accept error: {}", e);
            }
        }
    }
}

/// Create transport state
///
/// The `storage_capacity` is shared with the node's accounting layer
/// (a single `Arc`, not a copy) so swap decisions, publish accounting,
/// and periodic reconciliation all observe one counter. Callers size it
/// from node configuration; there is no transport-level default.
///
/// `swap_state` is likewise shared with the node runner so the
/// transport-side swap flow and runner-side consumers (verification
/// challenges, heartbeat propagation) use one registry.
///
/// `leases` is the runner's lease manager (`Some` in production, `None`
/// in mesh unit tests): swap commit finalization inserts leases carrying
/// the content owner's public key for signed-heartbeat verification.
///
/// This is the only way to build a [`TransportState`]: passing the
/// shared state explicitly prevents accidentally constructing a node
/// with a disconnected swap/capacity registry.
pub fn create_transport_state(
    node_id: NodeId,
    mix_node: MixNode,
    cover_config: crate::CoverTrafficConfig,
    storage_capacity: Arc<Mutex<StorageCapacity>>,
    swap_state: Arc<Mutex<SwapState>>,
    leases: Option<Arc<Mutex<LeaseManager>>>,
) -> (Arc<TransportState>, mpsc::Receiver<InboundMessage>) {
    let (inbound_tx, inbound_rx) = mpsc::channel(CHANNEL_BUFFER);
    let routing_table = RoutingTable::new(node_id);
    let storage_key = static_crypto::SymmetricKey::random();
    let chunk_holder = ChunkHolder::new();
    let transport: Arc<dyn Transport> = Arc::new(TcpTransport::new());
    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    // Per-node bucket: capacity = 2s of traffic (allows short bursts
    // without leaking long-term rate), refill = configured rate.
    let bucket = TokenBucket::new(
        cover_config.target_rate_bps.saturating_mul(2).max(4096),
        cover_config.target_rate_bps,
        now_secs,
    );
    let mut identity_bytes = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut identity_bytes);
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&identity_bytes);
    let identity_public_key = signing_key.verifying_key().to_bytes();

    let state = Arc::new(TransportState {
        node_id,
        mix_node: Arc::new(Mutex::new(mix_node)),
        connections: Arc::new(RwLock::new(HashMap::new())),
        pending: Arc::new(RwLock::new(HashMap::new())),
        cover_config: Arc::new(RwLock::new(cover_config)),
        cover_bucket: Arc::new(Mutex::new(bucket)),
        total_bytes_sent: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        total_real_bytes_sent: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        total_cover_bytes_sent: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        inbound_tx,
        routing_table: Arc::new(RwLock::new(routing_table)),
        swap_state,
        lease_manager: leases,
        pending_swap_timeout_secs: static_storage::swap::DEFAULT_PENDING_SWAP_TIMEOUT_SECS,
        storage_capacity,
        storage_key: Arc::new(Mutex::new(storage_key)),
        chunk_holder: Arc::new(Mutex::new(chunk_holder)),
        kem: Arc::new(Mutex::new(static_crypto::KemKeypair::random())),
        identity_key: Arc::new(signing_key),
        identity_public_key,
        peer_chunk_counts: Arc::new(Mutex::new(HashMap::new())),
        previously_connected: Arc::new(RwLock::new(HashSet::new())),
        serve_enabled: Arc::new(std::sync::atomic::AtomicBool::new(true)),
        peer_activity: Arc::new(std::sync::Mutex::new(HashMap::new())),
        compute_enabled: false,
        compute_capacity: 0,
        transport,
        handshake_nonces: Arc::new(std::sync::Mutex::new(HashMap::new())),
        maintenance_nonces: Arc::new(std::sync::Mutex::new(HashMap::new())),
        pending_requests: Arc::new(Mutex::new(crate::fragment::ReassemblyManager::new())),
    });

    (state, inbound_rx)
}

/// Send maintenance payload Sphinx-wrapped to a destination (Phase 7).
///
/// Builds `[body_type][payload]`, fragments it, wraps each fragment in a
/// hybrid Sphinx packet routed via [`TransportState::build_route_to_
/// destination`] (3-hop when the table allows, else direct), and queues
/// each packet on the first hop's connection. Drops (with a warning)
/// when the destination's keys are unknown.
///
/// Public so the node runner Sphinx-wraps its own maintenance sends
/// (swap proposals, reconciliation batches, prepayments) through the
/// same path instead of direct-wire messages.
pub async fn send_maintenance_sphinx(
    state: &TransportState,
    dest: NodeId,
    body_type: u8,
    payload: &[u8],
) {
    let body = wrap_maintenance_payload(body_type, payload);
    let Some(route) = state.build_route_to_destination(dest).await else {
        warn!("No route for maintenance to {:02x?}: unknown peer", dest);
        return;
    };
    let first_hop = route.hops[0].node_id;
    let kem_map: HashMap<NodeId, Vec<u8>> = {
        let table = state.routing_table.read().await;
        table
            .nodes
            .iter()
            .filter_map(|(id, n)| n.kem_public_key.as_ref().map(|k| (*id, k.clone())))
            .collect()
    };
    let kem_lookup = |id: &NodeId| kem_map.get(id).cloned();
    let classical = static_sphinx::Route {
        hops: route
            .hops
            .iter()
            .map(|h| static_sphinx::RouteHop {
                public_key: h.classical_public_key,
                node_id: h.node_id,
            })
            .collect(),
        destination: route.destination,
    };
    let packets = match create_hybrid_payload_packets(&body, &classical, &kem_lookup) {
        Ok(p) => p,
        Err(_) => {
            warn!("Failed to wrap maintenance for {:02x?}", dest);
            return;
        }
    };
    let connections = state.connections.read().await;
    let Some(sender) = connections.get(&first_hop) else {
        return;
    };
    for pkt in packets {
        let _ = sender.send(WireMessage::Sphinx(pkt)).await;
    }
}

/// Send a signed `SwapCommit`/`SwapAbort` Sphinx-wrapped to a swap peer.
async fn send_swap_control_sphinx(
    state: &TransportState,
    peer: NodeId,
    body_type: u8,
    payload_json: &[u8],
) {
    send_maintenance_sphinx(state, peer, body_type, payload_json).await;
}

/// Send a Sphinx packet to a specific peer
pub async fn send_sphinx(
    state: &Arc<TransportState>,
    peer: NodeId,
    packet: SphinxPacket,
) -> Result<(), TransportError> {
    let connections = state.connections.read().await;
    let sender = connections.get(&peer)
        .ok_or(TransportError::ConnectionNotFound(peer))?;
    
    sender.send(WireMessage::Sphinx(packet))
        .await
        .map_err(|_| TransportError::ChannelSend)
}

/// Send a prepayment to a sponsor peer (Phase 7: Sphinx-wrapped).
pub async fn send_prepayment(
    state: &Arc<TransportState>,
    peer: NodeId,
    prepayment: crate::wire::Prepayment,
) -> Result<(), TransportError> {
    let json =
        serde_json::to_vec(&prepayment).map_err(|_| TransportError::ChannelSend)?;
    send_maintenance_sphinx(state, peer, MSG_BODY_PREPAYMENT, &json).await;
    Ok(())
}

/// Send an accounting reconciliation batch to a reconnected peer
/// (Phase 7: Sphinx-wrapped).
///
/// Large states are split by the caller into batches of at most
/// `crate::wire::MAX_RECONCILIATION_ENTRIES`.
pub async fn send_reconciliation(
    state: &Arc<TransportState>,
    peer: NodeId,
    reconciliation: crate::wire::AccountingReconciliation,
) -> Result<(), TransportError> {
    let json =
        serde_json::to_vec(&reconciliation).map_err(|_| TransportError::ChannelSend)?;
    send_maintenance_sphinx(state, peer, MSG_BODY_RECONCILIATION, &json).await;
    Ok(())
}

/// Get transport statistics
pub async fn get_stats(state: &Arc<TransportState>) -> TransportStats {
    TransportStats {
        total_bytes_sent: state.total_bytes_sent.load(std::sync::atomic::Ordering::Relaxed),
        total_real_bytes_sent: state.total_real_bytes_sent.load(std::sync::atomic::Ordering::Relaxed),
        total_cover_bytes_sent: state.total_cover_bytes_sent.load(std::sync::atomic::Ordering::Relaxed),
        connected_peers: state.connections.read().await.len(),
    }
}

/// Transport statistics
#[derive(Debug, Clone)]
pub struct TransportStats {
    /// Total bytes sent (real + cover)
    pub total_bytes_sent: u64,
    /// Total real bytes sent
    pub total_real_bytes_sent: u64,
    /// Total cover bytes sent
    pub total_cover_bytes_sent: u64,
    /// Number of connected peers
    pub connected_peers: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::*;
    use static_sphinx::{Route, RouteHop, create_packet, MixNode};
    use rand::RngCore;

    fn random_node_id() -> NodeId {
        let mut id = [0u8; NODE_ID_SIZE];
        rand::rngs::OsRng.fill_bytes(&mut id);
        id
    }

    /// Fresh 10 GB capacity for tests (mirrors the node default).
    fn test_capacity() -> Arc<Mutex<StorageCapacity>> {
        Arc::new(Mutex::new(StorageCapacity::new(10 * 1024 * 1024 * 1024)))
    }

    /// Build a test transport state: fresh capacity + swap registry, no
    /// lease manager (mesh tests do not exercise lease bookkeeping).
    fn test_state(
        node_id: NodeId,
        mix_node: MixNode,
        cover_config: crate::CoverTrafficConfig,
    ) -> (Arc<TransportState>, mpsc::Receiver<InboundMessage>) {
        create_transport_state(
            node_id,
            mix_node,
            cover_config,
            test_capacity(),
            Arc::new(Mutex::new(SwapState::new())),
            None,
        )
    }

    #[tokio::test]
    async fn test_transport_state_creation() {
        let node_id = random_node_id();
        let mix_node = MixNode::new();
        let cover_config = crate::CoverTrafficConfig::default();

        let (state, _rx) = test_state(node_id, mix_node, cover_config);

        assert_eq!(state.node_id, node_id);
        assert_eq!(state.connections.read().await.len(), 0);
    }

    #[tokio::test]
    async fn test_cover_packet_generation() {
        let packet1 = generate_cover_packet(1024);
        let packet2 = generate_cover_packet(1024);

        assert_eq!(packet1.len(), 1024);
        assert_ne!(packet1, packet2); // Random packets should differ
    }

    #[tokio::test]
    async fn test_send_sphinx_no_connection() {
        let node_id = random_node_id();
        let mix_node = MixNode::new();
        let cover_config = crate::CoverTrafficConfig::default();

        let (state, _rx) = test_state(node_id, mix_node, cover_config, );

        let route = Route {
            hops: vec![RouteHop {
                public_key: [0u8; 32],
                node_id: random_node_id(),
            }],
            destination: random_node_id(),
        };
        let packet = create_packet(&route, b"test").unwrap();

        let result = send_sphinx(&state, random_node_id(), packet).await;
        assert!(matches!(result, Err(TransportError::ConnectionNotFound(_))));
    }

    #[tokio::test]
    async fn test_transport_stats() {
        let node_id = random_node_id();
        let mix_node = MixNode::new();
        let cover_config = crate::CoverTrafficConfig::default();

        let (state, _rx) = test_state(node_id, mix_node, cover_config, );

        let stats = get_stats(&state).await;
        assert_eq!(stats.total_bytes_sent, 0);
        assert_eq!(stats.connected_peers, 0);
    }

    #[tokio::test]
    async fn test_tcp_connection_and_handshake() {
        // Create two nodes
        let node1_id = random_node_id();
        let node1_mix = MixNode::new();
        let cover_config = crate::CoverTrafficConfig {
            enabled: false, // Disable cover traffic for test
            ..Default::default()
        };

        let (state1, _rx1) = test_state(node1_id, node1_mix, cover_config.clone(), );

        // Start listener for node1
        let listener_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let listener = TcpListener::bind(listener_addr).await.unwrap();
        let actual_addr = listener.local_addr().unwrap();

        let state1_clone = state1.clone();
        tokio::spawn(async move {
            loop {
                if let Ok((stream, addr)) = listener.accept().await {
                    let s = state1_clone.clone();
                    tokio::spawn(async move {
                        handle_incoming_connection(
                            Box::new(TcpConnection::new(stream)),
                            addr.to_string(),
                            s,
                        )
                        .await;
                    });
                }
            }
        });

        // Node2 connects to node1
        let node2_id = random_node_id();
        let node2_mix = MixNode::new();
        let (state2, _rx2) = test_state(node2_id, node2_mix, cover_config, );

        // Give listener a moment to start
        tokio::time::sleep(Duration::from_millis(50)).await;

        connect_to_peer(actual_addr, state2.clone()).await.unwrap();

        // Give time for handshake to complete
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Node2 should have node1 in its connections
        let conns = state2.connections.read().await;
        assert!(conns.len() > 0, "node2 should have a connection to node1");

        // Node1 should have node2 in its connections
        let conns1 = state1.connections.read().await;
        assert!(conns1.len() > 0, "node1 should have a connection from node2");
    }

    #[tokio::test]
    async fn test_sphinx_forwarding_through_tcp() {
        // Create 3 nodes: A -> B -> C (hybrid-only)
        use static_sphinx::{HybridRoute, HybridRouteHop, create_packet_hybrid};
        let node_a_id = random_node_id();
        let node_b_id = random_node_id();
        let node_c_id = random_node_id();

        let mix_a = MixNode::new();
        let mix_b = MixNode::new();
        let mix_c = MixNode::new();

        let cover_config = crate::CoverTrafficConfig {
            enabled: false,
            ..Default::default()
        };

        let (state_a, _rx_a) = test_state(node_a_id, mix_a, cover_config.clone(), );
        let (state_b, _rx_b) = test_state(node_b_id, mix_b, cover_config.clone(), );
        let (state_c, mut rx_c) = test_state(node_c_id, mix_c, cover_config, );

        // Start listeners for B and C
        let listener_b = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr_b = listener_b.local_addr().unwrap();
        let listener_c = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr_c = listener_c.local_addr().unwrap();

        let state_b_clone = state_b.clone();
        tokio::spawn(async move {
            loop {
                if let Ok((stream, addr)) = listener_b.accept().await {
                    let s = state_b_clone.clone();
                    tokio::spawn(async move {
                        handle_incoming_connection(
                            Box::new(TcpConnection::new(stream)),
                            addr.to_string(),
                            s,
                        )
                        .await;
                    });
                }
            }
        });

        let state_c_clone = state_c.clone();
        tokio::spawn(async move {
            loop {
                if let Ok((stream, addr)) = listener_c.accept().await {
                    let s = state_c_clone.clone();
                    tokio::spawn(async move {
                        handle_incoming_connection(
                            Box::new(TcpConnection::new(stream)),
                            addr.to_string(),
                            s,
                        )
                        .await;
                    });
                }
            }
        });

        tokio::time::sleep(Duration::from_millis(50)).await;

        // A connects to B, B connects to C
        connect_to_peer(addr_b, state_a.clone()).await.unwrap();
        connect_to_peer(addr_c, state_b.clone()).await.unwrap();

        tokio::time::sleep(Duration::from_millis(100)).await;

        // Create a hybrid Sphinx packet: A -> B -> C (destination)
        let kem_b = state_b.kem.lock().await.public_bytes();
        let kem_c = state_c.kem.lock().await.public_bytes();
        let route = HybridRoute {
            hops: vec![
                HybridRouteHop {
                    node_id: node_b_id,
                    classical_public_key: state_b.mix_node.lock().await.public_key,
                    kem_public_key: kem_b,
                },
                HybridRouteHop {
                    node_id: node_c_id,
                    classical_public_key: state_c.mix_node.lock().await.public_key,
                    kem_public_key: kem_c,
                },
            ],
            destination: node_c_id,
        };

        let body = b"end to end sphinx test";
        let packet = create_packet_hybrid(&route, body).unwrap();

        // A sends the packet to B
        send_sphinx(&state_a, node_b_id, packet).await.unwrap();

        // Wait for the packet to arrive at C
        let timeout = time::sleep(Duration::from_secs(5));
        tokio::pin!(timeout);

        loop {
            tokio::select! {
                Some(inbound) = rx_c.recv() => {
                    match inbound.message {
                        WireMessage::Sphinx(pkt) => {
                            // C is the destination, the body should be the decrypted content
                            assert_eq!(&pkt.body[..body.len()], body);
                            break;
                        }
                        _ => {}
                    }
                }
                _ = &mut timeout => {
                    panic!("Timeout waiting for Sphinx packet at destination");
                }
            }
        }
    }

    #[tokio::test]
    async fn test_tcp_transport_implementation() {
        let transport = TcpTransport::new();

        assert_eq!(transport.name(), "tcp");
        assert_eq!(transport.max_message_size(), HYBRID_MAX_MESSAGE_SIZE);
    }

    #[tokio::test]
    async fn test_tcp_connection_send_recv() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        // Echo server: read once, send the bytes back
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let conn = TcpConnection::new(stream);
            let mut buf = vec![0u8; 64];
            match conn.recv_bytes(&mut buf).await.unwrap() {
                Some(n) => {
                    conn.send_bytes(&buf[..n]).await.unwrap();
                }
                None => panic!("server: unexpected disconnect"),
            }
        });

        let stream = TcpStream::connect(addr).await.unwrap();
        assert!(!stream.peer_addr().unwrap().to_string().is_empty());
        let client = TcpConnection::new(stream);

        client.send_bytes(b"ping").await.unwrap();

        let mut buf = vec![0u8; 64];
        let n = client
            .recv_bytes(&mut buf)
            .await
            .unwrap()
            .expect("client: connection closed before echo");
        assert_eq!(&buf[..n], b"ping");

        server.await.unwrap();
    }

    /// Build a metadata-only swap proposal
    ///
    /// The proposal carries only the chunk ID; `data` is used to
    /// generate a genuine Merkle proof (which rides along for
    /// retrieval-time verification of the chunk data). The lease must
    /// be valid and the proposal Ed25519-signed with an ephemeral
    /// content key so `decide_on_swap` accepts it.
    fn test_swap_proposal(from: NodeId, chunk_id: [u8; 32], data: Vec<u8>) -> static_storage::swap::SwapProposal {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let chunk = static_storage::EncryptedChunk { id: chunk_id, data };
        let (content_root, proofs) =
            static_storage::integrity::generate_proofs(std::slice::from_ref(&chunk));
        // Sign with ephemeral content key so sig verifies (Phase 7: no
        // content_id on the wire; proposal carries a fresh nonce).
        let content_sk = ed25519_dalek::SigningKey::from_bytes(&[0x33u8; 32]);
        let content_pub = content_sk.verifying_key().to_bytes();
        let mut proposal = static_storage::swap::SwapProposal {
            from_node: from,
            chunk_id,
            lease: static_storage::ChunkLease {
                chunk_id,
                expires_at: now + 86400,
                renewal_token: [0u8; 32],
                content_pub_key: content_pub,
            },
            encrypted_master_key: Vec::new(),
            content_root,
            merkle_proof: proofs.into_iter().next().expect("one chunk, one proof"),
            proposal_nonce: [0u8; 32],
            content_public_key: content_pub,
            content_signature: vec![],
        };
        proposal.sign(&content_sk);
        proposal
    }

    #[tokio::test]
    async fn test_swap_proposal_prepares_without_storing_then_commit_stores() {
        // 2-phase accepter side, metadata-only wire: the proposal
        // reserves capacity but nothing is stored and no data arrives.
        // The retrieved chunk (fed via handle_swap_chunk_retrieval) is
        // buffered pending commit; the peer's SwapCommit finalizes
        // storage, converts the reservation, and inserts the
        // owner-keyed lease.
        let leases: Arc<Mutex<LeaseManager>> = Arc::new(Mutex::new(LeaseManager::new()));
        let (state, _rx) = create_transport_state(
            random_node_id(),
            MixNode::new(),
            crate::CoverTrafficConfig::default(),
            test_capacity(),
            Arc::new(Mutex::new(SwapState::new())),
            Some(leases.clone()),
        );
        // Strict barter needs a real return chunk: pre-populate holder.
        let existing_id = [0xB0u8; 32];
        state
            .chunk_holder
            .lock()
            .await
            .add_chunk(existing_id, vec![0xAAu8; static_storage::CHUNK_SIZE + 16], [0u8; 32]);
        state.storage_capacity.lock().await.record_accept((static_storage::CHUNK_SIZE + 16) as u64);

        let from = random_node_id();
        let chunk_id = [0xB1u8; 32];
        let data = vec![0x5Cu8; static_storage::CHUNK_SIZE + 16];
        let proposal = test_swap_proposal(from, chunk_id, data.clone());
        let pid = static_storage::swap::proposal_id(&proposal);

        // Prepare phase: reserve, store nothing (no data on the wire).
        handle_maintenance_proposal(&state, proposal.clone()).await;

        assert!(state.chunk_holder.lock().await.get_chunk(&chunk_id).is_none());
        {
            let capacity = state.storage_capacity.lock().await;
            assert_eq!(capacity.current_bytes, (static_storage::CHUNK_SIZE + 16) as u64);
            assert_eq!(capacity.reserved_bytes, (static_storage::CHUNK_SIZE + 16) as u64);
        }
        {
            let swaps = state.swap_state.lock().await;
            let pending = swaps.get_pending_swap(&pid).expect("pending swap recorded");
            assert!(pending.their_chunk_data.is_empty());
            assert!(!pending.received_their_chunk);
            assert!(!pending.sent_commit, "no commit until data is retrieved");
            assert!(!pending.received_commit);
            assert_eq!(pending.peer, from);
        }

        // Retrieval phase: the peer's chunk data arrives via the Sphinx
        // retrieval protocol and is consumed by the pending swap (which
        // also emits our commit — dropped here, no connection).
        let consumed =
            handle_swap_chunk_retrieval(&state, &chunk_id, data.clone()).await;
        assert!(consumed, "retrieved chunk matched the pending swap");

        {
            let swaps = state.swap_state.lock().await;
            let pending = swaps.get_pending_swap(&pid).unwrap();
            assert_eq!(pending.their_chunk_data, data);
            assert!(pending.received_their_chunk);
            assert!(pending.sent_commit, "commit sent after data retrieved");
        }
        // Still nothing stored before their commit.
        assert!(state.chunk_holder.lock().await.get_chunk(&chunk_id).is_none());

        // Commit phase: the peer's commit finalizes the swap.
        let mut commit =
            static_storage::swap::create_swap_commit(pid, from, None);
        commit.sign(&state.identity_key);
        handle_maintenance_commit(&state, commit).await;

        let expected_len = (static_storage::CHUNK_SIZE + 16) as u64 * 2;
        assert_eq!(state.chunk_holder.lock().await.get_chunk(&chunk_id), Some(&data));
        {
            let capacity = state.storage_capacity.lock().await;
            assert_eq!(capacity.current_bytes, expected_len);
            assert_eq!(capacity.reserved_bytes, 0);
        }
        {
            let swaps = state.swap_state.lock().await;
            assert_eq!(swaps.get_swap_partner(&chunk_id), Some(&from));
            assert_eq!(swaps.completed_swaps, vec![pid]);
        }
        assert_eq!(
            state.peer_chunk_counts.lock().await.get(&from).copied(),
            Some(1)
        );
        // The lease carries the content owner's key from the proposal.
        let lease = leases.lock().await.leases.get(&chunk_id).cloned();
        assert_eq!(lease.expect("lease inserted").content_pub_key, proposal.content_public_key);
    }

    #[tokio::test]
    async fn test_swap_proposer_commits_after_accept() {
        // 2-phase proposer side, metadata-only: begin_swap_proposal
        // tracks the pending swap; the metadata accept names the return
        // chunk and reserves capacity (no storage); the retrieved data
        // emits our commit; their commit finalizes it.
        let (state, _rx) = test_state(
            random_node_id(),
            MixNode::new(),
            crate::CoverTrafficConfig::default(),
        );
        let peer = random_node_id();
        let our_chunk_id = [0xC1u8; 32];
        let proposal = test_swap_proposal(
            state.node_id,
            our_chunk_id,
            vec![0x6Au8; static_storage::CHUNK_SIZE + 16],
        );
        let pid = state.begin_swap_proposal(peer, &proposal).await;

        // The metadata accept names their return chunk by ID.
        let their_id = [0xC2u8; 32];
        let their_data = vec![0x6Bu8; static_storage::CHUNK_SIZE + 16];
        let mut accept = create_swap_accept(
            peer,
            their_id,
            &static_crypto::SymmetricKey::random(),
            pid,
            86400,
        );
        accept.sign(&state.identity_key);
        handle_maintenance_accept(&state, accept).await;

        // Prepare phase on the proposer side: reserved, not stored.
        assert!(state.chunk_holder.lock().await.get_chunk(&their_id).is_none());
        {
            let capacity = state.storage_capacity.lock().await;
            assert_eq!(capacity.reserved_bytes, (static_storage::CHUNK_SIZE + 16) as u64);
            assert_eq!(capacity.current_bytes, 0);
        }
        {
            let swaps = state.swap_state.lock().await;
            let pending = swaps.get_pending_swap(&pid).expect("pending swap tracked");
            assert_eq!(pending.their_chunk_id, their_id);
            assert!(pending.their_chunk_data.is_empty());
            assert!(!pending.sent_commit);
        }

        // Retrieval phase: their chunk data arrives; our commit goes out
        // (dropped here, no connection).
        let consumed =
            handle_swap_chunk_retrieval(&state, &their_id, their_data.clone()).await;
        assert!(consumed);

        // Their commit arrives: finalize.
        let mut commit =
            static_storage::swap::create_swap_commit(pid, peer, None);
        commit.sign(&state.identity_key);
        handle_maintenance_commit(&state, commit).await;

        assert_eq!(state.chunk_holder.lock().await.get_chunk(&their_id), Some(&their_data));
        let capacity = state.storage_capacity.lock().await;
        assert_eq!(capacity.current_bytes, (static_storage::CHUNK_SIZE + 16) as u64);
        assert_eq!(capacity.reserved_bytes, 0);
        drop(capacity);
        assert_eq!(
            state.swap_state.lock().await.get_swap_partner(&their_id),
            Some(&peer)
        );
    }

    #[tokio::test]
    async fn test_swap_abort_releases_reservation() {
        // The peer aborts mid-swap: the pending swap is dropped and the
        // reserved capacity is released. Nothing is stored.
        let (state, _rx) = test_state(
            random_node_id(),
            MixNode::new(),
            crate::CoverTrafficConfig::default(),
        );
        let existing_id = [0xB0u8; 32];
        state
            .chunk_holder
            .lock()
            .await
            .add_chunk(existing_id, vec![0xAAu8; static_storage::CHUNK_SIZE + 16], [0u8; 32]);
        state.storage_capacity.lock().await.record_accept((static_storage::CHUNK_SIZE + 16) as u64);

        let from = random_node_id();
        let chunk_id = [0xB4u8; 32];
        let proposal = test_swap_proposal(from, chunk_id, vec![0x5Fu8; static_storage::CHUNK_SIZE + 16]);
        let pid = static_storage::swap::proposal_id(&proposal);

        handle_maintenance_proposal(&state, proposal).await;
        assert_eq!(
            state.storage_capacity.lock().await.reserved_bytes,
            (static_storage::CHUNK_SIZE + 16) as u64
        );

        let mut abort = static_storage::swap::create_swap_abort(
            pid,
            from,
            "cannot honor barter".to_string(),
            None,
        );
        abort.sign(&state.identity_key);
        handle_maintenance_abort(&state, abort).await;

        assert!(state.chunk_holder.lock().await.get_chunk(&chunk_id).is_none());
        let capacity = state.storage_capacity.lock().await;
        assert_eq!(capacity.reserved_bytes, 0);
        assert_eq!(capacity.current_bytes, (static_storage::CHUNK_SIZE + 16) as u64);
        drop(capacity);
        let swaps = state.swap_state.lock().await;
        assert!(swaps.get_pending_swap(&pid).is_none());
        assert_eq!(swaps.aborted_swaps, vec![pid]);
    }

    #[tokio::test]
    async fn test_swap_timeout_expires_and_releases_reservation() {
        // A pending swap older than the timeout is expired by
        // expire_pending_swaps: reservation released, nothing stored.
        let (state, _rx) = test_state(
            random_node_id(),
            MixNode::new(),
            crate::CoverTrafficConfig::default(),
        );
        let existing_id = [0xB0u8; 32];
        state
            .chunk_holder
            .lock()
            .await
            .add_chunk(existing_id, vec![0xAAu8; static_storage::CHUNK_SIZE + 16], [0u8; 32]);
        state.storage_capacity.lock().await.record_accept((static_storage::CHUNK_SIZE + 16) as u64);

        let from = random_node_id();
        let chunk_id = [0xB5u8; 32];
        let proposal = test_swap_proposal(from, chunk_id, vec![0x60u8; static_storage::CHUNK_SIZE + 16]);
        let pid = static_storage::swap::proposal_id(&proposal);

        handle_maintenance_proposal(&state, proposal).await;

        // Age the pending swap past the timeout without sleeping.
        {
            let mut swaps = state.swap_state.lock().await;
            let started = swaps.get_pending_swap(&pid).unwrap().started_at;
            swaps.pending_swaps.get_mut(&pid).unwrap().started_at =
                started.saturating_sub(state.pending_swap_timeout_secs + 1);
        }

        let aborted = state.expire_pending_swaps().await;
        assert_eq!(aborted, 1);

        assert!(state.chunk_holder.lock().await.get_chunk(&chunk_id).is_none());
        let capacity = state.storage_capacity.lock().await;
        assert_eq!(capacity.reserved_bytes, 0);
        drop(capacity);
        let swaps = state.swap_state.lock().await;
        assert!(swaps.get_pending_swap(&pid).is_none());
        assert_eq!(swaps.aborted_swaps, vec![pid]);
    }

    #[tokio::test]
    async fn test_active_swap_accept_stores_nothing() {
        // Forged proposal (bad content signature) is rejected: nothing
        // stored, nothing reserved. Phase 7: with Sphinx delivery there is
        // no TCP peer to bind against — the content signature is the binding.
        let (state, _rx) = test_state(
            random_node_id(),
            MixNode::new(),
            crate::CoverTrafficConfig::default(),
        );
        // Active node (default): serving enabled
        assert!(state.serve_enabled.load(std::sync::atomic::Ordering::Relaxed));

        let chunk_id = [0xB2u8; 32];
        let mut proposal = test_swap_proposal(
            random_node_id(),
            chunk_id,
            vec![0x5Du8; static_storage::CHUNK_SIZE + 16],
        );
        proposal.content_signature[0] ^= 0xFF;

        handle_maintenance_proposal(&state, proposal).await;

        assert!(state.chunk_holder.lock().await.get_chunk(&chunk_id).is_none());
        let capacity = state.storage_capacity.lock().await;
        assert_eq!(capacity.current_bytes, 0);
        assert_eq!(capacity.reserved_bytes, 0);
    }

    #[tokio::test]
    async fn test_swap_bad_chunk_data_aborts() {
        // Garbage-flooding protection, retrieval phase: data fetched
        // from the peer must verify against the proposal's Merkle proof
        // before it can be stored. A tampered same-size payload aborts
        // the swap: reservation released, nothing stored, abort recorded.
        let (state, _rx) = test_state(
            random_node_id(),
            MixNode::new(),
            crate::CoverTrafficConfig::default(),
            );
        let existing_id = [0xB0u8; 32];
        state
            .chunk_holder
            .lock()
            .await
            .add_chunk(existing_id, vec![0xAAu8; static_storage::CHUNK_SIZE + 16], [0u8; 32]);
        state.storage_capacity.lock().await.record_accept((static_storage::CHUNK_SIZE + 16) as u64);

        let from = random_node_id();
        let chunk_id = [0xB3u8; 32];
        let data = vec![0x5Eu8; static_storage::CHUNK_SIZE + 16];
        let proposal = test_swap_proposal(from, chunk_id, data);
        let pid = static_storage::swap::proposal_id(&proposal);

        // Metadata proposal is accepted (integrity is data-bound and
        // deferred to the retrieval phase).
        handle_maintenance_proposal(&state, proposal.clone()).await;
        assert!(state.swap_state.lock().await.get_pending_swap(&pid).is_some());

        // Same size, different bytes than the proof was generated over.
        let mut tampered = vec![0x5Eu8; static_storage::CHUNK_SIZE + 16];
        tampered[0] ^= 0xFF;
        let consumed = handle_swap_chunk_retrieval(&state, &chunk_id, tampered).await;
        assert!(consumed, "bad data is consumed (and rejected), not stashed");

        // The swap aborted: reservation released, nothing stored.
        assert!(state.chunk_holder.lock().await.get_chunk(&chunk_id).is_none());
        let capacity = state.storage_capacity.lock().await;
        assert_eq!(capacity.reserved_bytes, 0);
        assert_eq!(capacity.current_bytes, (static_storage::CHUNK_SIZE + 16) as u64);
        drop(capacity);
        let swaps = state.swap_state.lock().await;
        assert!(swaps.get_pending_swap(&pid).is_none());
        assert_eq!(swaps.aborted_swaps, vec![pid]);
        assert!(swaps.completed_swaps.is_empty());
    }

    #[tokio::test]
    async fn test_swap_retrieval_unrelated_data_passes_through() {
        // Data that does not match any pending swap chunk ID (e.g. an
        // ordinary content retrieval response) is not consumed by the
        // swap path.
        let (state, _rx) = test_state(
            random_node_id(),
            MixNode::new(),
            crate::CoverTrafficConfig::default(),
        );
        let from = random_node_id();
        let chunk_id = [0xB6u8; 32];
        let proposal = test_swap_proposal(from, chunk_id, vec![0x61u8; static_storage::CHUNK_SIZE + 16]);
        handle_maintenance_proposal(&state, proposal).await;

        let other_id = [0xB7u8; 32];
        let other_data = vec![0x62u8; static_storage::CHUNK_SIZE + 16];
        let consumed = handle_swap_chunk_retrieval(&state, &other_id, other_data).await;
        assert!(!consumed);
        // Wrong-size data is also passed through.
        let consumed = handle_swap_chunk_retrieval(&state, &chunk_id, vec![1, 2, 3]).await;
        assert!(!consumed);
}

    #[tokio::test]
    async fn test_dormant_backup_ignores_chunk_request() {
        // A dormant backup must not serve chunks it holds, even valid ones.
        let (state, _rx) = test_state(
            random_node_id(),
            MixNode::new(),
            crate::CoverTrafficConfig::default(),
            );
        state
            .serve_enabled
            .store(false, std::sync::atomic::Ordering::Relaxed);

        // Store a chunk so an active node would have something to serve.
        let chunk_id = [0xB3u8; 32];
        state
            .chunk_holder
            .lock()
            .await
            .add_chunk(chunk_id, vec![0x11u8; 512], [0u8; 32]);

        // Build a ChunkRequest destined for us and wrap it in a Sphinx
        // packet addressed to our mix node (destination flag).
        let requester_id = random_node_id();
        let return_route = static_storage::retrieval::ReturnRoute {
            hops: vec![static_storage::retrieval::RouteHopInfo {
                public_key: [0u8; 32],
                node_id: requester_id,
            }],
            destination: requester_id,
        };
        let request = static_storage::retrieval::ChunkRequest {
            chunk_id,
            return_route,
            surb: None, };
        let request_bytes = static_storage::retrieval::serialize_request(&request);

        // A packet created for us (our public key) with our node ID as
        // destination decrypts at our hop with flag = Destination.
        let our_pubkey = state.mix_node.lock().await.public_key;
        let forward_route = Route {
            hops: vec![RouteHop {
                public_key: our_pubkey,
                node_id: state.node_id,
            }],
            destination: state.node_id,
        };
        let packet = create_packet(&forward_route, &request_bytes).unwrap();

        handle_message(WireMessage::Sphinx(packet), &state, requester_id)
            .await
            .unwrap();

        // The chunk is still held (nothing was deleted), and no chunk
        // response was sent (no connection to the requester existed, and
        // more importantly the dormant gate returned before serving).
        assert!(state.chunk_holder.lock().await.get_chunk(&chunk_id).is_some());
    }

    #[tokio::test]
    async fn test_swap_accept_binding() {
        // Phase 7 Task 6 (H2-H3): an accept with a VALID signature but
        // from the WRONG node is rejected — the accept must come from
        // the pending swap's peer (sender binding without TCP).
        let (state, _rx) = test_state(
            random_node_id(),
            MixNode::new(),
            crate::CoverTrafficConfig::default(),
        );
        let peer = random_node_id();
        let impostor = random_node_id();
        let our_chunk_id = [0xD1u8; 32];
        let proposal = test_swap_proposal(
            state.node_id,
            our_chunk_id,
            vec![0x6Au8; static_storage::CHUNK_SIZE + 16],
        );
        let pid = state.begin_swap_proposal(peer, &proposal).await;

        // Signed accept from an impostor (not the swap peer).
        let their_id = [0xD2u8; 32];
        let mut accept = create_swap_accept(
            impostor,
            their_id,
            &static_crypto::SymmetricKey::random(),
            pid,
            86400,
        );
        accept.sign(&state.identity_key);
        assert!(accept.verify_signature(), "signature itself is valid");
        handle_maintenance_accept(&state, accept).await;

        // Nothing reserved, pending swap untouched.
        assert_eq!(state.storage_capacity.lock().await.reserved_bytes, 0);
        let swaps = state.swap_state.lock().await;
        let pending = swaps.get_pending_swap(&pid).unwrap();
        assert_eq!(pending.their_chunk_id, [0u8; 32]);
        drop(swaps);


        // The genuine peer's signed accept is accepted.
        let mut good = create_swap_accept(
            peer,
            [0xD3u8; 32],
            &static_crypto::SymmetricKey::random(),
            pid,
            86400,
        );
        good.sign(&state.identity_key);
        handle_maintenance_accept(&state, good).await;
        let pending = state
            .swap_state
            .lock()
            .await
            .get_pending_swap(&pid)
            .cloned()
            .expect("pending swap present");
        assert_eq!(pending.their_chunk_id, [0xD3u8; 32]);
        assert_eq!(
            state.storage_capacity.lock().await.reserved_bytes,
            (static_storage::CHUNK_SIZE + 16) as u64
        );
    }
}
