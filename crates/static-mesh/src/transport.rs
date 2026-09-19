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

use crate::routing::{RoutingTable, KnownNode};
use crate::retrieval::handle_retrieval_request;
use static_storage::swap::{
    SwapState, StorageCapacity, PendingSwap, decide_on_swap,
    create_swap_accept, create_swap_reject,
    MAX_PENDING_SWAPS,
};
use static_storage::heartbeat::LeaseManager;
use static_storage::retrieval::ChunkHolder;
use crate::wire;
use crate::wire::{
    WireMessage, Handshake,
    try_read_message, write_message, HYBRID_MAX_MESSAGE_SIZE,
};
use static_sphinx::{
    SphinxPacket, MixNode, RoutingFlag,
    NodeId,
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
            send_swap_control(
                self,
                swap.peer,
                WireMessage::SwapAbort(crate::wire::SwapAbort {
                    proposal_id: swap.proposal_id,
                    from_node: self.node_id,
                    reason: "pending swap timed out".to_string(),
                }),
            )
            .await;
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
        {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            if let Ok(mut cache) = self.handshake_nonces.lock() {
                cache.retain(|_, ts| now.saturating_sub(*ts) <= HANDSHAKE_NONCE_TTL_SECS);
                if cache.contains_key(&hs.nonce) {
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
                cache.insert(hs.nonce, now);
            }
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
/// Performs handshake, then enters the connection loop.
pub async fn handle_incoming_connection(
    connection: Box<dyn Connection>,
    addr: String,
    state: Arc<TransportState>,
) {
    debug!("Incoming connection from {}", addr);

    // Read handshake from peer
    let mut buf = vec![0u8; READ_BUFFER_SIZE];
    let mut read_buf = bytes::BytesMut::with_capacity(READ_BUFFER_SIZE);

    // Read until we have a complete handshake
    loop {
        let n = match connection.recv_bytes(&mut buf).await {
            Ok(Some(n)) => n,
            Ok(None) => {
                warn!("Peer {} disconnected during handshake", addr);
                return;
            }
            Err(e) => {
                warn!("Error reading handshake from {}: {}", addr, e);
                return;
            }
        };
        read_buf.extend_from_slice(&buf[..n]);

        if let Some(msg) = match try_read_message(&mut read_buf) {
            Ok(msg) => msg,
            Err(e) => {
                warn!("Wire error from {}: {}", addr, e);
                return;
            }
        } {
            match msg {
                WireMessage::Handshake(hs) => {
                    // Authenticate before any state change.
                    if !state.verify_handshake(&hs).await {
                        warn!("Rejected handshake with bad signature/KEM from {}", addr);
                        return;
                    }
                    // Send our handshake back
                    let our_hs = WireMessage::Handshake(state.signed_handshake().await);
                    
                    let mut write_buf = bytes::BytesMut::new();
                    if let Err(e) = write_message(&mut write_buf, &our_hs) {
                        warn!("Failed to serialize handshake for {}: {}", addr, e);
                        return;
                    }
                    if let Err(e) = connection.send_bytes(&write_buf).await {
                        warn!("Failed to send handshake to {}: {}", addr, e);
                        return;
                    }

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
                    return;
                }
                WireMessage::Sphinx(_) => {
                    warn!("Expected handshake, got Sphinx from {}", addr);
                    return;
                }
                WireMessage::Gossip(_) => {
                    warn!("Expected handshake, got Gossip from {}", addr);
                    return;
                }
                WireMessage::SwapProposal(_) => {
                    warn!("Expected handshake, got SwapProposal from {}", addr);
                    return;
                }
                WireMessage::SwapAccept(_) => {
                    warn!("Expected handshake, got SwapAccept from {}", addr);
                    return;
                }
                WireMessage::SwapReject(_) => {
                    warn!("Expected handshake, got SwapReject from {}", addr);
                    return;
                }
                WireMessage::SwapCommit(_) => {
                    warn!("Expected handshake, got SwapCommit from {}", addr);
                    return;
                }
                WireMessage::SwapAbort(_) => {
                    warn!("Expected handshake, got SwapAbort from {}", addr);
                    return;
                }
                WireMessage::Prepayment(_) => {
                    warn!("Expected handshake, got Prepayment from {}", addr);
                    return;
                }
                WireMessage::AccountingReconciliation(_) => {
                    warn!("Expected handshake, got AccountingReconciliation from {}", addr);
                    return;
                }
            }
        }
    }
}

/// Connect to a peer
pub async fn connect_to_peer(
    addr: SocketAddr,
    state: Arc<TransportState>,
) -> Result<(), TransportError> {
    debug!("Connecting to {}", addr);

    let connection = state.transport.connect(&addr.to_string()).await?;

    // Send our handshake first (signed, no tier)
    let our_hs = WireMessage::Handshake(state.signed_handshake().await);

    let mut write_buf = bytes::BytesMut::new();
    write_message(&mut write_buf, &our_hs)?;
    connection.send_bytes(&write_buf).await?;

    // Read their handshake
    let mut buf = vec![0u8; READ_BUFFER_SIZE];
    let mut read_buf = bytes::BytesMut::with_capacity(READ_BUFFER_SIZE);

    loop {
        let n = match connection.recv_bytes(&mut buf).await? {
            Some(n) => n,
            None => return Err(TransportError::HandshakeFailed("peer disconnected".into())),
        };
        read_buf.extend_from_slice(&buf[..n]);

        if let Some(msg) = try_read_message(&mut read_buf)? {
            match msg {
                WireMessage::Handshake(hs) => {
                    if !state.verify_handshake(&hs).await {
                        return Err(TransportError::HandshakeFailed("bad handshake signature/KEM".into()));
                    }
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

                    return Ok(());
                }
                WireMessage::Sphinx(_) => {
                    return Err(TransportError::HandshakeFailed("expected handshake".into()));
                }
                WireMessage::Gossip(_) => {
                    return Err(TransportError::HandshakeFailed("expected handshake, got gossip".into()));
                }
                WireMessage::SwapProposal(_) => {
                    return Err(TransportError::HandshakeFailed("expected handshake, got swap proposal".into()));
                }
                WireMessage::SwapAccept(_) => {
                    return Err(TransportError::HandshakeFailed("expected handshake, got swap accept".into()));
                }
                WireMessage::SwapReject(_) => {
                    return Err(TransportError::HandshakeFailed("expected handshake, got swap reject".into()));
                }
                WireMessage::SwapCommit(_) => {
                    return Err(TransportError::HandshakeFailed("expected handshake, got swap commit".into()));
                }
                WireMessage::SwapAbort(_) => {
                    return Err(TransportError::HandshakeFailed("expected handshake, got swap abort".into()));
                }
                WireMessage::Prepayment(_) => {
                    return Err(TransportError::HandshakeFailed("expected handshake, got prepayment".into()));
                }
                WireMessage::AccountingReconciliation(_) => {
                    return Err(TransportError::HandshakeFailed("expected handshake, got reconciliation".into()));
                }
            }
        }
    }
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
                    // Hybrid-only cover (v1-sized dummies).
                    let dummy_msg = dummy_sphinx_message(true, remaining as usize);
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
        WireMessage::Gossip(gossip) => {
            // Enforce sender binding: gossip must come from its claimed sender.
            if gossip.from_node != from {
                return Ok(());
            }
            let new_peers = state.routing_table.write().await.process_gossip(&gossip);
            if new_peers > 0 {
                debug!("Added {} new peers from gossip", new_peers);
            }
        }
        WireMessage::SwapProposal(proposal) => {
            // Validate the proposal
            let current_time = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();

            // Reconcile the shared capacity counter with holder reality
            // before deciding: the counter is maintained incrementally and
            // any missed update would otherwise corrupt the decision.
            // (No record_accept here: accepting stores nothing in the
            // holder — the 2-phase flow only reserves until commit.)
            let actual_bytes = {
                let holder = state.chunk_holder.lock().await;
                holder.total_bytes()
            };
            {
                let mut capacity = state.storage_capacity.lock().await;
                capacity.reconcile(actual_bytes);
            }

            let peer_chunks = {
                state.peer_chunk_counts.lock().await.get(&from).copied().unwrap_or(0)
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
                    // Spoof binding: proposal must come from its claimant.
                    if proposal.from_node != from {
                        let proposal_id = static_storage::swap::proposal_id(&proposal);
                        let reject = create_swap_reject(state.node_id, proposal_id, static_storage::swap::SwapRejectReason::InvalidLease);
                        let connections = state.connections.read().await;
                        if let Some(sender) = connections.get(&from) {
                            let _ = sender.send(WireMessage::SwapReject(reject)).await;
                        }
                        return Ok(());
                    }
                    // Select a real return chunk (first held, excluding offered).
                    // Only its ID goes on the wire; the peer fetches the
                    // data via the Sphinx retrieval protocol.
                    let return_entry: Option<static_storage::ChunkId> = {
                        let holder = state.chunk_holder.lock().await;
                        holder
                            .chunks
                            .iter()
                            .find(|(id, _)| **id != proposal.chunk_id)
                            .map(|(id, _data)| *id)
                    };
                    let Some(ret_id) = return_entry else {
                        // Nothing real to offer: reject instead of dummy.
                        let proposal_id = static_storage::swap::proposal_id(&proposal);
                        let reject = create_swap_reject(state.node_id, proposal_id, static_storage::swap::SwapRejectReason::NoCapacity);
                        let connections = state.connections.read().await;
                        if let Some(sender) = connections.get(&from) {
                            let _ = sender.send(WireMessage::SwapReject(reject)).await;
                        }
                        return Ok(());
                    };
                    // DoS bound: too many pending swaps pin too much
                    // buffered chunk memory.
                    {
                        let swaps = state.swap_state.lock().await;
                        if swaps.pending_swaps.len() >= MAX_PENDING_SWAPS {
                            let proposal_id = static_storage::swap::proposal_id(&proposal);
                            let reject = create_swap_reject(state.node_id, proposal_id, static_storage::swap::SwapRejectReason::NoCapacity);
                            let connections = state.connections.read().await;
                            if let Some(sender) = connections.get(&from) {
                                let _ = sender.send(WireMessage::SwapReject(reject)).await;
                            }
                            return Ok(());
                        }
                    }
                    // Prepare phase: reserve capacity atomically (re-check
                    // under the same lock that reserves) but store nothing.
                    // The proposal carries no data (metadata-only wire),
                    // so we reserve the fixed chunk size up front.
                    let chunk_len = (static_storage::CHUNK_SIZE + 16) as u64;
                    {
                        let mut capacity = state.storage_capacity.lock().await;
                        if !capacity.can_accept(chunk_len, peer_chunks) {
                            let proposal_id = static_storage::swap::proposal_id(&proposal);
                            let reject = create_swap_reject(state.node_id, proposal_id, static_storage::swap::SwapRejectReason::NoCapacity);
                            let connections = state.connections.read().await;
                            if let Some(sender) = connections.get(&from) {
                                let _ = sender.send(WireMessage::SwapReject(reject)).await;
                            }
                            return Ok(());
                        }
                        capacity.reserve(chunk_len);
                    }
                    // Track the pending 2-phase swap. Their chunk data is
                    // NOT on the wire: it arrives via the Sphinx-fragmented
                    // retrieval phase, is verified against the proposal's
                    // Merkle proof, and only then do we commit.
                    let pid = static_storage::swap::proposal_id(&proposal);
                    {
                        let mut swaps = state.swap_state.lock().await;
                        swaps.remove_proposal(&pid);
                        swaps.start_pending_swap(PendingSwap {
                            proposal_id: pid,
                            peer: from,
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

                    let master_key = state.storage_key.lock().await.clone();
                    let accept = create_swap_accept(
                        state.node_id,
                        ret_id,
                        &master_key,
                        pid,
                        86400,
                    );

                    // Send the acceptance back. No commit yet: we still
                    // have to retrieve and verify their chunk data via
                    // the Sphinx retrieval protocol before we are ready
                    // to finalize.
                    {
                        let connections = state.connections.read().await;
                        if let Some(sender) = connections.get(&from) {
                            let _ = sender.send(WireMessage::SwapAccept(accept)).await;
                        }
                    }
                }
                Err(reason) => {
                    let proposal_id = static_storage::swap::proposal_id(&proposal);
                    let reject = create_swap_reject(state.node_id, proposal_id, reason);
                    // Clean pending on reject too.
                    state.swap_state.lock().await.remove_proposal(&proposal_id);
                    state.swap_state.lock().await.rejected_swaps += 1;
                    let connections = state.connections.read().await;
                    if let Some(sender) = connections.get(&from) {
                        let _ = sender.send(WireMessage::SwapReject(reject)).await;
                    }
                }
            }
        }
        WireMessage::SwapAccept(accept) => {
            // Proposer side of the prepare phase: the accept is
            // metadata-only and names the return chunk by ID. Validate,
            // reserve capacity for the (fixed-size) return chunk — and
            // store nothing. The chunk data itself arrives via the
            // Sphinx retrieval phase.
            let pid = accept.proposal_id;
            let has_pending = {
                let swaps = state.swap_state.lock().await;
                swaps.get_pending_swap(&pid).is_some()
            };
            if !has_pending {
                // Stale or duplicate accept (no proposal in flight).
                return Ok(());
            }
            let chunk_len = (static_storage::CHUNK_SIZE + 16) as u64;
            // Reserve capacity for their return chunk; abort the swap if
            // we cannot honor the barter.
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
                send_swap_control(
                    state,
                    from,
                    WireMessage::SwapAbort(crate::wire::SwapAbort {
                        proposal_id: pid,
                        from_node: state.node_id,
                        reason: "no capacity for return chunk".to_string(),
                    }),
                )
                .await;
                return Ok(());
            }
            {
                let mut swaps = state.swap_state.lock().await;
                if let Some(swap) = swaps.pending_swaps.get_mut(&pid) {
                    swap.their_chunk_id = accept.chunk_id;
                    swap.reserved_bytes = chunk_len;
                    // The return chunk's lease terms come from the
                    // accepter (it minted the lease). The return chunk
                    // carries no content binding in chunk-level barter,
                    // so `content_pub_key` stays all-zero: the lease
                    // adopts the owner key on the first signed
                    // heartbeat (see `LeaseManager`).
                    swap.renewal_token = accept.lease.renewal_token;
                    swap.lease_expires_at = accept.lease.expires_at;
                }
            }
            // No commit yet: we must first retrieve their chunk over the
            // Sphinx retrieval protocol, verify it, and only then commit.
        }
        WireMessage::SwapCommit(commit) => {
            // Commit phase: the peer holds our chunk and is ready to
            // store. Finalize only when we have both sent and received
            // a commit for the proposal (and hold their chunk — it
            // arrives via the retrieval phase, see
            // `handle_swap_chunk_retrieval`).
            if commit.from_node != from {
                return Ok(());
            }
            let pid = commit.proposal_id;
            {
                // Auth: the commit must belong to a pending swap with
                // this exact peer.
                let swaps = state.swap_state.lock().await;
                if !swaps
                    .get_pending_swap(&pid)
                    .is_some_and(|swap| swap.peer == from)
                {
                    // Unknown proposal or wrong peer: ignore.
                    return Ok(());
                }
            }
            {
                let mut swaps = state.swap_state.lock().await;
                swaps.mark_commit_received(&pid);
            }
            finalize_swap_if_ready(state, &pid).await;
        }
        WireMessage::SwapAbort(abort) => {
            // One side failed (or the timeout fired): cancel the swap and
            // release the reserved capacity. Nothing is stored.
            if abort.from_node != from {
                return Ok(());
            }
            let pid = abort.proposal_id;
            let swap = state.swap_state.lock().await.abort_swap(&pid);
            if let Some(swap) = swap {
                state
                    .storage_capacity
                    .lock()
                    .await
                    .release_reserved(swap.reserved_bytes, false);
                debug!(
                    "Swap {:02x?} aborted by peer {:02x?}: {}",
                    pid,
                    from,
                    abort.reason
                );
            }
        }
        WireMessage::SwapReject(reject) => {
            state.swap_state.lock().await.rejected_swaps += 1;
            state.swap_state.lock().await.remove_proposal(&reject.proposal_id);
        }
        WireMessage::Prepayment(prepayment) => {
            // Prepayments are accounting metadata (like gossip): forward to
            // the node runner for validation. NodeRunner::handle_inbound
            // owns signature checks, rate limiting, sponsor limits, and
            // accounting updates to preserve layering (mesh = transport,
            // node = business logic).
            debug!(
                "Received prepayment from {:02x?} for content {:02x?} ({} bytes)",
                from, prepayment.content_id, prepayment.bytes
            );
            let _ = state
                .inbound_tx
                .send(InboundMessage {
                    from,
                    message: WireMessage::Prepayment(prepayment),
                    is_reconnection: false,
                })
                .await;
        }
        WireMessage::AccountingReconciliation(recon) => {
            // Reconciliation batches are accounting metadata: forward to
            // the runner, which owns last-write-wins merging.
            debug!(
                "Received accounting reconciliation from {:02x?} ({} entries)",
                from,
                recon.peer_credits.len()
            );
            let _ = state
                .inbound_tx
                .send(InboundMessage {
                    from,
                    message: WireMessage::AccountingReconciliation(recon),
                    is_reconnection: false,
                })
                .await;
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
                        // Try to parse as a chunk request
                        match static_storage::retrieval::deserialize_request(&body) {
                            Ok(request) => {
                                // Dormant backup nodes hold chunks but do
                                // not serve them. All other traffic keeps
                                // flowing, so a dormant backup remains
                                // indistinguishable from any other peer.
                                if !state
                                    .serve_enabled
                                    .load(std::sync::atomic::Ordering::Relaxed)
                                {
                                    return Ok(());
                                }

                                // Look up the chunk in our holder
                                let chunk_data = {
                                    let holder = state.chunk_holder.lock().await;
                                    holder.get_chunk(&request.chunk_id).map(|d| d.clone())
                                };
                                
                                // Hybrid response (Phase 0): resolve KEM keys
                                // for the return route from our routing table.
                                let kem_map: HashMap<NodeId, Vec<u8>> = {
                                    let table = state.routing_table.read().await;
                                    table
                                        .nodes
                                        .iter()
                                        .filter_map(|(id, n)| {
                                            n.kem_public_key
                                                .as_ref()
                                                .map(|k| (*id, k.clone()))
                                        })
                                        .collect()
                                };
                                let kem_lookup = move |id: &NodeId| kem_map.get(id).cloned();

                                // Handle the retrieval request. The response
                                // for a full-size chunk is ~1038 fragment
                                // packets — more than the outbound channel
                                // buffer — so building and sending runs in
                                // a detached task: this handler executes
                                // INLINE in the peer connection's read loop,
                                // and blocking here on the node's own
                                // outbound channel would deadlock (the
                                // connection loop is the only drainer).
                                let state_for_serve = state.clone();
                                let body_for_serve = body.clone();
                                tokio::spawn(async move {
                                    match handle_retrieval_request(
                                        &body_for_serve,
                                        chunk_data.as_deref(),
                                        &kem_lookup,
                                    ) {
                                        Ok(response_packets) => {
                                            if request.return_route.hops.is_empty() {
                                                return;
                                            }
                                            // Send each response packet to the first hop of the return route
                                            let first_hop = request.return_route.hops[0].node_id;
                                            for resp_packet in response_packets {
                                                let connections = state_for_serve.connections.read().await;
                                                if let Some(sender) = connections.get(&first_hop) {
                                                    let _ = sender.send(WireMessage::Sphinx(resp_packet)).await;
                                                }
                                            }
                                        }
                                        Err(_) => {}
                                    }
                                });
                            }
                            Err(_) => {
                                // Not a chunk request - send to inbound channel
                                let _ = state.inbound_tx.send(InboundMessage {
                                    from,
                                    message: WireMessage::Sphinx(SphinxPacket {
                                        header: static_sphinx::SphinxHeader {
                                            version: static_sphinx::SPHINX_VERSION_HYBRID,
                                            ephemeral_key: [0u8; 32],
                                            routing_info: vec![],
                                            mac: [0u8; 16],
                                        },
                                        kem_ciphertexts: Vec::new(),
                                        body,
                                    }),
                                    is_reconnection: false,
                                }).await;
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
    }
    Ok(())
}

/// Feed a chunk retrieved via the Sphinx retrieval protocol into a
/// pending 2-phase swap
///
/// Called by the node runner when a `ChunkResponse` completes: if the
/// response's chunk ID matches a pending swap still waiting for data,
/// the chunk is verified against the swap's stashed Merkle
/// proof/root and buffered in the pending swap. On success we send our
/// [`SwapCommit`](crate::wire::SwapCommit) (if not already sent) and
/// finalize when both commits are in. On verification failure the swap
/// is aborted, the reservation released, and a `SwapAbort` sent to the
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
            send_swap_control(
                state,
                peer,
                WireMessage::SwapAbort(crate::wire::SwapAbort {
                    proposal_id: pid,
                    from_node: state.node_id,
                    reason: "retrieved chunk failed integrity verification".to_string(),
                }),
            )
            .await;
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
        send_swap_control(
            state,
            peer,
            WireMessage::SwapCommit(crate::wire::SwapCommit {
                proposal_id: pid,
                from_node: state.node_id,
            }),
        )
        .await;
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
fn dummy_sphinx_message(_use_hybrid: bool, budget: usize) -> WireMessage {
    use rand::RngCore;

    // Hybrid dummy: fill the budget with version + ephemeral + as many
    // whole KEM ciphertexts as fit (capped at MAX_HOPS), random bytes
    // throughout. Validity is not required — only wire-size realism.
    let max_kem = static_sphinx::MAX_HOPS * static_sphinx::HYBRID_KEM_CIPHERTEXT_SIZE;
    let fixed = 32 + static_sphinx::ROUTING_INFO_SIZE + 16 + static_sphinx::BODY_SIZE;
    let kem_budget = budget.saturating_sub(fixed + 1 + 4);
    let kem_len = (kem_budget / static_sphinx::HYBRID_KEM_CIPHERTEXT_SIZE
        * static_sphinx::HYBRID_KEM_CIPHERTEXT_SIZE)
        .min(max_kem);
    let total = fixed + kem_len;
    let mut dummy = vec![0u8; total.max(32)];
    rand::rngs::OsRng.fill_bytes(&mut dummy);
    let routing_end = 32 + static_sphinx::ROUTING_INFO_SIZE;
    let mac_end = routing_end + 16;

    WireMessage::Sphinx(SphinxPacket {
        header: static_sphinx::SphinxHeader {
            version: static_sphinx::SPHINX_VERSION_HYBRID,
            ephemeral_key: dummy[..32].try_into().unwrap_or([0u8; 32]),
            routing_info: dummy.get(32..routing_end).unwrap_or(&[]).to_vec(),
            mac: dummy.get(routing_end..mac_end).unwrap_or(&[]).try_into().unwrap_or([0u8; 16]),
        },
        kem_ciphertexts: dummy.get(mac_end..mac_end + kem_len).unwrap_or(&[]).to_vec(),
        body: dummy.get(mac_end + kem_len..).unwrap_or(&[]).to_vec(),
    })
}

/// Background loop to periodically gossip known peers to connected peers
pub async fn gossip_loop(state: Arc<TransportState>, interval_secs: u64) {
    let mut interval = time::interval(Duration::from_secs(interval_secs));
    
    loop {
        interval.tick().await;
        
        // Signed gossip (Phase 0 sender auth).
        let gossip = {
            let table = state.routing_table.read().await;
            let sk_bytes = state.identity_key.to_bytes();
            let sk = ed25519_dalek::SigningKey::from_bytes(&sk_bytes);
            table.create_signed_gossip(50, &sk)
        };
        
        let connections = state.connections.read().await;
        if connections.is_empty() {
            continue;
        }
        
        for sender in connections.values() {
            let _ = sender.send(WireMessage::Gossip(gossip.clone())).await;
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
    });

    (state, inbound_rx)
}

/// Send a `SwapCommit` or `SwapAbort` to a swap peer
///
/// Commit/abort are direct wire maintenance traffic (like rejects), not
/// Sphinx-wrapped.
async fn send_swap_control(
    state: &TransportState,
    peer: NodeId,
    message: WireMessage,
) {
    let connections = state.connections.read().await;
    if let Some(sender) = connections.get(&peer) {
        let _ = sender.send(message).await;
    }
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

/// Send a prepayment to a sponsor peer
///
/// Prepayments are direct wire maintenance traffic (like gossip),
/// not Sphinx-wrapped. Sponsored chunks themselves are Sphinx-wrapped.
pub async fn send_prepayment(
    state: &Arc<TransportState>,
    peer: NodeId,
    prepayment: crate::wire::Prepayment,
) -> Result<(), TransportError> {
    let connections = state.connections.read().await;
    let sender = connections
        .get(&peer)
        .ok_or(TransportError::ConnectionNotFound(peer))?;

    sender
        .send(WireMessage::Prepayment(prepayment))
        .await
        .map_err(|_| TransportError::ChannelSend)
}

/// Send an accounting reconciliation batch to a reconnected peer
///
/// Reconciliation traffic is direct wire maintenance (like gossip),
/// not Sphinx-wrapped. Large states are split by the caller into
/// batches of at most `crate::wire::MAX_RECONCILIATION_ENTRIES`.
pub async fn send_reconciliation(
    state: &Arc<TransportState>,
    peer: NodeId,
    reconciliation: crate::wire::AccountingReconciliation,
) -> Result<(), TransportError> {
    let connections = state.connections.read().await;
    let sender = connections
        .get(&peer)
        .ok_or(TransportError::ConnectionNotFound(peer))?;

    sender
        .send(WireMessage::AccountingReconciliation(reconciliation))
        .await
        .map_err(|_| TransportError::ChannelSend)
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
        // Sign with ephemeral content key so binding + sig verify.
        let content_sk = ed25519_dalek::SigningKey::from_bytes(&[0x33u8; 32]);
        let content_pub = content_sk.verifying_key().to_bytes();
        let content_id = *blake3::hash(&content_pub).as_bytes();
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
            content_id,
            content_public_key: content_pub,
            content_signature: vec![],
        };
        {
            use ed25519_dalek::Signer;
            let sig = content_sk.sign(&proposal.signing_bytes());
            proposal.content_signature = sig.to_bytes().to_vec();
        }
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
        handle_message(WireMessage::SwapProposal(proposal.clone()), &state, from)
            .await
            .unwrap();

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
        handle_message(
            WireMessage::SwapCommit(crate::wire::SwapCommit { proposal_id: pid, from_node: from }),
            &state,
            from,
        )
        .await
        .unwrap();

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
        let accept = create_swap_accept(
            peer,
            their_id,
            &static_crypto::SymmetricKey::random(),
            pid,
            86400,
        );
        handle_message(WireMessage::SwapAccept(accept), &state, peer)
            .await
            .unwrap();

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
        handle_message(
            WireMessage::SwapCommit(crate::wire::SwapCommit { proposal_id: pid, from_node: peer }),
            &state,
            peer,
        )
        .await
        .unwrap();

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

        handle_message(WireMessage::SwapProposal(proposal), &state, from)
            .await
            .unwrap();
        assert_eq!(
            state.storage_capacity.lock().await.reserved_bytes,
            (static_storage::CHUNK_SIZE + 16) as u64
        );

        handle_message(
            WireMessage::SwapAbort(crate::wire::SwapAbort {
                proposal_id: pid,
                from_node: from,
                reason: "cannot honor barter".to_string(),
            }),
            &state,
            from,
        )
        .await
        .unwrap();

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

        handle_message(WireMessage::SwapProposal(proposal), &state, from)
            .await
            .unwrap();

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
        // Spoofed proposal (sender != claimant) is rejected: nothing
        // stored, nothing reserved.
        let (state, _rx) = test_state(
            random_node_id(),
            MixNode::new(),
            crate::CoverTrafficConfig::default(),
        );
        // Active node (default): serving enabled
        assert!(state.serve_enabled.load(std::sync::atomic::Ordering::Relaxed));

        let chunk_id = [0xB2u8; 32];
        let proposal = test_swap_proposal(
            random_node_id(),
            chunk_id,
            vec![0x5Du8; static_storage::CHUNK_SIZE + 16],
        );

        handle_message(WireMessage::SwapProposal(proposal), &state, random_node_id())
            .await
            .unwrap();

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
        handle_message(WireMessage::SwapProposal(proposal.clone()), &state, from)
            .await
            .unwrap();
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
        handle_message(WireMessage::SwapProposal(proposal), &state, from)
            .await
            .unwrap();

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
        };
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
}
