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
use static_storage::swap::{SwapState, StorageCapacity, decide_on_swap, create_swap_accept, create_swap_reject};
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
    /// Last refill timestamp (unix secs)
    pub last_refill: u64,
}

impl TokenBucket {
    /// Create a new bucket, full.
    pub fn new(max_tokens: u64, refill_rate: u64, now_secs: u64) -> Self {
        Self {
            tokens: max_tokens,
            max_tokens,
            refill_rate,
            last_refill: now_secs,
        }
    }

    fn now_secs() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }

    /// Refill based on elapsed wall time.
    pub fn refill(&mut self) {
        let now = Self::now_secs();
        let elapsed = now.saturating_sub(self.last_refill);
        if elapsed > 0 {
            self.tokens = self
                .tokens
                .saturating_add(elapsed.saturating_mul(self.refill_rate))
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
    pub swap_state: Arc<Mutex<SwapState>>,
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
    /// New peers are TOFU-pinned on first encounter.
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

            // Cover traffic tick
            _ = interval.tick() => {
                let cfg = state.cover_config.read().await.clone();
                // Keep bucket rate in sync with config.
                {
                    let mut bucket = state.cover_bucket.lock().await;
                    let cap = cfg.target_rate_bps.saturating_mul(2).max(4096);
                    bucket.set_rate(cfg.target_rate_bps, cap);
                }
                let target_bytes_per_interval = (cfg.target_rate_bps * cfg.interval_ms) / 1000;
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
async fn handle_message(
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
            // holder — only metadata and a reply — so the holder total,
            // and hence the counter, is unchanged by this path.)
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
                    // Strict 1:1 barter (Phase 0): store the offered chunk and
                    // return a real held chunk. No dummy 100B replies.
                    let chunk_len = proposal.chunk.data.len() as u64;
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
                    let return_entry: Option<(static_storage::ChunkId, Vec<u8>)> = {
                        let holder = state.chunk_holder.lock().await;
                        holder
                            .chunks
                            .iter()
                            .find(|(id, _)| **id != proposal.chunk.id)
                            .map(|(id, data)| (*id, data.clone()))
                    };
                    let Some((ret_id, ret_data)) = return_entry else {
                        // Nothing real to offer: reject instead of dummy.
                        let proposal_id = static_storage::swap::proposal_id(&proposal);
                        let reject = create_swap_reject(state.node_id, proposal_id, static_storage::swap::SwapRejectReason::NoCapacity);
                        let connections = state.connections.read().await;
                        if let Some(sender) = connections.get(&from) {
                            let _ = sender.send(WireMessage::SwapReject(reject)).await;
                        }
                        return Ok(());
                    };
                    // Store incoming (if new) + account.
                    {
                        let already = state.chunk_holder.lock().await.has_chunk(&proposal.chunk.id);
                        if !already {
                            state.chunk_holder.lock().await.add_chunk(
                                proposal.chunk.id,
                                proposal.chunk.data.clone(),
                                [0u8; 32],
                            );
                            state.storage_capacity.lock().await.record_accept(chunk_len);
                        }
                    }
                    {
                        // Track per-peer counts for TooManyFromPeer.
                        let mut counts = state.peer_chunk_counts.lock().await;
                        *counts.entry(from).or_insert(0) += 1;
                    }
                    // Clean pending (idempotency) + record active.
                    {
                        let pid = static_storage::swap::proposal_id(&proposal);
                        let mut swaps = state.swap_state.lock().await;
                        swaps.remove_proposal(&pid);
                        swaps.record_swap(proposal.chunk.id, from, chunk_len);
                    }

                    let master_key = state.storage_key.lock().await.clone();
                    let return_chunk = static_storage::EncryptedChunk {
                        id: ret_id,
                        data: ret_data,
                    };
                    let proposal_id = static_storage::swap::proposal_id(&proposal);
                    let accept = create_swap_accept(
                        state.node_id,
                        return_chunk,
                        &master_key,
                        proposal_id,
                        86400,
                    );
                    
                    // Send the acceptance back
                    let connections = state.connections.read().await;
                    if let Some(sender) = connections.get(&from) {
                        let _ = sender.send(WireMessage::SwapAccept(accept)).await;
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
            // Validate return size + store real chunk (strict barter).
            if accept.chunk.data.len() != static_storage::CHUNK_SIZE + 16 {
                return Ok(());
            }
            {
                let already = state.chunk_holder.lock().await.has_chunk(&accept.chunk.id);
                if !already {
                    // Capacity check before storing accept.
                    let fits = state.storage_capacity.lock().await.can_accept(
                        accept.chunk.data.len() as u64,
                        state.peer_chunk_counts.lock().await.get(&from).copied().unwrap_or(0),
                    );
                    if fits {
                        state.chunk_holder.lock().await.add_chunk(
                            accept.chunk.id,
                            accept.chunk.data.clone(),
                            [0u8; 32],
                        );
                        state.storage_capacity.lock().await.record_accept(accept.chunk.data.len() as u64);
                    }
                }
            }
            {
                let mut counts = state.peer_chunk_counts.lock().await;
                *counts.entry(from).or_insert(0) += 1;
            }
            state.swap_state.lock().await.record_swap(
                accept.chunk.id,
                from,
                accept.chunk.data.len() as u64,
            );
            // Clear the pending proposal this answers.
            state.swap_state.lock().await.remove_proposal(&accept.proposal_id);
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
                                let kem_lookup = |id: &NodeId| kem_map.get(id).cloned();

                                // Handle the retrieval request
                                match handle_retrieval_request(&body, chunk_data.as_deref(), &kem_lookup) {
                                    Ok(response_packets) => {
                                        if request.return_route.hops.is_empty() {
                                            return Ok(());
                                        }
                                        // Send each response packet to the first hop of the return route
                                        let first_hop = request.return_route.hops[0].node_id;
                                        for resp_packet in response_packets {
                                            let connections = state.connections.read().await;
                                            if let Some(sender) = connections.get(&first_hop) {
                                                let _ = sender.send(WireMessage::Sphinx(resp_packet)).await;
                                            }
                                        }
                                    }
                                    Err(_) => {}
                                }
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
pub fn create_transport_state(
    node_id: NodeId,
    mix_node: MixNode,
    cover_config: crate::CoverTrafficConfig,
    storage_capacity: Arc<Mutex<StorageCapacity>>,
) -> (Arc<TransportState>, mpsc::Receiver<InboundMessage>) {
    create_transport_state_with_identity(node_id, mix_node, cover_config, storage_capacity, None)
}

/// Create transport state with an explicit Ed25519 identity key.
///
/// Production callers pass the persistent key from `PersistentConfig`;
/// tests pass `None` for an ephemeral key.
pub fn create_transport_state_with_identity(
    node_id: NodeId,
    mix_node: MixNode,
    cover_config: crate::CoverTrafficConfig,
    storage_capacity: Arc<Mutex<StorageCapacity>>,
    identity_key: Option<ed25519_dalek::SigningKey>,
) -> (Arc<TransportState>, mpsc::Receiver<InboundMessage>) {
    let (inbound_tx, inbound_rx) = mpsc::channel(CHANNEL_BUFFER);
    let routing_table = RoutingTable::new(node_id);
    let swap_state = SwapState::new();
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
    let signing_key = identity_key.unwrap_or_else(|| {
        let mut bytes = [0u8; 32];
        use rand::RngCore;
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        ed25519_dalek::SigningKey::from_bytes(&bytes)
    });
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
        swap_state: Arc::new(Mutex::new(swap_state)),
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
    });

    (state, inbound_rx)
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

    #[tokio::test]
    async fn test_transport_state_creation() {
        let node_id = random_node_id();
        let mix_node = MixNode::new();
        let cover_config = crate::CoverTrafficConfig::default();

        let (state, _rx) = create_transport_state(node_id, mix_node, cover_config, test_capacity());

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

        let (state, _rx) = create_transport_state(node_id, mix_node, cover_config, test_capacity());

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

        let (state, _rx) = create_transport_state(node_id, mix_node, cover_config, test_capacity());

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

        let (state1, _rx1) = create_transport_state(node1_id, node1_mix, cover_config.clone(), test_capacity());

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
        let (state2, _rx2) = create_transport_state(node2_id, node2_mix, cover_config, test_capacity());

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

        let (state_a, _rx_a) = create_transport_state(node_a_id, mix_a, cover_config.clone(), test_capacity());
        let (state_b, _rx_b) = create_transport_state(node_b_id, mix_b, cover_config.clone(), test_capacity());
        let (state_c, mut rx_c) = create_transport_state(node_c_id, mix_c, cover_config, test_capacity());

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

    /// Build a swap proposal carrying a real chunk
    ///
    /// Chunk data must be exactly `CHUNK_SIZE + 16` bytes and the lease
    /// must be valid, or `decide_on_swap` rejects the proposal. A genuine
    /// single-chunk Merkle proof is generated so the integrity check
    /// passes.
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
            chunk,
            lease: static_storage::ChunkLease {
                chunk_id,
                expires_at: now + 86400,
                renewal_token: [0u8; 32],
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
    async fn test_dormant_swap_accept_stores_chunk() {
        let (state, _rx) = create_transport_state(
            random_node_id(),
            MixNode::new(),
            crate::CoverTrafficConfig::default(),
            test_capacity(),
        );
        // Dormant backup: serving disabled
        state
            .serve_enabled
            .store(false, std::sync::atomic::Ordering::Relaxed);

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

        handle_message(WireMessage::SwapProposal(proposal), &state, from)
            .await
            .unwrap();

        let expected_len = (static_storage::CHUNK_SIZE + 16) as u64 * 2;
        let holder = state.chunk_holder.lock().await;
        assert_eq!(holder.get_chunk(&chunk_id), Some(&data));
        assert_eq!(holder.total_bytes(), expected_len);
        drop(holder);
        assert_eq!(state.storage_capacity.lock().await.current_bytes, expected_len);
    }

    #[tokio::test]
    async fn test_active_swap_accept_stores_chunk_strict() {
        let (state, _rx) = create_transport_state(
            random_node_id(),
            MixNode::new(),
            crate::CoverTrafficConfig::default(),
            test_capacity(),
        );
        // Active node (default): strict 1:1 stores incoming + returns real.
        assert!(state.serve_enabled.load(std::sync::atomic::Ordering::Relaxed));

        let existing_id = [0xB0u8; 32];
        state
            .chunk_holder
            .lock()
            .await
            .add_chunk(existing_id, vec![0xAAu8; static_storage::CHUNK_SIZE + 16], [0u8; 32]);
        state.storage_capacity.lock().await.record_accept((static_storage::CHUNK_SIZE + 16) as u64);

        let from = random_node_id();
        let chunk_id = [0xB2u8; 32];
        let data = vec![0x5Du8; static_storage::CHUNK_SIZE + 16];
        let proposal = test_swap_proposal(from, chunk_id, data.clone());

        handle_message(WireMessage::SwapProposal(proposal), &state, from)
            .await
            .unwrap();

        assert_eq!(state.chunk_holder.lock().await.get_chunk(&chunk_id), Some(&data));
    }

    #[tokio::test]
    async fn test_active_swap_accept_stores_nothing() {
        let (state, _rx) = create_transport_state(
            random_node_id(),
            MixNode::new(),
            crate::CoverTrafficConfig::default(),
            test_capacity(),
        );
        // Active node (default): serving enabled, metadata-only swaps
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
        assert_eq!(state.storage_capacity.lock().await.current_bytes, 0);
    }

    #[tokio::test]
    async fn test_dormant_swap_rejects_tampered_chunk() {
        // Garbage-flooding protection end-to-end: a chunk tampered after
        // proof generation must not be materialized by a dormant backup.
        let (state, _rx) = create_transport_state(
            random_node_id(),
            MixNode::new(),
            crate::CoverTrafficConfig::default(),
            test_capacity(),
        );
        state
            .serve_enabled
            .store(false, std::sync::atomic::Ordering::Relaxed);

        let chunk_id = [0xB3u8; 32];
        let mut proposal = test_swap_proposal(
            random_node_id(),
            chunk_id,
            vec![0x5Eu8; static_storage::CHUNK_SIZE + 16],
        );
        let proof = proposal.merkle_proof.clone();
        let root = proposal.content_root;
        // Same size, different bytes: passes the size gate, fails integrity.
        proposal.chunk.data[0] ^= 0xFF;
        assert!(!static_storage::integrity::verify_chunk(
            &proposal.chunk,
            &proof,
            &root
        ));

        handle_message(WireMessage::SwapProposal(proposal), &state, random_node_id())
            .await
            .unwrap();

        // The tampered chunk was rejected (InvalidIntegrityTag), so the
        // dormant backup stored nothing.
        assert!(state.chunk_holder.lock().await.get_chunk(&chunk_id).is_none());
        assert_eq!(state.storage_capacity.lock().await.current_bytes, 0);
    }

    #[tokio::test]
    async fn test_dormant_backup_ignores_chunk_request() {
        // A dormant backup must not serve chunks it holds, even valid ones.
        let (state, _rx) = create_transport_state(
            random_node_id(),
            MixNode::new(),
            crate::CoverTrafficConfig::default(),
            test_capacity(),
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
