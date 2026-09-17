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
use crate::wire::{
    self, WireMessage, Handshake,
    try_read_message, write_message, HYBRID_MAX_MESSAGE_SIZE,
};
use static_sphinx::{
    SphinxPacket, MixNode, process_packet, RoutingFlag,
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
                    debug!("Handshake from {}: node_id={:02x?}", addr, hs.node_id);
                    
                    // Send our handshake back
                    let our_hs = WireMessage::Handshake(Handshake {
                        node_id: state.node_id,
                        public_key: state.mix_node.lock().await.public_key,
                        tier: state.cover_config.read().await.tier,
                        kem_public_key: Some(state.kem.lock().await.public_bytes()),
                    });
                    
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
                        debug!("Partition heal detected (inbound) with {:02x?}", hs.node_id);
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

    // Send our handshake first
    let our_hs = WireMessage::Handshake(Handshake {
        node_id: state.node_id,
        public_key: state.mix_node.lock().await.public_key,
        tier: state.cover_config.read().await.tier,
        kem_public_key: Some(state.kem.lock().await.public_bytes()),
    });

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
                    debug!("Handshake from {}: node_id={:02x?}", addr, hs.node_id);
                    
                    // Add to routing table
                    state.routing_table.write().await.add_node(KnownNode {
                        node_id: hs.node_id,
                        public_key: hs.public_key,
                        address: addr.to_string(),
                        kem_public_key: hs.kem_public_key.clone(),
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
/// the peer. Runs until the connection dies, then cleans up (removes
/// the connection and remembers the peer for heal detection).
async fn connection_loop(
    connection: Arc<dyn Connection>,
    mut rx: mpsc::Receiver<WireMessage>,
    state: Arc<TransportState>,
    peer_id: NodeId,
) {
    let cover_config = state.cover_config.read().await.clone();
    let interval_ms = cover_config.interval_ms;
    let target_rate_bps = cover_config.target_rate_bps;
    let target_bytes_per_interval = (target_rate_bps * interval_ms) / 1000;

    let mut interval = time::interval(Duration::from_millis(interval_ms));
    let mut bytes_this_interval: u64 = 0;
    let mut read_buf = bytes::BytesMut::with_capacity(READ_BUFFER_SIZE);
    let mut read_chunk = vec![0u8; READ_BUFFER_SIZE];

    'conn: loop {
        tokio::select! {
            // Real message to send
            Some(msg) = rx.recv() => {
                println!("[WRITE_LOOP] Received message to send to peer");
                let mut wire_buf = bytes::BytesMut::new();
                if let Err(e) = write_message(&mut wire_buf, &msg) {
                    warn!("Failed to serialize message to {:02x?}: {}", peer_id, e);
                    continue;
                }

                let msg_bytes = wire_buf.len() as u64;
                if let Err(e) = connection.send_bytes(&wire_buf).await {
                    warn!("Write error to {:02x?}: {}", peer_id, e);
                    break;
                }

                bytes_this_interval += msg_bytes;
                state.total_bytes_sent.fetch_add(msg_bytes, std::sync::atomic::Ordering::Relaxed);
                state.total_real_bytes_sent.fetch_add(msg_bytes, std::sync::atomic::Ordering::Relaxed);
            }

            // Cover traffic tick
            _ = interval.tick() => {
                let remaining = target_bytes_per_interval.saturating_sub(bytes_this_interval);

                if remaining > 0 && cover_config.enabled {
                    // Generate cover traffic matching the configured packet
                    // version: hybrid nodes emit v1-sized dummies (with
                    // placeholder KEM ciphertexts) so cover is
                    // indistinguishable from real traffic of that version.
                    let dummy_msg = dummy_sphinx_message(cover_config.use_hybrid, remaining as usize);
                    let mut wire_buf = bytes::BytesMut::new();

                    if write_message(&mut wire_buf, &dummy_msg).is_err() {
                        continue;
                    }

                    let cover_bytes = wire_buf.len() as u64;
                    if connection.send_bytes(&wire_buf).await.is_err() {
                        break;
                    }

                    // bytes_this_interval is reset at the start of the next interval
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
                        println!("[READ_LOOP] Read {} bytes from peer", n);
                        read_buf.extend_from_slice(&read_chunk[..n]);
                        // Process all complete messages in the buffer
                        loop {
                            match try_read_message(&mut read_buf) {
                                Ok(Some(msg)) => {
                                    if let Err(e) = handle_message(msg, &state, peer_id).await {
                                        warn!("Error handling message from {:02x?}: {}", peer_id, e);
                                    }
                                }
                                Ok(None) => break, // Need more data
                                Err(e) => {
                                    warn!("Wire error from {:02x?}: {}", peer_id, e);
                                    break 'conn;
                                }
                            }
                        }
                    }
                    Ok(None) => {
                        info!("Peer {:02x?} disconnected", peer_id);
                        break;
                    }
                    Err(e) => {
                        warn!("Read error from {:02x?}: {}", peer_id, e);
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
    println!("[HANDLE_MSG] Received message from {:02x?}", from);
    // Any inbound message is proof of life: refresh the peer's
    // liveness timestamp (backup nodes use this as the heartbeat).
    state.note_peer_activity(from);
    match msg {
        WireMessage::Handshake(_) => {
            warn!("Unexpected handshake from connected peer {:02x?}", from);
        }
        WireMessage::Gossip(gossip) => {
            let new_peers = state.routing_table.write().await.process_gossip(&gossip);
            if new_peers > 0 {
                debug!("Added {} new peers from gossip by {:02x?}", new_peers, from);
            }
        }
        WireMessage::SwapProposal(proposal) => {
            debug!("Received swap proposal from {:02x?} for chunk {:02x?}", from, proposal.chunk.id);
            
            // Validate the proposal
            let current_time = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
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

            let capacity = state.storage_capacity.lock().await;
            let result = decide_on_swap(
                &proposal,
                &capacity,
                0, // peer_chunks - would track this in a real implementation
                static_storage::CHUNK_SIZE + 16,
                current_time,
            );
            drop(capacity);
            
            match result {
                Ok(()) => {
                    // Dormant backup nodes materialize the offered chunk
                    // locally: this is how backups acquire content (the
                    // rotation swaps of full-node primaries deliver real
                    // chunks). Active nodes keep the metadata-only swap
                    // behavior: nothing is stored, so nothing is
                    // accounted (item 16 invariant).
                    if !state
                        .serve_enabled
                        .load(std::sync::atomic::Ordering::Relaxed)
                    {
                        let chunk_len = proposal.chunk.data.len() as u64;
                        let already_held = state
                            .chunk_holder
                            .lock()
                            .await
                            .has_chunk(&proposal.chunk.id);
                        if !already_held {
                            let fits = state
                                .storage_capacity
                                .lock()
                                .await
                                .can_accept(chunk_len, 0);
                            if fits {
                                state.chunk_holder.lock().await.add_chunk(
                                    proposal.chunk.id,
                                    proposal.chunk.data.clone(),
                                    [0u8; 32], // swaps carry no content binding
                                );
                                state
                                    .storage_capacity
                                    .lock()
                                    .await
                                    .record_accept(chunk_len);
                                debug!(
                                    "Dormant backup stored swapped chunk {:02x?} ({} bytes)",
                                    proposal.chunk.id, chunk_len
                                );
                            }
                        }
                    }

                    // Accept the swap - create a return chunk
                    // In a real implementation, we'd select one of our chunks to offer
                    // For now, create a dummy chunk
                    let master_key = state.storage_key.lock().await.clone();
                    let nonce = static_crypto::NonceBytes::random();
                    let dummy_data = vec![0u8; 100];
                    let return_chunk = static_storage::encrypt_chunk(
                        &master_key, &nonce, 0, &dummy_data,
                    ).unwrap();
                    
                    let proposal_id = static_storage::swap::proposal_id(&proposal);
                    let accept = create_swap_accept(
                        state.node_id,
                        return_chunk,
                        &master_key,
                        proposal_id,
                        86400,
                    );
                    
                    // Record the swap
                    state.swap_state.lock().await.record_swap(
                        proposal.chunk.id,
                        from,
                        proposal.chunk.data.len() as u64,
                    );
                    
                    // Send the acceptance back
                    let connections = state.connections.read().await;
                    if let Some(sender) = connections.get(&from) {
                        let _ = sender.send(WireMessage::SwapAccept(accept)).await;
                        debug!("Sent swap acceptance to {:02x?}", from);
                    }
                }
                Err(reason) => {
                    let proposal_id = static_storage::swap::proposal_id(&proposal);
                    let reject = create_swap_reject(state.node_id, proposal_id, reason);
                    
                    let connections = state.connections.read().await;
                    if let Some(sender) = connections.get(&from) {
                        let _ = sender.send(WireMessage::SwapReject(reject)).await;
                        debug!("Sent swap rejection to {:02x?}: {:?}", from, reason);
                    }
                }
            }
        }
        WireMessage::SwapAccept(accept) => {
            debug!("Received swap acceptance from {:02x?}", from);
            state.swap_state.lock().await.record_swap(
                accept.chunk.id,
                from,
                accept.chunk.data.len() as u64,
            );
        }
        WireMessage::SwapReject(reject) => {
            debug!("Received swap rejection from {:02x?}: {:?}", from, reject.reason);
            state.swap_state.lock().await.rejected_swaps += 1;
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
            // Version dispatch: v0 → classical X25519, v1 → hybrid
            // X25519 + ML-KEM (both required to recover hop keys).
            let outcome = if packet.header.version == static_sphinx::SPHINX_VERSION_HYBRID {
                let kem_secret = state.kem.lock().await.secret_bytes();
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
            } else {
                // Process the Sphinx packet through our mix node
                let mut mix_node = state.mix_node.lock().await;
                let result = process_packet(&mut mix_node, packet)?;
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
                        println!("[HANDLE_MSG] Destination reached, body len: {}", body.len());

                        // Try to parse as a chunk request
                        match static_storage::retrieval::deserialize_request(&body) {
                            Ok(request) => {
                                println!("[HANDLE_MSG] Parsed as ChunkRequest for chunk {:02x?}", request.chunk_id);

                                // Dormant backup nodes hold chunks but do
                                // not serve them. All other traffic keeps
                                // flowing, so a dormant backup remains
                                // indistinguishable from any other peer.
                                if !state
                                    .serve_enabled
                                    .load(std::sync::atomic::Ordering::Relaxed)
                                {
                                    debug!(
                                        "Dormant backup ignoring chunk request for {:02x?}",
                                        request.chunk_id
                                    );
                                    return Ok(());
                                }

                                // Look up the chunk in our holder
                                let chunk_data = {
                                    let holder = state.chunk_holder.lock().await;
                                    holder.get_chunk(&request.chunk_id).map(|d| d.clone())
                                };
                                
                                // Handle the retrieval request
                                match handle_retrieval_request(&body, chunk_data.as_deref()) {
                                    Ok(response_packets) => {
                                        println!("[HANDLE_MSG] Generated {} response packets", response_packets.len());
                                        
                                        // Send each response packet to the first hop of the return route
                                        let first_hop = request.return_route.hops[0].node_id;
                                        println!("[HANDLE_MSG] Sending response to first hop: {:02x?}", first_hop);
                                        for resp_packet in response_packets {
                                            let connections = state.connections.read().await;
                                            if let Some(sender) = connections.get(&first_hop) {
                                                println!("[HANDLE_MSG] Found connection, sending packet...");
                                                let _ = sender.send(WireMessage::Sphinx(resp_packet)).await;
                                            } else {
                                                println!("[HANDLE_MSG] No connection to first hop {:02x?}!", first_hop);
                                            }
                                        }
                                    }
                                    Err(e) => {
                                        println!("[HANDLE_MSG] Failed to handle retrieval request: {}", e);
                                    }
                                }
                            }
                            Err(_) => {
                                println!("[HANDLE_MSG] Not a chunk request, sending to inbound channel");
                                // Not a chunk request - send to inbound channel
                                let _ = state.inbound_tx.send(InboundMessage {
                                    from,
                                    message: WireMessage::Sphinx(SphinxPacket {
                                        header: static_sphinx::SphinxHeader {
                                            version: static_sphinx::SPHINX_VERSION_CLASSICAL,
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
                            debug!("Forwarding Sphinx packet to {:02x?}", next_hop);
                            if sender.send(WireMessage::Sphinx(forward_packet)).await.is_err() {
                                warn!("Failed to forward to {:02x?}: channel closed", next_hop);
                            }
                        } else {
                            warn!("No connection to next hop {:02x?}", next_hop);
                        }
                    }
                }
            }
        }
    }
    Ok(())
}

/// Generate a dummy packet for cover traffic
fn generate_cover_packet(size: usize) -> Vec<u8> {
    use rand::RngCore;
    let mut packet = vec![0u8; size];
    rand::rngs::OsRng.fill_bytes(&mut packet);
    packet
}

/// Build a dummy Sphinx message for cover traffic
///
/// The dummy matches the configured packet version's wire size: classical
/// dummies are fixed-size v0 packets, hybrid dummies are v1 packets sized
/// to `budget` (up to the 5-hop hybrid maximum) with random KEM bytes.
/// Field slicing is bounds-checked so small budgets cannot panic.
fn dummy_sphinx_message(use_hybrid: bool, budget: usize) -> WireMessage {
    use rand::RngCore;

    if !use_hybrid {
        let dummy = generate_cover_packet(
            32 + static_sphinx::ROUTING_INFO_SIZE + 16 + static_sphinx::BODY_SIZE,
        );
        let routing_end = 32 + static_sphinx::ROUTING_INFO_SIZE;
        let mac_end = routing_end + 16;
        return WireMessage::Sphinx(SphinxPacket {
            header: static_sphinx::SphinxHeader {
                version: static_sphinx::SPHINX_VERSION_CLASSICAL,
                ephemeral_key: dummy[..32].try_into().unwrap_or([0u8; 32]),
                routing_info: dummy[32..routing_end].to_vec(),
                mac: dummy[routing_end..mac_end].try_into().unwrap_or([0u8; 16]),
            },
            kem_ciphertexts: Vec::new(),
            body: dummy[mac_end..].to_vec(),
        });
    }

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
        
        let table = state.routing_table.read().await;
        let gossip = table.create_gossip(50);
        drop(table);
        
        let connections = state.connections.read().await;
        if connections.is_empty() {
            continue;
        }
        
        debug!("Gossiping {} peers to {} connected peers", gossip.peers.len(), connections.len());
        
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
    let (inbound_tx, inbound_rx) = mpsc::channel(CHANNEL_BUFFER);
    let routing_table = RoutingTable::new(node_id);
    let swap_state = SwapState::new();
    let storage_key = static_crypto::SymmetricKey::random();
    let chunk_holder = ChunkHolder::new();
    let transport: Arc<dyn Transport> = Arc::new(TcpTransport::new());

    let state = Arc::new(TransportState {
        node_id,
        mix_node: Arc::new(Mutex::new(mix_node)),
        connections: Arc::new(RwLock::new(HashMap::new())),
        pending: Arc::new(RwLock::new(HashMap::new())),
        cover_config: Arc::new(RwLock::new(cover_config)),
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
        previously_connected: Arc::new(RwLock::new(HashSet::new())),
        serve_enabled: Arc::new(std::sync::atomic::AtomicBool::new(true)),
        peer_activity: Arc::new(std::sync::Mutex::new(HashMap::new())),
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
    println!("[SPHINX] Attempting to send to peer {:02x?}", peer);
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
    use super::wire::*;
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
        // Create 3 nodes: A -> B -> C
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

        // Create a Sphinx packet: A -> B -> C (destination)
        let route = Route {
            hops: vec![
                RouteHop {
                    public_key: state_b.mix_node.lock().await.public_key,
                    node_id: node_b_id,
                },
                RouteHop {
                    public_key: state_c.mix_node.lock().await.public_key,
                    node_id: node_c_id,
                },
            ],
            destination: node_c_id,
        };

        let body = b"end to end sphinx test";
        let packet = create_packet(&route, body).unwrap();

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
    /// must be valid, or `decide_on_swap` rejects the proposal.
    fn test_swap_proposal(from: NodeId, chunk_id: [u8; 32], data: Vec<u8>) -> static_storage::swap::SwapProposal {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        static_storage::swap::SwapProposal {
            from_node: from,
            chunk: static_storage::EncryptedChunk { id: chunk_id, data },
            lease: static_storage::ChunkLease {
                chunk_id,
                expires_at: now + 86400,
                renewal_token: [0u8; 32],
            },
            encrypted_master_key: Vec::new(),
        }
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

        let chunk_id = [0xB1u8; 32];
        let data = vec![0x5Cu8; static_storage::CHUNK_SIZE + 16];
        let proposal = test_swap_proposal(random_node_id(), chunk_id, data.clone());

        handle_message(WireMessage::SwapProposal(proposal), &state, random_node_id())
            .await
            .unwrap();

        let expected_len = (static_storage::CHUNK_SIZE + 16) as u64;
        let holder = state.chunk_holder.lock().await;
        assert_eq!(holder.get_chunk(&chunk_id), Some(&data));
        assert_eq!(holder.total_bytes(), expected_len);
        drop(holder);
        assert_eq!(state.storage_capacity.lock().await.current_bytes, expected_len);
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
