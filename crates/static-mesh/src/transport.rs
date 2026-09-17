//! Async TCP transport for Static network
//!
//! Implements:
//! - TCP listener for incoming peer connections
//! - TCP connector for outgoing peer connections
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
    try_read_message, write_message, MAX_MESSAGE_SIZE,
};
use static_sphinx::{
    SphinxPacket, MixNode, process_packet, RoutingFlag,
    NodeId,
};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, RwLock, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader, BufWriter};
use tokio::time;
use tracing::{info, warn, error, debug};

/// Size of a node ID
pub const NODE_ID_SIZE: usize = 16;

/// Channel buffer size for messages
pub const CHANNEL_BUFFER: usize = 256;

/// Read buffer size
pub const READ_BUFFER_SIZE: usize = MAX_MESSAGE_SIZE + 1024;

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
}

/// An inbound message from a peer
#[derive(Debug)]
pub struct InboundMessage {
    /// The sending peer's node ID
    pub from: NodeId,
    /// The message content
    pub message: WireMessage,
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

/// Handle an incoming TCP connection
///
/// Performs handshake, then enters read loop.
pub async fn handle_incoming_connection(
    stream: TcpStream,
    addr: SocketAddr,
    state: Arc<TransportState>,
) {
    debug!("Incoming connection from {}", addr);

    let (read_half, write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half);
    let mut writer = BufWriter::new(write_half);

    // Read handshake from peer
    let mut buf = vec![0u8; READ_BUFFER_SIZE];
    let mut read_buf = bytes::BytesMut::with_capacity(READ_BUFFER_SIZE);

    // Read until we have a complete handshake
    loop {
        let n = match reader.read(&mut buf).await {
            Ok(0) => {
                warn!("Peer {} disconnected during handshake", addr);
                return;
            }
            Ok(n) => n,
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
                    });
                    
                    let mut write_buf = bytes::BytesMut::new();
                    if let Err(e) = write_message(&mut write_buf, &our_hs) {
                        warn!("Failed to serialize handshake for {}: {}", addr, e);
                        return;
                    }
                    if let Err(e) = writer.write_all(&write_buf).await {
                        warn!("Failed to send handshake to {}: {}", addr, e);
                        return;
                    }
                    let _ = writer.flush().await;

                    // Add to routing table
                    state.routing_table.write().await.add_node(KnownNode {
                        node_id: hs.node_id,
                        public_key: hs.public_key,
                        address: addr.to_string(),
                    });

                    // Set up connection
                    let (tx, rx) = mpsc::channel::<WireMessage>(CHANNEL_BUFFER);
                    state.connections.write().await.insert(hs.node_id, tx.clone());
                    
                    // Spawn write loop
                    let write_state = state.clone();
                    let peer_id = hs.node_id;
                    tokio::spawn(async move {
                        write_loop(writer, rx, write_state, peer_id).await;
                    });

                    // Enter read loop
                    read_loop(reader, read_buf, state.clone(), peer_id).await;
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

    let stream = TcpStream::connect(addr).await?;
    let (read_half, write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half);
    let mut writer = BufWriter::new(write_half);

    // Send our handshake first
    let our_hs = WireMessage::Handshake(Handshake {
        node_id: state.node_id,
        public_key: state.mix_node.lock().await.public_key,
        tier: state.cover_config.read().await.tier,
    });

    let mut write_buf = bytes::BytesMut::new();
    write_message(&mut write_buf, &our_hs)?;
    writer.write_all(&write_buf).await?;
    let _ = writer.flush().await;

    // Read their handshake
    let mut buf = vec![0u8; READ_BUFFER_SIZE];
    let mut read_buf = bytes::BytesMut::with_capacity(READ_BUFFER_SIZE);

    loop {
        let n = reader.read(&mut buf).await?;
        if n == 0 {
            return Err(TransportError::HandshakeFailed("peer disconnected".into()));
        }
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
                    });

                    let (tx, rx) = mpsc::channel::<WireMessage>(CHANNEL_BUFFER);
                    state.connections.write().await.insert(hs.node_id, tx.clone());
                    
                    let write_state = state.clone();
                    let peer_id = hs.node_id;
                    tokio::spawn(async move {
                        write_loop(writer, rx, write_state, peer_id).await;
                    });

                    tokio::spawn(async move {
                        read_loop(reader, read_buf, state, peer_id).await;
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
            }
        }
    }
}

/// Read loop for a peer connection
///
/// Reads messages from the peer and processes them.
async fn read_loop(
    mut reader: BufReader<tokio::net::tcp::OwnedReadHalf>,
    mut read_buf: bytes::BytesMut,
    state: Arc<TransportState>,
    peer_id: NodeId,
) {
    let mut buf = vec![0u8; READ_BUFFER_SIZE];

    loop {
        // Try to read a message from the buffer
        match try_read_message(&mut read_buf) {
            Ok(Some(msg)) => {
                if let Err(e) = handle_message(msg, &state, peer_id).await {
                    warn!("Error handling message from {:02x?}: {}", peer_id, e);
                }
                continue;
            }
            Ok(None) => {} // Need more data
            Err(e) => {
                warn!("Wire error from {:02x?}: {}", peer_id, e);
                break;
            }
        }

        // Read more data
        match reader.read(&mut buf).await {
            Ok(0) => {
                info!("Peer {:02x?} disconnected", peer_id);
                break;
            }
            Ok(n) => {
                println!("[READ_LOOP] Read {} bytes from peer", n);
                read_buf.extend_from_slice(&buf[..n]);
            }
            Err(e) => {
                warn!("Read error from {:02x?}: {}", peer_id, e);
                break;
            }
        }
    }

    // Clean up connection
    state.connections.write().await.remove(&peer_id);
}

/// Handle an incoming message from a peer
async fn handle_message(
    msg: WireMessage,
    state: &Arc<TransportState>,
    from: NodeId,
) -> Result<(), TransportError> {
    println!("[HANDLE_MSG] Received message from {:02x?}", from);
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
                })
                .await;
        }
        WireMessage::Sphinx(packet) => {
            // Process the Sphinx packet through our mix node
            let mut mix_node = state.mix_node.lock().await;
            let result = process_packet(&mut mix_node, packet)?;
            drop(mix_node);

            match result.flag {
                RoutingFlag::Destination => {
                    // We are the destination - try to handle as chunk request
                    if let Some(body) = result.body {
                        println!("[HANDLE_MSG] Destination reached, body len: {}", body.len());
                        
                        // Try to parse as a chunk request
                        match static_storage::retrieval::deserialize_request(&body) {
                            Ok(request) => {
                                println!("[HANDLE_MSG] Parsed as ChunkRequest for chunk {:02x?}", request.chunk_id);
                                
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
                                            ephemeral_key: [0u8; 32],
                                            routing_info: vec![],
                                            mac: [0u8; 16],
                                        },
                                        body,
                                    }),
                                }).await;
                            }
                        }
                    }
                }
                RoutingFlag::Forward => {
                    // Forward to the next hop
                    if let Some(forward_packet) = result.forward_packet {
                        let next_hop = result.next_hop;
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

/// Write loop for a peer connection
///
/// Reads messages from the channel and writes them to the TCP stream.
/// Also generates cover traffic at a constant rate.
async fn write_loop(
    mut writer: BufWriter<tokio::net::tcp::OwnedWriteHalf>,
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

    loop {
        tokio::select! {
            // Real message to send
            Some(msg) = rx.recv() => {
                println!("[WRITE_LOOP] Received message to send to peer");
                let mut buf = bytes::BytesMut::new();
                if let Err(e) = write_message(&mut buf, &msg) {
                    warn!("Failed to serialize message to {:02x?}: {}", peer_id, e);
                    continue;
                }

                let msg_bytes = buf.len() as u64;
                if let Err(e) = writer.write_all(&buf).await {
                    warn!("Write error to {:02x?}: {}", peer_id, e);
                    break;
                }
                let _ = writer.flush().await;

                bytes_this_interval += msg_bytes;
                state.total_bytes_sent.fetch_add(msg_bytes, std::sync::atomic::Ordering::Relaxed);
                state.total_real_bytes_sent.fetch_add(msg_bytes, std::sync::atomic::Ordering::Relaxed);
            }

            // Cover traffic tick
            _ = interval.tick() => {
                let remaining = target_bytes_per_interval.saturating_sub(bytes_this_interval);
                
                if remaining > 0 && cover_config.enabled {
                    // Generate cover traffic
                    let dummy = generate_cover_packet(remaining as usize);
                    let mut buf = bytes::BytesMut::new();
                    
                    // Create a dummy Sphinx-like message
                    let dummy_msg = WireMessage::Sphinx(SphinxPacket {
                        header: static_sphinx::SphinxHeader {
                            ephemeral_key: dummy[..32].try_into().unwrap_or([0u8; 32]),
                            routing_info: dummy[32..32 + static_sphinx::ROUTING_INFO_SIZE].to_vec(),
                            mac: dummy[32 + static_sphinx::ROUTING_INFO_SIZE..32 + static_sphinx::ROUTING_INFO_SIZE + 16]
                                .try_into().unwrap_or([0u8; 16]),
                        },
                        body: dummy[32 + static_sphinx::ROUTING_INFO_SIZE + 16..].to_vec(),
                    });

                    if write_message(&mut buf, &dummy_msg).is_err() {
                        continue;
                    }

                    let cover_bytes = buf.len() as u64;
                    if writer.write_all(&buf).await.is_err() {
                        break;
                    }
                    let _ = writer.flush().await;

                    // bytes_this_interval is reset at the start of the next interval
                    state.total_bytes_sent.fetch_add(cover_bytes, std::sync::atomic::Ordering::Relaxed);
                    state.total_cover_bytes_sent.fetch_add(cover_bytes, std::sync::atomic::Ordering::Relaxed);
                }

                // Reset interval
                bytes_this_interval = 0;
            }
        }
    }
}

/// Generate a dummy packet for cover traffic
fn generate_cover_packet(size: usize) -> Vec<u8> {
    use rand::RngCore;
    let mut packet = vec![0u8; size];
    rand::rngs::OsRng.fill_bytes(&mut packet);
    packet
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

/// Start the TCP listener
pub async fn start_listener(
    addr: SocketAddr,
    state: Arc<TransportState>,
) -> Result<(), TransportError> {
    let listener = TcpListener::bind(addr).await?;
    info!("Listening on {}", addr);

    loop {
        match listener.accept().await {
            Ok((stream, peer_addr)) => {
                let state = state.clone();
                tokio::spawn(async move {
                    handle_incoming_connection(stream, peer_addr, state).await;
                });
            }
            Err(e) => {
                error!("Accept error: {}", e);
            }
        }
    }
}

/// Create transport state
pub fn create_transport_state(
    node_id: NodeId,
    mix_node: MixNode,
    cover_config: crate::CoverTrafficConfig,
) -> (Arc<TransportState>, mpsc::Receiver<InboundMessage>) {
    let (inbound_tx, inbound_rx) = mpsc::channel(CHANNEL_BUFFER);
    let routing_table = RoutingTable::new(node_id);
    let swap_state = SwapState::new();
    let storage_capacity = StorageCapacity::new(10 * 1024 * 1024 * 1024); // 10 GB default
    let storage_key = static_crypto::SymmetricKey::random();
    let chunk_holder = ChunkHolder::new();

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
        storage_capacity: Arc::new(Mutex::new(storage_capacity)),
        storage_key: Arc::new(Mutex::new(storage_key)),
        chunk_holder: Arc::new(Mutex::new(chunk_holder)),
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

    #[tokio::test]
    async fn test_transport_state_creation() {
        let node_id = random_node_id();
        let mix_node = MixNode::new();
        let cover_config = crate::CoverTrafficConfig::default();

        let (state, _rx) = create_transport_state(node_id, mix_node, cover_config);

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

        let (state, _rx) = create_transport_state(node_id, mix_node, cover_config);

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

        let (state, _rx) = create_transport_state(node_id, mix_node, cover_config);

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

        let (state1, _rx1) = create_transport_state(node1_id, node1_mix, cover_config.clone());

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
                        handle_incoming_connection(stream, addr, s).await;
                    });
                }
            }
        });

        // Node2 connects to node1
        let node2_id = random_node_id();
        let node2_mix = MixNode::new();
        let (state2, _rx2) = create_transport_state(node2_id, node2_mix, cover_config);

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

        let (state_a, _rx_a) = create_transport_state(node_a_id, mix_a, cover_config.clone());
        let (state_b, _rx_b) = create_transport_state(node_b_id, mix_b, cover_config.clone());
        let (state_c, mut rx_c) = create_transport_state(node_c_id, mix_c, cover_config);

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
                        handle_incoming_connection(stream, addr, s).await;
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
                        handle_incoming_connection(stream, addr, s).await;
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
}
