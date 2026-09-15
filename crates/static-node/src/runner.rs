//! Async node runner
//!
//! Ties together all Static components into a running node:
//! - TCP listener and connector for peer connections
//! - Sphinx mixnet processing for inbound packets
//! - Storage swap barter protocol handler
//! - Lease/heartbeat manager for owner control
//! - Chunk holder for serving retrieval requests
//! - Constant-rate cover traffic loop
//! - Lease expiration and repopulation loop

use rand::RngCore;
use crate::{NodeConfig, NodeStatus};
use static_accounting::AccountingState;
use static_crypto::SymmetricKey;
use static_mesh::transport::{
    TransportState, InboundMessage, create_transport_state,
    start_listener, connect_to_peer, get_stats, gossip_loop,
};
use static_mesh::wire::WireMessage;
use static_sphinx::{MixNode, NodeId, Route, RouteHop};
use static_storage::{
    EncryptedChunk, ChunkId, ContentId, ContentManifest,
    heartbeat::LeaseManager,
    retrieval::{ChunkHolder, ContentRetriever},
    swap::{SwapState, StorageCapacity},
};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::{info, warn, error, debug};

/// The running Static node
pub struct NodeRunner {
    /// Transport state (shared across tasks)
    pub transport: Arc<TransportState>,
    /// Lease manager (protected by mutex)
    pub leases: Arc<Mutex<LeaseManager>>,
    /// Swap state (protected by mutex)
    pub swaps: Arc<Mutex<SwapState>>,
    /// Storage capacity (protected by mutex)
    pub capacity: Arc<Mutex<StorageCapacity>>,
    /// Accounting state (protected by mutex)
    pub accounting: Arc<Mutex<AccountingState>>,
    /// Storage master key for this node's published content
    pub storage_keys: Arc<Mutex<HashMap<ContentId, SymmetricKey>>>,
    /// Content retriever for assembling files from chunks
    /// Content retriever for assembling files from chunks
    pub content_retriever: Arc<Mutex<ContentRetriever>>,
    /// Content retriever for tracking pending chunk retrievals
    /// Retrieval manager for tracking pending network fragments
    pub retriever: Arc<Mutex<static_mesh::retrieval::RetrievalManager>>,
    /// Inbound message receiver
    pub inbound_rx: Arc<tokio::sync::Mutex<tokio::sync::mpsc::Receiver<InboundMessage>>>,
    /// Node configuration
    pub config: NodeConfig,
}

impl NodeRunner {
    /// Create a new node runner
    pub fn new(config: NodeConfig, node_id: NodeId, mix_node: MixNode) -> Self {
        let cover_config = static_mesh::CoverTrafficConfig {
            target_rate_bps: config.cover_traffic_rate_bps,
            interval_ms: config.cover_traffic_interval_ms,
            enabled: config.cover_traffic_enabled,
            tier: config.tier,
        };

        let (transport, inbound_rx) = create_transport_state(node_id, mix_node, cover_config);

        Self {
            transport,
            leases: Arc::new(Mutex::new(LeaseManager::new())),
            swaps: Arc::new(Mutex::new(SwapState::new())),
            capacity: Arc::new(Mutex::new(StorageCapacity::new(config.max_storage_bytes))),
            accounting: Arc::new(Mutex::new(AccountingState::default())),
            storage_keys: Arc::new(Mutex::new(HashMap::new())),
            retriever: Arc::new(Mutex::new(static_mesh::retrieval::RetrievalManager::new())),
            content_retriever: Arc::new(Mutex::new(ContentRetriever::new())),
            inbound_rx: Arc::new(tokio::sync::Mutex::new(inbound_rx)),
            config,
        }
    }

    /// Start the node
    pub async fn run(self: Arc<Self>) -> anyhow::Result<()> {
        let node_id = self.transport.node_id;

        info!("Starting Static node: {:02x?}", node_id);

        // Start TCP listener
        let listen_addr: std::net::SocketAddr = self.config.listen_addr.parse()?;
        let transport_clone = self.transport.clone();
        tokio::spawn(async move {
            if let Err(e) = start_listener(listen_addr, transport_clone).await {
                error!("Listener error: {}", e);
            }
        });

        // Connect to bootstrap peers
        for peer_addr in &self.config.bootstrap_peers {
            let addr: std::net::SocketAddr = match peer_addr.parse() {
                Ok(addr) => addr,
                Err(e) => {
                    warn!("Invalid peer address '{}': {}", peer_addr, e);
                    continue;
                }
            };

            let transport = self.transport.clone();
            tokio::spawn(async move {
                debug!("Connecting to bootstrap peer: {}", addr);
                if let Err(e) = connect_to_peer(addr, transport).await {
                    warn!("Failed to connect to {}: {}", addr, e);
                }
            });
        }

        // Start lease expiration loop
        let leases = self.leases.clone();
        let chunks = self.transport.chunk_holder.clone();
        tokio::spawn(async move {
            lease_expiration_loop(leases, chunks).await;
        });

        // Start peer gossip loop
        let transport_for_gossip = self.transport.clone();
        tokio::spawn(async move {
            gossip_loop(transport_for_gossip, 60).await;
        });

        // Start local API server
        let api_addr = self.config.api_addr.clone();
        let runner_ref = self.clone();
        tokio::spawn(async move {
            if let Err(e) = crate::api::start_api_server(runner_ref, api_addr).await {
                tracing::error!("API server error: {}", e);
            }
        });

        info!("Node running. Processing inbound messages.");

        let mut inbound_rx = self.inbound_rx.lock().await;
        while let Some(inbound) = inbound_rx.recv().await {
            if let Err(e) = self.handle_inbound(inbound).await {
                warn!("Error handling inbound message: {}", e);
            }
        }

        info!("Node shutting down.");
        Ok(())
    }

    /// Handle an inbound message from the transport layer
    async fn handle_inbound(&self, inbound: InboundMessage) -> anyhow::Result<()> {
        match inbound.message {
            WireMessage::Sphinx(packet) => {
                debug!("Received Sphinx packet (destination) from {:02x?}", inbound.from);
                
                let mut manager = self.retriever.lock().await;
                if let Ok(Some(response)) = manager.process_fragment(&packet.body) {
                    if response.found {
                        let chunk = EncryptedChunk {
                            id: response.chunk_id,
                            data: response.chunk_data,
                        };
                        let mut content_retriever = self.content_retriever.lock().await;
                        if content_retriever.record_chunk(chunk).unwrap_or(false) {
                            debug!("Successfully retrieved chunk {:02x?}", response.chunk_id);
                        }
                    }
                }
            }
            _ => {}
        }
        Ok(())
    }

    /// Get node status
    pub async fn status(&self) -> NodeStatus {
        let transport_stats = get_stats(&self.transport).await;
        let _leases = self.leases.lock().await;
        let chunks = self.transport.chunk_holder.lock().await;
        let _swaps = self.swaps.lock().await;
        let accounting = self.accounting.lock().await;

        NodeStatus {
            running: true,
            node_id: self.transport.node_id,
            peer_count: transport_stats.connected_peers,
            connected_peers: transport_stats.connected_peers,
            stored_chunks: chunks.chunk_count(),
            published_content: self.storage_keys.lock().await.len(),
            cover_traffic_enabled: self.config.cover_traffic_enabled,
            total_bytes_served: accounting.total_bytes_served,
            total_bytes_received: accounting.total_bytes_received,
        }
    }

    /// Publish content to the network using the hidden service model
    pub async fn publish_content(
        &self,
        file_data: &[u8],
    ) -> anyhow::Result<(ContentId, ContentManifest, [u8; 32])> {
        // 1. Generate a keypair for this content
        let mut content_pub_key = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut content_pub_key);
        let content_id = static_storage::hidden_service::content_id_from_public(&content_pub_key);

        // 2. Encrypt the file into chunks
        let master_key = SymmetricKey::random();
        let nonce = static_crypto::NonceBytes::random();
        let (chunks, mut manifest) = static_storage::encrypt_file(&master_key, &nonce, file_data)?;

        // Update the manifest with the correct content_id
        manifest.content_id = content_id;

        // 3. Store the chunks locally
        {
            let mut holder = self.transport.chunk_holder.lock().await;
            for chunk in &chunks {
                holder.add_chunk(chunk.id, chunk.data.clone(), content_id);
            }
        }

        // 4. Store the master key in storage_keys
        self.storage_keys.lock().await.insert(content_id, master_key.clone());

        // 5. Encrypt the manifest
        let (encrypted_manifest, manifest_chunk_id) = static_storage::hidden_service::encrypt_manifest(&manifest, &content_pub_key)?;

        // 6. Store the encrypted manifest as a chunk locally
        {
            let mut holder = self.transport.chunk_holder.lock().await;
            holder.add_chunk(manifest_chunk_id, encrypted_manifest.ciphertext.clone(), content_id);
        }

        // 7. Register with lease manager
        let mut chunk_ids: Vec<ChunkId> = chunks.iter().map(|c| c.id).collect();
        chunk_ids.push(manifest_chunk_id); // Include the manifest chunk in the lease

        self.leases.lock().await.register_owned_content(
            content_id,
            master_key.clone(),
            chunk_ids.clone(),
        );

        tracing::info!("Published content: {:02x?} ({} chunks + 1 manifest)", content_id, chunks.len());

        Ok((content_id, manifest, content_pub_key))
    }

    /// Retrieve content from the network using the hidden service model
    pub async fn retrieve_content(
        &self,
        content_pub_key: &[u8; 32],
    ) -> anyhow::Result<Vec<u8>> {
        let content_id = static_storage::hidden_service::content_id_from_public(content_pub_key);
        tracing::info!("Retrieving content: {:02x?}", content_id);

        // 1. Ask peers for the encrypted manifest chunk
        let routing_table = self.transport.routing_table.read().await;
        let known_nodes: Vec<static_mesh::routing::KnownNode> = routing_table.nodes.values().cloned().collect();
        drop(routing_table);

        if known_nodes.is_empty() {
            return Err(anyhow::anyhow!("No known peers to request manifest from"));
        }

        let our_pubkey = self.transport.mix_node.lock().await.public_key;
        let our_node_id = self.transport.node_id;
        let return_route = Route {
            hops: vec![RouteHop { public_key: our_pubkey, node_id: our_node_id }],
            destination: our_node_id,
        };

        let peer = &known_nodes[0];
        let forward_route = Route {
            hops: vec![RouteHop { public_key: peer.public_key, node_id: peer.node_id }],
            destination: peer.node_id,
        };

        // We request the content_id itself, as the publisher stored the encrypted manifest there
        let request_packet = static_mesh::retrieval::create_anonymous_request(
            content_id,
            &return_route,
            &forward_route,
        )?;

        static_mesh::transport::send_sphinx(&self.transport, peer.node_id, request_packet).await?;

        // 2. Wait for the encrypted manifest to arrive
        let mut manager = self.retriever.lock().await;
        manager.start_retrieval(content_id);

        let timeout = tokio::time::sleep(std::time::Duration::from_secs(10));
        tokio::pin!(timeout);

        let mut encrypted_manifest_data: Option<Vec<u8>> = None;
        
        loop {
            tokio::select! {
                _ = &mut timeout => {
                    return Err(anyhow::anyhow!("Timeout waiting for manifest"));
                }
                _ = tokio::time::sleep(std::time::Duration::from_millis(100)) => {
                    let r = self.content_retriever.lock().await;
                    if r.is_complete() {
                        encrypted_manifest_data = Some(r.assemble()?);
                        drop(r);
                        let mut r = self.content_retriever.lock().await;
                        *r = ContentRetriever::new();
                        break;
                    }
                    drop(r);
                }
            }
        }

        let encrypted_manifest_data = encrypted_manifest_data.ok_or_else(|| anyhow::anyhow!("Failed to retrieve manifest"))?;
        
        // The response is a ChunkResponse. Deserialize it.
        let response: static_storage::retrieval::ChunkResponse = serde_json::from_slice(&encrypted_manifest_data)?;
        if !response.found {
            return Err(anyhow::anyhow!("Manifest not found on peer"));
        }

        // 3. Decrypt the manifest
        // In a full implementation, the nonce would be stored alongside the ciphertext.
        // For this prototype, we'll use a zero nonce as placeholder.
        let encrypted_manifest = static_storage::hidden_service::EncryptedManifest {
            ciphertext: response.chunk_data,
            nonce: static_crypto::NonceBytes::from_bytes([0u8; 12]),
        };
        
        let manifest = static_storage::hidden_service::decrypt_manifest(&encrypted_manifest, content_pub_key)
            .map_err(|e| anyhow::anyhow!("Failed to decrypt manifest: {}", e))?;

        // 4. Retrieve the chunks using the manifest
        let mut content_retriever = self.content_retriever.lock().await;
        let master_key = self.storage_keys.lock().await.get(&content_id).cloned()
            .ok_or_else(|| anyhow::anyhow!("Master key not found for content"))?;
        
        content_retriever.start_retrieval(manifest.clone(), master_key);

        // First check locally
        {
            let holder = self.transport.chunk_holder.lock().await;
            let pending_ids: Vec<ChunkId> = content_retriever.pending.keys().cloned().collect();
            drop(holder);
            
            for chunk_id in &pending_ids {
                let holder = self.transport.chunk_holder.lock().await;
                if let Some(data) = holder.get_chunk(chunk_id) {
                    let chunk = EncryptedChunk {
                        id: *chunk_id,
                        data: data.clone(),
                    };
                    drop(holder);
                    content_retriever.record_chunk(chunk)?;
                }
            }
        }

        if content_retriever.is_complete() {
            return Ok(content_retriever.assemble()?);
        }

        // For missing chunks, send requests to peers
        let pending_ids: Vec<ChunkId> = content_retriever.pending.keys().cloned().collect();
        for chunk_id in &pending_ids {
            let request_packet = static_mesh::retrieval::create_anonymous_request(*chunk_id, &return_route, &forward_route)?;
            static_mesh::transport::send_sphinx(&self.transport, peer.node_id, request_packet).await?;
        }

        // Wait for chunks to complete
        loop {
            let r = self.content_retriever.lock().await;
            if r.is_complete() {
                let result = r.assemble()?;
                drop(r);
                let mut r = self.content_retriever.lock().await;
                *r = ContentRetriever::new();
                return Ok(result);
            }
            drop(r);
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
    }
}

/// Lease expiration loop
async fn lease_expiration_loop(
    leases: Arc<Mutex<LeaseManager>>,
    chunks: Arc<Mutex<ChunkHolder>>,
) {
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));

    loop {
        interval.tick().await;
        
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let mut leases = leases.lock().await;
        let expired = leases.get_expired_chunks(current_time);

        if !expired.is_empty() {
            debug!("Found {} expired chunks", expired.len());
            
            let mut chunks = chunks.lock().await;
            for chunk_id in &expired {
                chunks.remove_chunk(chunk_id);
                leases.remove_lease(chunk_id);
            }
        }

        leases.cleanup_nonces(current_time);
    }
}
