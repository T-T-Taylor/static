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

        // Start local API server
        let api_addr = self.config.api_addr.clone();
        let runner_ref = self.clone();
        tokio::spawn(async move {
            if let Err(e) = crate::api::start_api_server(runner_ref, api_addr).await {
                tracing::error!("API server error: {}", e);
            }
        });

        // Start peer gossip loop
        let transport_for_gossip = self.transport.clone();
        tokio::spawn(async move {
            gossip_loop(transport_for_gossip, 60).await;
        });

        // Main inbound message processing loop
        info!("Node running. Processing inbound messages.");
        
        while let Some(inbound) = self.inbound_rx.lock().await.recv().await {
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
                
                // Feed the fragment to the retrieval manager
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

    /// Handle a decrypted Sphinx body

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

    /// Publish content to the network
    pub async fn publish_content(
        &self,
        file_data: &[u8],
    ) -> anyhow::Result<(ContentId, ContentManifest, SymmetricKey)> {
        let master_key = SymmetricKey::random();
        let nonce = static_crypto::NonceBytes::random();

        let (chunks, manifest) = static_storage::encrypt_file(&master_key, &nonce, file_data)?;

        let content_id = manifest.content_id;

        // Store the master key
        self.storage_keys.lock().await.insert(content_id, master_key.clone());

        // Register with lease manager
        let chunk_ids: Vec<ChunkId> = manifest.chunk_ids.clone();
        self.leases.lock().await.register_owned_content(
            content_id,
            master_key.clone(),
            chunk_ids.clone(),
        );

        // Add chunks to our holder
        {
            let mut holder = self.transport.chunk_holder.lock().await;
            for chunk in &chunks {
                holder.add_chunk(chunk.id, chunk.data.clone(), content_id);
            }
        }

        // In a real implementation, we'd now initiate swaps to distribute
        // chunks across the network. For now, we just hold them locally.
        info!("Published content: {:02x?} ({} chunks)", content_id, chunks.len());

        Ok((content_id, manifest, master_key))
    }

    /// Retrieve content from the network
    pub async fn retrieve_content(
        &self,
        manifest: ContentManifest,
        master_key: SymmetricKey,
    ) -> anyhow::Result<Vec<u8>> {
        let mut content_retriever = self.content_retriever.lock().await;
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
        drop(content_retriever);

        // For missing chunks, send requests to peers
        let pending_ids: Vec<ChunkId> = {
            let r = self.content_retriever.lock().await;
            r.pending.keys().cloned().collect()
        };
        
        let routing_table = self.transport.routing_table.read().await;
        let known_nodes: Vec<static_mesh::routing::KnownNode> = routing_table.nodes.values().cloned().collect();
        drop(routing_table);

        if known_nodes.is_empty() {
            return Err(anyhow::anyhow!("No known peers to request chunks from"));
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

        // Register pending retrievals in the manager so handle_inbound can reassemble them
        let mut manager = self.retriever.lock().await;
        for chunk_id in &pending_ids {
            manager.start_retrieval(*chunk_id);
        }
        drop(manager);

        for chunk_id in &pending_ids {
            let request_packet = static_mesh::retrieval::create_anonymous_request(*chunk_id, &return_route, &forward_route)?;
            static_mesh::transport::send_sphinx(&self.transport, peer.node_id, request_packet).await?;
        }

        // Wait for the content retriever to complete
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
///
/// Runs periodically to check for expired leases and remove chunks.
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

        // Clean up old nonces
        leases.cleanup_nonces(current_time);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::RngCore;
    use static_storage::CHUNK_SIZE;

    fn random_node_id() -> NodeId {
        let mut id = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut id);
        id
    }

    #[tokio::test]
    async fn test_node_runner_creation() {
        let config = NodeConfig {
            listen_addr: "127.0.0.1:0".to_string(),
            ..Default::default()
        };
        let node_id = random_node_id();
        let mix_node = MixNode::new();

        let runner = NodeRunner::new(config, node_id, mix_node);

        assert_eq!(runner.transport.node_id, node_id);
        assert_eq!(runner.config.bootstrap_peers.len(), 0);
    }

    #[tokio::test]
    async fn test_node_runner_status() {
        let config = NodeConfig::default();
        let node_id = random_node_id();
        let mix_node = MixNode::new();

        let runner = NodeRunner::new(config, node_id, mix_node);
        let status = runner.status().await;

        assert!(status.running);
        assert_eq!(status.node_id, node_id);
        assert_eq!(status.peer_count, 0);
    }

    #[tokio::test]
    async fn test_publish_content() {
        let config = NodeConfig::default();
        let node_id = random_node_id();
        let mix_node = MixNode::new();

        let runner = NodeRunner::new(config, node_id, mix_node);
        
        let file_data = vec![0x42u8; 100];
        let (_content_id, manifest, _master_key) = runner.publish_content(&file_data).await.unwrap();

        assert_eq!(manifest.original_size, 100);
        assert_eq!(manifest.chunk_ids.len(), 1);

        let chunks = runner.transport.chunk_holder.lock().await;
        assert_eq!(chunks.chunk_count(), 1);
    }

    #[tokio::test]
    async fn test_publish_and_retrieve() {
        let config = NodeConfig::default();
        let node_id = random_node_id();
        let mix_node = MixNode::new();

        let runner = NodeRunner::new(config, node_id, mix_node);
        
        let file_data = vec![0x42u8; 100];
        let (_content_id, manifest, _master_key) = runner.publish_content(&file_data).await.unwrap();

        // Retrieve the content
        let master_key = runner.storage_keys.lock().await
            .get(&manifest.content_id).cloned().unwrap();
        let retrieved = runner.retrieve_content(manifest, master_key).await.unwrap();

        assert_eq!(retrieved, file_data);
    }

    #[tokio::test]
    async fn test_publish_large_content() {
        let config = NodeConfig::default();
        let node_id = random_node_id();
        let mix_node = MixNode::new();

        let runner = NodeRunner::new(config, node_id, mix_node);
        
        let file_data = vec![0x42u8; CHUNK_SIZE * 3 + 50];
        let (_content_id, manifest, _master_key) = runner.publish_content(&file_data).await.unwrap();

        assert_eq!(manifest.chunk_ids.len(), 4); // 3 full + 1 partial

        let master_key = runner.storage_keys.lock().await
            .get(&manifest.content_id).cloned().unwrap();
        let retrieved = runner.retrieve_content(manifest, master_key).await.unwrap();

        assert_eq!(retrieved, file_data);
    }
}
