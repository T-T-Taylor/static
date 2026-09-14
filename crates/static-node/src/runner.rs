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
use static_sphinx::{MixNode, NodeId};
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
        };

        let (transport, inbound_rx) = create_transport_state(node_id, mix_node, cover_config);

        Self {
            transport,
            leases: Arc::new(Mutex::new(LeaseManager::new())),
            swaps: Arc::new(Mutex::new(SwapState::new())),
            capacity: Arc::new(Mutex::new(StorageCapacity::new(config.max_storage_bytes))),
            accounting: Arc::new(Mutex::new(AccountingState::default())),
            storage_keys: Arc::new(Mutex::new(HashMap::new())),
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
                // This is a decrypted Sphinx body that we are the destination for
                debug!("Received Sphinx packet (destination) from {:02x?}", inbound.from);
                
                // Try to parse as a chunk request or response
                // In a real implementation, we'd have a more sophisticated dispatch
                self.handle_sphinx_body(&inbound.from, &packet.body).await?;
            }
            WireMessage::Handshake(_) => {
                // Handshakes are handled by the transport layer
            }
            WireMessage::Gossip(_) => {
                // Gossip is handled by the transport layer (peers added to routing table)
            }
            WireMessage::SwapProposal(_) => {
                // Swap proposals are handled by the transport layer
            }
            WireMessage::SwapAccept(_) => {
                // Swap acceptances are handled by the transport layer
            }
            WireMessage::SwapReject(_) => {
                // Swap rejections are handled by the transport layer
            }
        }
        Ok(())
    }

    /// Handle a decrypted Sphinx body
    async fn handle_sphinx_body(&self, _from: &NodeId, body: &[u8]) -> anyhow::Result<()> {
        if body.is_empty() {
            return Ok(());
        }

        // Check message type byte
        match body[0] {
            static_storage::retrieval::MSG_CHUNK_REQUEST => {
                // Parse as chunk request
                match static_storage::retrieval::deserialize_request(body) {
                    Ok(request) => {
                        debug!("Received chunk request for chunk: {:02x?}", request.chunk_id);
                        
                        let holder = self.transport.chunk_holder.lock().await;
                        if let Some(response) = holder.handle_request(&request) {
                            debug!("Responding to chunk request (found: {})", response.found);
                            // In a real implementation, we'd send this response back
                            // through the mixnet using the return_route
                        }
                    }
                    Err(e) => {
                        warn!("Failed to parse chunk request: {}", e);
                    }
                }
            }
            static_storage::retrieval::MSG_CHUNK_RESPONSE => {
                // Parse as chunk response
                match static_storage::retrieval::deserialize_response(body) {
                    Ok(response) => {
                        debug!("Received chunk response for chunk: {:02x?} (found: {})", 
                               response.chunk_id, response.found);
                        
                        if response.found {
                            let chunk = EncryptedChunk {
                                id: response.chunk_id,
                                data: response.chunk_data,
                            };
                            
                            // In a real implementation, this would feed into the ContentRetriever
                            debug!("Received chunk data ({} bytes)", chunk.data.len());
                        }
                    }
                    Err(e) => {
                        warn!("Failed to parse chunk response: {}", e);
                    }
                }
            }
            _ => {
                debug!("Unknown message type: {}", body[0]);
            }
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

    /// Publish content to the network
    pub async fn publish_content(
        &self,
        file_data: &[u8],
    ) -> anyhow::Result<(ContentId, ContentManifest)> {
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
            master_key,
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

        Ok((content_id, manifest))
    }

    /// Retrieve content from the network
    pub async fn retrieve_content(
        &self,
        manifest: ContentManifest,
        master_key: SymmetricKey,
    ) -> anyhow::Result<Vec<u8>> {
        let mut retriever = ContentRetriever::new();
        retriever.start_retrieval(manifest, master_key);

        // In a real implementation, we'd send chunk requests through the mixnet
        // For now, just check if we have all chunks locally
        let holder = self.transport.chunk_holder.lock().await;
        let pending_ids: Vec<ChunkId> = retriever.pending.keys().cloned().collect();
        drop(holder);
        
        for chunk_id in &pending_ids {
            let holder = self.transport.chunk_holder.lock().await;
            if let Some(data) = holder.get_chunk(chunk_id) {
                let chunk = EncryptedChunk {
                    id: *chunk_id,
                    data: data.clone(),
                };
                drop(holder);
                retriever.record_chunk(chunk)?;
            }
        }

        if retriever.is_complete() {
            Ok(retriever.assemble()?)
        } else {
            Err(anyhow::anyhow!("Not all chunks available locally"))
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
        let (_content_id, manifest) = runner.publish_content(&file_data).await.unwrap();

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
        let (_content_id, manifest) = runner.publish_content(&file_data).await.unwrap();

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
        let (_content_id, manifest) = runner.publish_content(&file_data).await.unwrap();

        assert_eq!(manifest.chunk_ids.len(), 4); // 3 full + 1 partial

        let master_key = runner.storage_keys.lock().await
            .get(&manifest.content_id).cloned().unwrap();
        let retrieved = runner.retrieve_content(manifest, master_key).await.unwrap();

        assert_eq!(retrieved, file_data);
    }
}
