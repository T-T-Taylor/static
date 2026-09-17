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
use crate::{NodeConfig, NodeMode, NodeStatus};
use static_accounting::{AccountingState, PeerCredit, current_timestamp};
use static_crypto::SymmetricKey;
use static_mesh::transport::{
    TransportState, InboundMessage, create_transport_state,
    start_listener, connect_to_peer, get_stats, gossip_loop,
};
use static_mesh::wire::{
    AccountingReconciliation, Prepayment, ReconciliationEntry, WireMessage,
    MAX_RECONCILIATION_ENTRIES,
};
use static_sphinx::{MixNode, NodeId, Route, RouteHop};
use static_storage::{
    EncryptedChunk, ChunkId, ContentId, ContentManifest,
    repair::RepairState,
    heartbeat::LeaseManager,
    retrieval::{ChunkHolder, ContentRetriever},
    rotation::{RotationConfig, RotationState},
    swap::{SwapState, StorageCapacity},
};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::{info, warn, error, debug};

/// Peers idle longer than this are treated as possibly partitioned (1 hour)
pub const PARTITION_THRESHOLD_SECS: u64 = 3600;

/// Extra prune grace for possibly-partitioned peers (24 hours, additive)
pub const PARTITION_GRACE_PERIOD_SECS: u64 = 86400;

/// Default inactivity threshold before pruning a peer (7 days)
pub const PRUNE_MAX_AGE_SECS: u64 = 86400 * 7;

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
    /// Repair state for tracking chunk repairs
    pub repair_state: Arc<Mutex<RepairState>>,
    /// Rotation state for tracking chunk rotations and caching
    pub rotation_state: Arc<Mutex<RotationState>>,
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
        // Seed-only nodes do not host locally and only send seed packages
        // (heartbeats/funding) when requested. They opt out of full-rate
        // cover traffic as a documented privacy trade-off: they are funding
        // a sponsor rather than hosting content themselves.
        let (target_rate, cover_enabled) = match config.mode {
            NodeMode::SeedOnly => (1024, false),
            _ => (
                config.cover_traffic_rate_bps,
                config.cover_traffic_enabled,
            ),
        };
        let cover_config = static_mesh::CoverTrafficConfig {
            target_rate_bps: target_rate,
            interval_ms: config.cover_traffic_interval_ms,
            enabled: cover_enabled,
            tier: config.tier,
            use_hybrid: config.use_hybrid_crypto,
        };

        // One shared capacity counter for the whole node: the swap
        // decision path (transport), publish/cache accounting, and the
        // periodic reconciler all observe the same object, so the
        // counter cannot drift between layers.
        let capacity = Arc::new(Mutex::new(StorageCapacity::new(config.max_storage_bytes)));
        let (transport, inbound_rx) =
            create_transport_state(node_id, mix_node, cover_config, capacity.clone());

        Self {
            transport,
            leases: Arc::new(Mutex::new(LeaseManager::new())),
            swaps: Arc::new(Mutex::new(SwapState::new())),
            capacity,
            accounting: Arc::new(Mutex::new(AccountingState::default())),
            storage_keys: Arc::new(Mutex::new(HashMap::new())),
            retriever: Arc::new(Mutex::new(static_mesh::retrieval::RetrievalManager::new())),
            content_retriever: Arc::new(Mutex::new(ContentRetriever::new())),
            repair_state: Arc::new(Mutex::new(RepairState::new())),
            rotation_state: Arc::new(Mutex::new(RotationState::new())),
            inbound_rx: Arc::new(tokio::sync::Mutex::new(inbound_rx)),
            config,
        }
    }

    /// Start the node
    pub async fn run(self: Arc<Self>) -> anyhow::Result<()> {
        let node_id = self.transport.node_id;

        info!(
            "Starting Static node: {:02x?} (mode: {:?})",
            node_id, self.config.mode
        );

        match self.config.mode {
            NodeMode::BackupOnly => {
                // TODO: Implement health-check via gossip and activation logic.
                // Backup-only nodes are dormant: they run the listener but do
                // not serve chunks until the primary's heartbeats stop.
                info!("Backup-only mode: dormant, monitoring primary (stub)");
            }
            NodeMode::SeedOnly => {
                info!(
                    "Seed-only mode: no chunk listener, sponsor={:?}. Cover traffic disabled (privacy trade-off: funding-only node).",
                    self.config.sponsor
                );
            }
            NodeMode::Full => {}
        }

        // Seed-only nodes do NOT start the normal listener for chunk requests
        // (they have no chunks to serve). They only connect out to their
        // configured sponsor peer.
        let start_listener_flag = !matches!(self.config.mode, NodeMode::SeedOnly);
        if start_listener_flag {
            // Start TCP listener
            let listen_addr: std::net::SocketAddr = self.config.listen_addr.parse()?;
            let transport_clone = self.transport.clone();
            tokio::spawn(async move {
                if let Err(e) = start_listener(listen_addr, transport_clone).await {
                    error!("Listener error: {}", e);
                }
            });
        }

        // Build the dial list: sponsor first (seed-only requires it),
        // then bootstrap peers.
        let mut dial_addrs: Vec<String> = Vec::new();
        if matches!(self.config.mode, NodeMode::SeedOnly) {
            if let Some(sponsor) = &self.config.sponsor {
                dial_addrs.push(sponsor.clone());
            } else if self.config.bootstrap_peers.is_empty() {
                warn!("Seed-only node has no --sponsor configured; cannot publish until a sponsor is connected");
            }
        }
        dial_addrs.extend(self.config.bootstrap_peers.clone());

        // Connect to peers (sponsor + bootstrap)
        for peer_addr in &dial_addrs {
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
        let capacity_for_expiry = self.capacity.clone();
        tokio::spawn(async move {
            lease_expiration_loop(leases, chunks, capacity_for_expiry).await;
        });

        // Start repair loop
        let repair_state = self.repair_state.clone();
        let storage_keys = self.storage_keys.clone();
        let leases_for_repair = self.leases.clone();
        tokio::spawn(async move {
            repair_loop(repair_state, storage_keys, leases_for_repair).await;
        });

        // Start peer gossip loop (seed-only nodes are rate-limited: they only
        // send seed packages when requested and do not gossip at full rate).
        if !matches!(self.config.mode, NodeMode::SeedOnly) {
            let transport_for_gossip = self.transport.clone();
            tokio::spawn(async move {
                gossip_loop(transport_for_gossip, 60).await;
            });
        }

        // Start accounting prune loop with partition grace.
        // Partitioned-but-alive peers get PARTITION_GRACE_PERIOD_SECS extra
        // before eviction so a healed partition can still reconcile.
        let accounting_for_prune = self.accounting.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(3600));
            loop {
                interval.tick().await;
                accounting_for_prune.lock().await.prune_inactive_peers_with_grace(
                    PRUNE_MAX_AGE_SECS,
                    PARTITION_THRESHOLD_SECS,
                    PARTITION_GRACE_PERIOD_SECS,
                );
            }
        });

        // Start capacity reconciliation loop (safety net).
        // Individual store/remove paths maintain the shared counter
        // incrementally, but any missed update drifts it; every 60 s the
        // counter is snapped back to ChunkHolder::total_bytes().
        let capacity_for_reconcile = self.capacity.clone();
        let holder_for_reconcile = self.transport.chunk_holder.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
            loop {
                interval.tick().await;
                reconcile_capacity_once(&holder_for_reconcile, &capacity_for_reconcile).await;
            }
        });

        // Start reconciliation loop: proactively reconnect to peers idle
        // longer than PARTITION_THRESHOLD_SECS. The reactive path
        // (is_reconnection in handle_inbound) covers already-reconnected
        // peers; this covers peers still disconnected.
        let accounting_for_recon = self.accounting.clone();
        let transport_for_recon = self.transport.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(600));
            loop {
                interval.tick().await;
                let current_time = current_timestamp();
                let partitioned: Vec<NodeId> = {
                    let accounting = accounting_for_recon.lock().await;
                    accounting
                        .peers
                        .iter()
                        .filter(|(_, credit)| {
                            current_time.saturating_sub(credit.last_interaction)
                                > PARTITION_THRESHOLD_SECS
                        })
                        .map(|(id, _)| *id)
                        .collect()
                };
                for peer_id in partitioned {
                    if transport_for_recon.connections.read().await.contains_key(&peer_id) {
                        continue;
                    }
                    let addr_opt = {
                        transport_for_recon
                            .routing_table
                            .read()
                            .await
                            .get_node(&peer_id)
                            .map(|n| n.address.clone())
                    };
                    let addr_str = match addr_opt {
                        Some(a) => a,
                        None => continue,
                    };
                    let addr: std::net::SocketAddr = match addr_str.parse() {
                        Ok(a) => a,
                        Err(_) => continue,
                    };
                    let transport = transport_for_recon.clone();
                    tokio::spawn(async move {
                        // Success triggers reconciliation via the
                        // is_reconnection signal in handle_inbound.
                        let _ = connect_to_peer(addr, transport).await;
                    });
                }
            }
        });

        // Start rotation loop (Full nodes only: SeedOnly holds no chunks
        // locally and must stay rate-limited; BackupOnly is dormant).
        if matches!(self.config.mode, NodeMode::Full) {
            let rotation_state = self.rotation_state.clone();
            let rotation_config = self.config.rotation_config.clone();
            let chunk_holder_for_rotation = self.transport.chunk_holder.clone();
            let leases_for_rotation = self.leases.clone();
            let swaps_for_rotation = self.swaps.clone();
            let capacity_for_rotation = self.capacity.clone();
            let transport_for_rotation = self.transport.clone();
            let rotation_node_id = self.transport.node_id;
            tokio::spawn(async move {
                rotation_loop(
                    rotation_state,
                    rotation_config,
                    chunk_holder_for_rotation,
                    leases_for_rotation,
                    swaps_for_rotation,
                    capacity_for_rotation,
                    transport_for_rotation,
                    rotation_node_id,
                )
                .await;
            });
        }

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
        // Reactive partition-heal path: the transport flags the
        // handshake-echo of a previously-connected peer. Exchange
        // accounting state now; the message itself (handshake echo)
        // carries no accounting data.
        if inbound.is_reconnection {
            info!("Partition heal detected with peer {:02x?}", inbound.from);
            if let Err(e) = self.trigger_reconciliation(inbound.from).await {
                warn!("Reconciliation trigger failed for {:02x?}: {}", inbound.from, e);
            }
        }

        match inbound.message {
            WireMessage::Sphinx(packet) => {
                // Backup-only nodes are dormant and do not serve chunks.
                // TODO: Implement health-check via gossip and activation logic.
                if matches!(self.config.mode, NodeMode::BackupOnly) {
                    debug!("Backup-only node dormant: ignoring Sphinx packet");
                    return Ok(());
                }
                debug!("Received Sphinx packet (destination) from {:02x?}", inbound.from);
                
                let mut manager = self.retriever.lock().await;
                if let Ok(Some(response)) = manager.process_fragment(&packet.body) {
                    if response.found {
                        let chunk = EncryptedChunk {
                            id: response.chunk_id,
                            data: response.chunk_data,
                        };
                        let mut content_retriever = self.content_retriever.lock().await;
                        if content_retriever.record_chunk(chunk.clone()).unwrap_or(false) {
                            debug!("Successfully retrieved chunk {:02x?}", response.chunk_id);
                        }
                        drop(content_retriever);
                        // Freenet-style: cache what we retrieve so popular
                        // chunks spread and no holder set stays static.
                        self.cache_retrieved_chunk(chunk.id, &chunk.data).await;
                    }
                }
            }
            WireMessage::Prepayment(prepayment) => {
                let accepted = self.handle_prepayment(inbound.from, prepayment).await?;
                debug!("Prepayment handled (accepted={})", accepted);
            }
            WireMessage::AccountingReconciliation(recon) => {
                self.process_reconciliation(recon).await?;
            }
            _ => {}
        }
        Ok(())
    }

    /// Convert local accounting state into batched wire entries
    fn reconciliation_batches(
        peers: &HashMap<NodeId, PeerCredit>,
        total_served: u64,
        total_received: u64,
        from_node: NodeId,
        now: u64,
    ) -> Vec<AccountingReconciliation> {
        let entries: Vec<ReconciliationEntry> = peers
            .iter()
            .map(|(peer_id, credit)| ReconciliationEntry {
                peer_id: *peer_id,
                bytes_served: credit.bytes_served,
                bytes_received: credit.bytes_received,
                net_credit: credit.net_credit,
                last_interaction: credit.last_interaction,
                prepaid_bytes: credit.prepaid_bytes,
                successful_challenges: credit.successful_challenges,
                failed_challenges: credit.failed_challenges,
            })
            .collect();
        if entries.is_empty() {
            return vec![AccountingReconciliation {
                from_node,
                peer_credits: vec![],
                total_bytes_served: total_served,
                total_bytes_received: total_received,
                timestamp: now,
            }];
        }
        entries
            .chunks(MAX_RECONCILIATION_ENTRIES)
            .map(|chunk| AccountingReconciliation {
                from_node,
                peer_credits: chunk.to_vec(),
                total_bytes_served: total_served,
                total_bytes_received: total_received,
                timestamp: now,
            })
            .collect()
    }

    /// Trigger reconciliation with a reconnected peer (partition heal)
    ///
    /// Exports local state and sends it in batches of at most
    /// [`MAX_RECONCILIATION_ENTRIES`] entries. Locks are never held
    /// across `.await` pairs: accounting is cloned then dropped before
    /// touching connections.
    pub async fn trigger_reconciliation(&self, peer: NodeId) -> anyhow::Result<()> {
        let (peers, total_served, total_received) = {
            let accounting = self.accounting.lock().await;
            (
                accounting.peers.clone(),
                accounting.total_bytes_served,
                accounting.total_bytes_received,
            )
        };
        let batches = Self::reconciliation_batches(
            &peers,
            total_served,
            total_received,
            self.transport.node_id,
            current_timestamp(),
        );
        let count = batches.len();
        for batch in batches {
            static_mesh::transport::send_reconciliation(&self.transport, peer, batch).await?;
        }
        info!("Sent {} reconciliation batch(es) to {:02x?}", count, peer);
        Ok(())
    }

    /// Process an incoming reconciliation batch (last-write-wins merge)
    pub async fn process_reconciliation(
        &self,
        recon: AccountingReconciliation,
    ) -> anyhow::Result<()> {
        let incoming: Vec<(NodeId, PeerCredit)> = recon
            .peer_credits
            .iter()
            .map(|e| {
                let mut credit = PeerCredit::new();
                credit.bytes_served = e.bytes_served;
                credit.bytes_received = e.bytes_received;
                credit.net_credit = e.net_credit;
                credit.prepaid_bytes = e.prepaid_bytes;
                credit.successful_challenges = e.successful_challenges;
                credit.failed_challenges = e.failed_challenges;
                credit.last_interaction = e.last_interaction;
                (e.peer_id, credit)
            })
            .collect();
        // Totals in the message are informational (no global ledger).
        self.accounting.lock().await.reconcile(&incoming);
        info!(
            "Reconciled accounting with {:02x?} ({} entries)",
            recon.from_node,
            incoming.len()
        );
        Ok(())
    }

    /// Check whether this runner is a seed-only node
    pub fn is_seed_only(&self) -> bool {
        matches!(self.config.mode, NodeMode::SeedOnly)
    }

    /// Check whether this runner is a backup-only node
    pub fn is_backup_only(&self) -> bool {
        matches!(self.config.mode, NodeMode::BackupOnly)
    }

    /// Cache a retrieved chunk locally (Freenet-style, Full nodes only)
    ///
    /// Popular chunks spread as retrievers keep copies; the holder set
    /// never stays static. Cached bytes count toward the storage
    /// contribution via `StorageCapacity::record_accept`, and the LRU
    /// cached chunk is evicted when at the cap. Lock discipline: each
    /// guard is dropped before the next is taken.
    pub async fn cache_retrieved_chunk(&self, chunk_id: ChunkId, data: &[u8]) {
        if !matches!(self.config.mode, NodeMode::Full) {
            return;
        }
        if !self.config.rotation_config.enable_caching {
            return;
        }
        if self.transport.chunk_holder.lock().await.has_chunk(&chunk_id) {
            return;
        }

        let chunk_len = data.len() as u64;
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Fast path: capacity available.
        let fits = self.capacity.lock().await.can_accept(chunk_len, 0);
        if fits {
            self.transport.chunk_holder.lock().await.add_chunk(
                chunk_id,
                data.to_vec(),
                [0u8; 32], // cached chunks carry no content binding
            );
            self.capacity.lock().await.record_accept(chunk_len);
            self.rotation_state.lock().await.record_cache(chunk_id, current_time);
            debug!("Cached chunk {:02x?} locally", chunk_id);
            return;
        }

        // Slow path: evict the LRU cached chunk to make room.
        let max = self.config.rotation_config.max_cached_chunks;
        if max > 0 {
            let lru = self.rotation_state.lock().await.lru_cached_chunk();
            if let Some(lru_id) = lru {
                let evicted_len = {
                    self.transport
                        .chunk_holder
                        .lock()
                        .await
                        .get_chunk(&lru_id)
                        .map(|d| d.len() as u64)
                        .unwrap_or(0)
                };
                self.transport.chunk_holder.lock().await.remove_chunk(&lru_id);
                self.rotation_state.lock().await.remove_cache(&lru_id);
                self.capacity.lock().await.record_remove(evicted_len);
                debug!("Evicted cached chunk {:02x?} to make room", lru_id);

                if self.capacity.lock().await.can_accept(chunk_len, 0) {
                    self.transport.chunk_holder.lock().await.add_chunk(
                        chunk_id,
                        data.to_vec(),
                        [0u8; 32],
                    );
                    self.capacity.lock().await.record_accept(chunk_len);
                    self.rotation_state.lock().await.record_cache(chunk_id, current_time);
                    debug!("Cached chunk {:02x?} locally after eviction", chunk_id);
                }
            }
        }
    }

    /// Number of seed-only nodes currently sponsored (sponsor-side)
    pub async fn sponsor_seed_count(&self) -> usize {
        self.accounting.lock().await.sponsor_seed_count()
    }

    /// Validate and accept a prepayment from a seed-only node (sponsor-side)
    ///
    /// Checks, in order:
    /// 1. Stub signature (`!signature.is_empty()`)
    /// 2. Misbehaving flag (dropped seeds are ignored, content expires)
    /// 3. Rate limit (one prepayment per content ID per hour)
    /// 4. Excess capacity (`has_excess_capacity`)
    /// 5. Sponsor limit (max [`static_accounting::MAX_SPONSORED_SEEDS`])
    ///
    /// On success records the prepayment in accounting and registers the
    /// seed. Returns `true` if accepted, `false` if rejected.
    pub async fn handle_prepayment(
        &self,
        from: NodeId,
        prepayment: Prepayment,
    ) -> anyhow::Result<bool> {
        // Backup-only nodes never accept prepayments (dormant).
        if matches!(self.config.mode, NodeMode::BackupOnly) {
            debug!("Backup-only node ignoring prepayment");
            return Ok(false);
        }

        // 1. Stub signature check.
        // TODO: Add ed25519-dalek for real signature verification
        if !prepayment.validate() {
            warn!("Rejecting prepayment from {:02x?}: invalid signature/amount", from);
            return Ok(false);
        }

        let now = current_timestamp();
        let mut accounting = self.accounting.lock().await;

        // 2. Drop misbehaving seeds; their content is allowed to expire.
        if accounting.is_seed_misbehaving(&from) {
            warn!("Ignoring prepayment from misbehaving seed {:02x?}", from);
            return Ok(false);
        }

        // 3. Rate limit: one prepayment per content ID per hour.
        if !accounting.check_prepay_rate_limit(&from, &prepayment.content_id, now) {
            warn!(
                "Rejecting prepayment from {:02x?}: rate limit exceeded",
                from
            );
            accounting.record_seed_violation(&from);
            return Ok(false);
        }
        accounting.record_prepay_attempt(from, prepayment.content_id, now);

        // 4. Sponsor must have excess capacity (own 1:1 satisfied + surplus).
        if !accounting.has_excess_capacity(0) {
            // Fresh nodes with zero totals have 0 surplus; allow the very
            // first sponsorship as bootstrap, but require surplus afterwards.
            let fresh = accounting.total_bytes_served == 0
                && accounting.total_bytes_received == 0;
            if !(fresh && accounting.sponsor_seed_count() == 0) {
                warn!("Rejecting prepayment from {:02x?}: no excess capacity", from);
                return Ok(false);
            }
        }

        // 5. Sponsor limit (new seeds only; renewals always accepted).
        if !accounting.is_sponsored(&from) && !accounting.can_sponsor() {
            warn!(
                "Rejecting prepayment from {:02x?}: sponsor at capacity",
                from
            );
            return Ok(false);
        }

        accounting.record_prepayment(from, prepayment.bytes);
        match accounting.register_sponsored_seed(
            from,
            prepayment.content_id,
            prepayment.bytes,
            now,
        ) {
            Ok(()) => {
                info!(
                    "Accepted prepayment from {:02x?}: {} bytes for {:02x?}",
                    from, prepayment.bytes, prepayment.content_id
                );
                Ok(true)
            }
            Err(e) => {
                warn!("Rejecting prepayment from {:02x?}: {}", from, e);
                Ok(false)
            }
        }
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
    ///
    /// Full nodes store chunks locally. Seed-only nodes pre-pay a single
    /// sponsor (avoids double-spend); the sponsor stores and distributes
    /// the chunks across its existing peer relationships. The 1:1 rule
    /// becomes `stored_bytes <= local_hosted + prepaid_hosted`.
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

        // 5. Encrypt the manifest (needed to compute total prepaid size)
        let (encrypted_manifest, manifest_chunk_id) = static_storage::hidden_service::encrypt_manifest(&manifest, &content_pub_key)?;

        let total_bytes: u64 = chunks.iter().map(|c| c.data.len() as u64).sum::<u64>()
            + encrypted_manifest.ciphertext.len() as u64;

        // Seed-only path: pre-pay ONE sponsor, do not store locally.
        if matches!(self.config.mode, NodeMode::SeedOnly) {
            return self.publish_via_sponsor(
                content_id,
                manifest,
                content_pub_key,
                master_key,
                chunks,
                manifest_chunk_id,
                total_bytes,
            ).await;
        }

        // 3. Store the chunks locally (full / backup nodes)
        {
            let mut holder = self.transport.chunk_holder.lock().await;
            for chunk in &chunks {
                holder.add_chunk(chunk.id, chunk.data.clone(), content_id);
            }
        }

        // 4. Store the master key in storage_keys
        self.storage_keys.lock().await.insert(content_id, master_key.clone());

        // 6. Store the encrypted manifest as a chunk locally
        {
            let mut holder = self.transport.chunk_holder.lock().await;
            holder.add_chunk(manifest_chunk_id, encrypted_manifest.ciphertext.clone(), content_id);
        }

        // 6b. Account the stored bytes toward the 1:1 contribution.
        {
            let mut capacity = self.capacity.lock().await;
            for chunk in &chunks {
                capacity.record_accept(chunk.data.len() as u64);
            }
            capacity.record_accept(encrypted_manifest.ciphertext.len() as u64);
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

    /// Seed-only publish: pre-pay a single sponsor and hand off chunks
    ///
    /// The prepayment itself is a direct wire message (like gossip). The
    /// chunks are Sphinx-wrapped for privacy when a transport path exists;
    /// for this MVP the seed registers the lease locally and the sponsor
    /// pulls/distributes the chunks via its existing swap relationships.
    /// Minimum stake equals the total content size (1:1 from the start).
    async fn publish_via_sponsor(
        &self,
        content_id: ContentId,
        manifest: ContentManifest,
        content_pub_key: [u8; 32],
        master_key: SymmetricKey,
        chunks: Vec<EncryptedChunk>,
        manifest_chunk_id: ChunkId,
        total_bytes: u64,
    ) -> anyhow::Result<(ContentId, ContentManifest, [u8; 32])> {
        // Resolve the sponsor peer: prefer the configured --sponsor address,
        // fall back to the first known peer.
        let sponsor_id = {
            let routing = self.transport.routing_table.read().await;
            let mut found: Option<NodeId> = None;
            if let Some(want) = &self.config.sponsor {
                for node in routing.nodes.values() {
                    if node.address == *want {
                        found = Some(node.node_id);
                        break;
                    }
                }
            }
            found.or_else(|| routing.nodes.values().next().map(|n| n.node_id))
        };
        // Also check active connections as fallback.
        let sponsor_id = match sponsor_id {
            Some(id) => id,
            None => {
                let conns = self.transport.connections.read().await;
                conns.keys().next().copied().ok_or_else(|| {
                    anyhow::anyhow!("Seed-only node has no sponsor connection; configure --sponsor and connect first")
                })?
            }
        };

        // Minimum stake = total content size ensures 1:1 from the start.
        let prepayment = Prepayment {
            from_node: self.transport.node_id,
            bytes: total_bytes,
            content_id,
            // TODO: Add ed25519-dalek for real signature verification
            signature: vec![0x01u8; 64],
        };
        debug_assert!(prepayment.validate());

        static_mesh::transport::send_prepayment(&self.transport, sponsor_id, prepayment).await?;

        // Record the prepayment locally (counts toward 1:1).
        self.accounting
            .lock()
            .await
            .record_prepayment(sponsor_id, total_bytes);

        // Seed-only nodes do not store chunks locally; the sponsor holds
        // them (or distributes via swap). Keep the master key + lease so
        // heartbeats/renewals can be sent when requested (rate-limited:
        // heartbeats every 30 min, one prepayment per content per hour,
        // no full-rate cover traffic).
        self.storage_keys.lock().await.insert(content_id, master_key.clone());
        let mut chunk_ids: Vec<ChunkId> = chunks.iter().map(|c| c.id).collect();
        chunk_ids.push(manifest_chunk_id);
        self.leases.lock().await.register_owned_content(
            content_id,
            master_key,
            chunk_ids,
        );

        // NOTE: chunk bodies are Sphinx-wrapped for privacy when sent over
        // the mixnet (see fragmentation layer). The direct prepayment above
        // is maintenance traffic; chunk hand-off to the sponsor follows via
        // the sponsor's swap/distribution relationships.
        info!(
            "Seed-only publish via sponsor {:02x?}: {:02x?} ({} bytes prepaid)",
            sponsor_id, content_id, total_bytes
        );

        Ok((content_id, manifest, content_pub_key))
    }

    /// Build a forward anonymous request, preferring hybrid key agreement
    ///
    /// When `use_hybrid` is set and the forward peer's ML-KEM key is known
    /// (learned via handshake), the forward packet uses hybrid v1 key
    /// agreement. The return route stays classical so the request fits in
    /// one body; versions are per-packet, so mixing is safe. Falls back
    /// to classical v0 otherwise (mixed-version networks keep working).
    fn build_forward_request(
        chunk_id: ChunkId,
        peer: &static_mesh::routing::KnownNode,
        return_route: &Route,
        forward_route: &Route,
        use_hybrid: bool,
    ) -> anyhow::Result<static_sphinx::SphinxPacket> {
        if use_hybrid {
            if let Some(kem) = peer.kem_public_key.as_ref().filter(|k| {
                k.len() == static_sphinx::HYBRID_KEM_PUBLIC_KEY_SIZE
            }) {
                let hybrid_forward = static_sphinx::HybridRoute {
                    hops: vec![static_sphinx::HybridRouteHop {
                        node_id: peer.node_id,
                        classical_public_key: peer.public_key,
                        kem_public_key: kem.clone(),
                    }],
                    destination: peer.node_id,
                };
                return Ok(static_mesh::retrieval::create_anonymous_request_hybrid(
                    chunk_id,
                    return_route,
                    &hybrid_forward,
                )?);
            }
        }
        Ok(static_mesh::retrieval::create_anonymous_request(
            chunk_id,
            return_route,
            forward_route,
        )?)
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
        let request_packet = Self::build_forward_request(
            content_id,
            peer,
            &return_route,
            &forward_route,
            self.config.use_hybrid_crypto,
        )?;

        static_mesh::transport::send_sphinx(&self.transport, peer.node_id, request_packet).await?;

        // 2. Wait for the encrypted manifest to arrive
        let mut manager = self.retriever.lock().await;
        manager.start_retrieval(content_id);

        let timeout = tokio::time::sleep(std::time::Duration::from_secs(10));
        tokio::pin!(timeout);

        #[allow(unused_assignments)]
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
            let request_packet = Self::build_forward_request(
                *chunk_id,
                peer,
                &return_route,
                &forward_route,
                self.config.use_hybrid_crypto,
            )?;
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
    capacity: Arc<Mutex<StorageCapacity>>,
) {
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));

    loop {
        interval.tick().await;
        expire_chunks_once(&leases, &chunks, &capacity).await;
    }
}

/// Run one lease-expiration sweep: drop expired chunks, release their
/// leases, and subtract the freed bytes from capacity.
///
/// Lock order per chunk is holder → leases → capacity, each guard
/// dropped before the next is taken, so sweeps never nest guards.
async fn expire_chunks_once(
    leases: &Arc<Mutex<LeaseManager>>,
    chunks: &Arc<Mutex<ChunkHolder>>,
    capacity: &Arc<Mutex<StorageCapacity>>,
) -> usize {
    let current_time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let expired = leases.lock().await.get_expired_chunks(current_time);

    if !expired.is_empty() {
        debug!("Found {} expired chunks", expired.len());

        for chunk_id in &expired {
            let chunk_size = {
                let mut holder = chunks.lock().await;
                let size = holder.get_chunk(chunk_id).map(|d| d.len() as u64).unwrap_or(0);
                holder.remove_chunk(chunk_id);
                size
            };
            leases.lock().await.remove_lease(chunk_id);
            capacity.lock().await.record_remove(chunk_size);
        }
    }

    leases.lock().await.cleanup_nonces(current_time);

    expired.len()
}


/// Background loop to periodically check content health and trigger repairs
async fn repair_loop(
    repair_state: Arc<Mutex<RepairState>>,
    storage_keys: Arc<Mutex<HashMap<ContentId, SymmetricKey>>>,
    leases: Arc<Mutex<LeaseManager>>,
) {
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(300)); // Check every 5 minutes

    loop {
        interval.tick().await;
        
        let _storage_keys = storage_keys.lock().await;
        let _leases = leases.lock().await;
        
        // In a full implementation, we would:
        // 1. Iterate through all owned content (storage_keys)
        // 2. For each content, send health check requests to the network
        // 3. Aggregate copy counts for each chunk
        // 4. Call check_content_health() with the aggregated counts
        // 5. If health is not healthy, call create_repair_plan()
        // 6. If a plan is created, retrieve remaining shards and reconstruct
        // 7. Re-distribute the reconstructed shards to new nodes
        //
        // Capacity invariant: when step 6/7 starts storing reconstructed
        // chunks in the holder, each stored chunk MUST be paired with
        // `capacity.record_accept(len)` (shared counter) so the 1:1
        // accounting stays truthful. Nothing is stored yet, so no
        // capacity call belongs here today.
        
        // For now, just log that the repair loop is running
        debug!("Repair loop tick. Active repairs: {}", repair_state.lock().await.active_count());
    }
}

/// Reconcile the shared capacity counter with holder reality (one sweep)
///
/// Safety net for any store/remove path that misses its incremental
/// update: snapshots `ChunkHolder::total_bytes()` then writes it into
/// the counter. Guards are strictly sequential.
async fn reconcile_capacity_once(
    chunk_holder: &Arc<Mutex<ChunkHolder>>,
    capacity: &Arc<Mutex<StorageCapacity>>,
) -> u64 {
    let actual_bytes = chunk_holder.lock().await.total_bytes();
    capacity.lock().await.reconcile(actual_bytes);
    actual_bytes
}

/// Evict least-recently-used cached chunks until under the limit
///
/// Each step takes at most one lock at a time (rotation state, then
/// chunk holder, then capacity) to respect the no-nested-guards
/// discipline. Evicted bytes are subtracted from capacity so the
/// counter keeps matching the holder.
async fn evict_excess_cache(
    rotation_state: &Arc<Mutex<RotationState>>,
    chunk_holder: &Arc<Mutex<ChunkHolder>>,
    capacity: &Arc<Mutex<StorageCapacity>>,
    max_cached_chunks: usize,
) {
    if max_cached_chunks == 0 {
        return; // 0 = unlimited
    }
    loop {
        let lru: Option<ChunkId> = {
            let state = rotation_state.lock().await;
            if state.cached_chunks.len() <= max_cached_chunks {
                None
            } else {
                state.lru_cached_chunk()
            }
        };
        let lru_chunk = match lru {
            Some(id) => id,
            None => break,
        };
        let evicted_len = {
            let mut holder = chunk_holder.lock().await;
            let len = holder.get_chunk(&lru_chunk).map(|d| d.len() as u64).unwrap_or(0);
            holder.remove_chunk(&lru_chunk);
            len
        };
        rotation_state.lock().await.remove_cache(&lru_chunk);
        capacity.lock().await.record_remove(evicted_len);
        debug!("Evicted cached chunk {:02x?}", lru_chunk);
    }
}

/// Background loop to periodically rotate chunks (Freenet-style)
///
/// Every epoch a percentage of held chunks is offered to random peers
/// via the existing swap barter (`SwapProposal`), keeping the 1:1
/// hosting balance. Only chunks with healthy remaining leases rotate.
/// Snapshot-then-act throughout: state is cloned under short locks,
/// guards are dropped before any send, and rotation records are
/// written back afterwards — no two guards are ever held at once.
#[allow(clippy::too_many_arguments)]
async fn rotation_loop(
    rotation_state: Arc<Mutex<RotationState>>,
    rotation_config: RotationConfig,
    chunk_holder: Arc<Mutex<ChunkHolder>>,
    leases: Arc<Mutex<LeaseManager>>,
    swaps: Arc<Mutex<SwapState>>,
    capacity: Arc<Mutex<StorageCapacity>>,
    transport: Arc<TransportState>,
    node_id: NodeId,
) {
    // Note: tokio::interval ticks immediately on first tick; with an
    // empty holder (or fresh state) selection is empty, so the first
    // tick is a safe no-op that just stamps last_epoch.
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(
        rotation_config.epoch_duration_secs.max(1),
    ));

    loop {
        interval.tick().await;

        if !rotation_config.enabled {
            continue;
        }

        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // 1. Snapshot held chunk IDs.
        let chunk_ids: Vec<ChunkId> = {
            chunk_holder.lock().await.chunks.keys().cloned().collect()
        };

        // 2. Select this epoch's rotation set.
        let chunks_to_rotate = {
            rotation_state.lock().await.select_chunks_for_rotation(
                &chunk_ids,
                &rotation_config,
                current_time,
            )
        };

        if chunks_to_rotate.is_empty() {
            rotation_state.lock().await.last_epoch = current_time;
            debug!("No chunks to rotate this epoch");
            continue;
        }

        // 3a. Snapshot (chunk_id, data) for selected chunks.
        let held: Vec<(ChunkId, Vec<u8>)> = {
            let holder = chunk_holder.lock().await;
            chunks_to_rotate
                .iter()
                .filter_map(|id| holder.get_chunk(id).map(|data| (*id, data.clone())))
                .collect()
        };

        // 3b. Keep only chunks with healthy remaining leases.
        let eligible: Vec<(ChunkId, Vec<u8>)> = {
            let lease_mgr = leases.lock().await;
            held.into_iter()
                .filter(|(chunk_id, _)| {
                    lease_mgr
                        .leases
                        .get(chunk_id)
                        .map(|lease| {
                            lease.expires_at.saturating_sub(current_time)
                                > rotation_config.min_lease_remaining_secs
                        })
                        .unwrap_or(false)
                })
                .collect()
        };

        if eligible.is_empty() {
            rotation_state.lock().await.last_epoch = current_time;
            debug!("No lease-eligible chunks to rotate this epoch");
            continue;
        }

        // 4a. Snapshot known peers.
        let known_nodes: Vec<static_mesh::routing::KnownNode> = {
            transport.routing_table.read().await.nodes.values().cloned().collect()
        };

        if known_nodes.is_empty() {
            rotation_state.lock().await.last_epoch = current_time;
            warn!("No peers available for rotation");
            continue;
        }

        // Mark the epoch processed before sending.
        rotation_state.lock().await.last_epoch = current_time;

        // 4b. Snapshot our key and connection senders (senders are cheap to clone).
        let master_key = transport.storage_key.lock().await.clone();
        let senders = transport.connections.read().await.clone();

        // 4c. Build proposals and send; collect what actually dispatched.
        let mut dispatched: Vec<ChunkId> = Vec::new();
        for (chunk_id, data) in &eligible {
            let peer = &known_nodes[rand::random::<usize>() % known_nodes.len()];
            if peer.node_id == node_id {
                continue;
            }
            let Some(sender) = senders.get(&peer.node_id) else {
                continue;
            };

            let chunk = EncryptedChunk { id: *chunk_id, data: data.clone() };
            // Leases here are minted with our own key: rotation proposals
            // are time-validated barters, not ownership proofs (MVP).
            let proposal = static_storage::swap::create_swap_proposal(
                node_id,
                chunk,
                &master_key,
                static_storage::swap::DEFAULT_LEASE_DURATION_SECS,
            );
            swaps.lock().await.record_proposal(&proposal);
            if sender.send(WireMessage::SwapProposal(proposal)).await.is_ok() {
                debug!(
                    "Sent rotation swap proposal for chunk {:02x?} to {:02x?}",
                    chunk_id, peer.node_id
                );
                dispatched.push(*chunk_id);
            }
        }

        // 5. Record successful rotations.
        if !dispatched.is_empty() {
            let mut state = rotation_state.lock().await;
            for chunk_id in &dispatched {
                state.record_rotation(*chunk_id, current_time);
            }
        }

        // 6. Evict excess cached chunks if over limit.
        evict_excess_cache(
            &rotation_state,
            &chunk_holder,
            &capacity,
            rotation_config.max_cached_chunks,
        )
        .await;

        debug!("Rotation epoch complete. Rotated {} chunks.", dispatched.len());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_node_runner_has_rotation_state() {
        let config = NodeConfig::default();
        assert!(config.rotation_config.enabled);
        let node_id = [0x42u8; 16];
        let mix_node = MixNode::new();
        let runner = NodeRunner::new(config, node_id, mix_node);

        let state = runner.rotation_state.lock().await;
        assert_eq!(state.total_rotations, 0);
        assert_eq!(state.total_cached, 0);
        assert!(state.cached_chunks.is_empty());
        assert!(state.rotation_history.is_empty());
        let stats = state.stats();
        assert_eq!(stats.active_cached, 0);
    }

    #[tokio::test]
    async fn test_publish_updates_capacity() {
        let config = NodeConfig::default();
        let runner = NodeRunner::new(config, [0x42u8; 16], MixNode::new());

        assert_eq!(runner.capacity.lock().await.current_bytes, 0);
        let (_content_id, _manifest, _pubkey) =
            runner.publish_content(b"capacity test payload").await.unwrap();

        // Shared counter matches holder reality (chunks + manifest).
        let actual = runner.transport.chunk_holder.lock().await.total_bytes();
        assert!(actual > 0);
        assert_eq!(runner.capacity.lock().await.current_bytes, actual);
    }

    #[tokio::test]
    async fn test_lease_expiry_updates_capacity() {
        use static_storage::heartbeat::LeaseManager;

        let chunk_id = [0xABu8; 32];
        let chunk_data = vec![0xCDu8; 1024];

        let leases = Arc::new(Mutex::new(LeaseManager::new()));
        let chunks = Arc::new(Mutex::new(ChunkHolder::new()));
        let capacity = Arc::new(Mutex::new(StorageCapacity::new(10 * 1024 * 1024)));

        // Store a chunk and account it, with a long-dead lease.
        chunks.lock().await.add_chunk(chunk_id, chunk_data.clone(), [0u8; 32]);
        capacity.lock().await.record_accept(chunk_data.len() as u64);
        let now = current_timestamp();
        let dead_lease = static_storage::create_lease(
            &chunk_id,
            &SymmetricKey::random(),
            1,
            now.saturating_sub(100_000),
        );
        leases.lock().await.add_lease(chunk_id, dead_lease);

        let expired = expire_chunks_once(&leases, &chunks, &capacity).await;
        assert_eq!(expired, 1);
        assert!(chunks.lock().await.get_chunk(&chunk_id).is_none());
        assert_eq!(capacity.lock().await.current_bytes, 0);
    }
}
