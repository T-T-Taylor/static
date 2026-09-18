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
//! - Backup-only mode: dormant chunk holding with primary health
//!   monitoring and activation on heartbeat timeout

use rand::RngCore;
use crate::{NodeConfig, NodeMode, NodeStatus, BackupConfig};
use crate::compute::{build_request_packets, build_response_packets, execute_wasm, ComputeError};
use crate::payment::{BlockchainWatcher, Currency};
use static_accounting::{AccountingState, PeerCredit, current_timestamp};
use static_crypto::SymmetricKey;
use static_mesh::fragment::{deserialize_fragment, Reassembler};
use static_mesh::transport::{
    TransportState, InboundMessage, create_transport_state,
    start_listener, connect_to_peer, get_stats, gossip_loop, send_sphinx,
};
use static_mesh::wire::{
    AccountingReconciliation, Prepayment, ReconciliationEntry, WireMessage,
    MAX_RECONCILIATION_ENTRIES,
};
use static_sphinx::{MixNode, NodeId, Route, RouteHop};
use static_storage::{
    EncryptedChunk, ChunkId, ContentId, ContentManifest, SEGMENT_SIZE,
    compute::{
        ComputeRequest, ComputeResponse, PaymentConfirmation, PaymentRequest, ReturnRoute,
        MAX_COMPUTE_INPUT_SIZE, deserialize_payment_confirmation, deserialize_payment_request,
        serialize_payment_confirmation, serialize_payment_request,
    },
    integrity::{MerkleProof, MerkleRoot},
    repair::RepairState,
    heartbeat::LeaseManager,
    retrieval::{ChunkHolder, ContentRetriever},
    rotation::{RotationConfig, RotationState},
    swap::{SwapState, StorageCapacity},
    verification::{
        ReturnRoute as VerificationReturnRoute, VerificationChallenge, VerificationResponse,
        deserialize_challenge, deserialize_response, serialize_challenge, serialize_response,
    },
};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::{info, warn, error, debug};

/// Peers idle longer than this are treated as possibly partitioned (1 hour)
pub const PARTITION_THRESHOLD_SECS: u64 = 3600;

/// Extra prune grace for possibly-partitioned peers (24 hours, additive)
pub const PARTITION_GRACE_PERIOD_SECS: u64 = 86400;

/// Default inactivity threshold before pruning a peer (7 days)
pub const PRUNE_MAX_AGE_SECS: u64 = 86400 * 7;

/// State for a single backed-up content item
#[derive(Debug, Clone)]
pub struct BackupContentState {
    /// The content ID being backed up
    ///
    /// Chunks that arrive via swap carry no content binding, so those
    /// entries use the chunk ID itself as the content ID.
    pub content_id: ContentId,
    /// The primary node ID for this content (`None` until known)
    pub primary_node_id: Option<NodeId>,
    /// Whether this backup is currently active (serving)
    pub is_active: bool,
    /// Last heartbeat (inbound activity) timestamp from the primary
    pub last_heartbeat: u64,
    /// Chunk IDs for this content
    pub chunk_ids: Vec<ChunkId>,
}

/// Overall backup state for the node
#[derive(Debug, Clone, Default)]
pub struct BackupState {
    /// Content items being backed up (content_id -> state)
    pub backed_up_content: HashMap<ContentId, BackupContentState>,
    /// Whether the node has activated for any content
    pub any_active: bool,
}

/// How often the provider payment-watch loop polls the blockchain (seconds)
pub const PAYMENT_WATCH_INTERVAL_SECS: u64 = 15;

/// Maximum stored compute results before the oldest are dropped
///
/// Results are removed when polled via the local API; this cap only
/// bounds growth for results nobody polls.
pub const MAX_COMPLETED_COMPUTE_RESULTS: usize = 512;

/// How long to wait for a verification response before counting the
/// challenge as failed (10 minutes)
pub const VERIFICATION_TIMEOUT_SECS: u64 = 600;

/// A verification challenge awaiting a response (item 14)
#[derive(Debug, Clone)]
pub struct VerificationPending {
    /// The chunk being verified
    pub chunk_id: ChunkId,
    /// The segment index requested
    pub segment_index: u32,
    /// Expected blake3 hash of the segment (from the manifest)
    pub expected_hash: [u8; 32],
    /// The node that was challenged
    pub challenged_node: NodeId,
    /// When the challenge was sent (unix timestamp)
    pub sent_at: u64,
}

/// State for chunk integrity verification (item 14)
///
/// `pending` tracks in-flight challenges keyed by nonce: responses are
/// matched by nonce, and stale or unsolicited nonces are discarded.
/// `reassembler` reassembles inbound challenge/response fragments (one
/// reassembly in flight at a time; concurrent exchanges serialize on it).
#[derive(Default)]
pub struct VerificationState {
    /// Challenges in flight (nonce -> pending)
    pub pending: HashMap<[u8; 32], VerificationPending>,
    /// Reassembler for inbound verification fragments
    pub reassembler: Reassembler,
}

impl std::fmt::Debug for ComputeState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ComputeState")
            .field("active_executions", &self.active_executions.len())
            .field("cached_modules", &self.cached_modules.len())
            .field("pending_requests", &self.pending_requests.len())
            .field("payment_pending", &self.payment_pending.len())
            .field("completed_results", &self.completed_results.len())
            .field(
                "reassembler",
                &(
                    self.reassembler.received_count(),
                    self.reassembler.total_expected(),
                ),
            )
            .field("successful_executions", &self.successful_executions)
            .field("failed_executions", &self.failed_executions)
            .finish()
    }
}

/// State of a single compute execution on the provider side
#[derive(Debug, Clone)]
pub struct ComputeExecution {
    /// The request ID
    pub request_id: [u8; 32],
    /// The requesting node (accounting bookkeeping only; unverifiable
    /// through the mixnet)
    pub from_node: NodeId,
    /// The module content ID
    pub module_content_id: ContentId,
    /// The input data
    pub input_data: Vec<u8>,
    /// When the execution was accepted
    pub started_at: u64,
}

/// A compute request this node has issued and is awaiting a response for
#[derive(Debug, Clone)]
pub struct PendingComputeRequest {
    /// The request ID
    pub request_id: [u8; 32],
    /// The provider node the request was routed to
    pub provider: NodeId,
    /// The provider's payment quote (set when a `PaymentRequest` arrives)
    pub payment: Option<PaymentRequest>,
    /// When the request was submitted
    pub started_at: u64,
}

/// A paid compute request staged on the provider until payment confirms
///
/// Capacity counts staged and executing requests together, so unpaid
/// quotes cannot be used to overrun the execution budget.
#[derive(Debug, Clone)]
pub struct PendingPayment {
    /// The request ID
    pub request_id: [u8; 32],
    /// The original request, replayed once payment confirms
    pub request: ComputeRequest,
    /// The payment quote sent to the requester
    pub payment: PaymentRequest,
    /// When the payment request was sent
    pub sent_at: u64,
    /// Transaction hash claimed by the requester (verified on-chain)
    pub claimed_tx_hash: Option<String>,
}

/// Overall compute state for the node
///
/// Serves both protocol roles: `active_executions`/`cached_modules`/
/// `payment_pending` track the provider side, `pending_requests`/
/// `completed_results` track the requester side. `reassembler`
/// reassembles inbound compute fragments (one reassembly in flight at a
/// time; concurrent exchanges serialize on it).
#[derive(Default)]
pub struct ComputeState {
    /// Active executions (request_id -> execution)
    pub active_executions: HashMap<[u8; 32], ComputeExecution>,
    /// Cached WASM modules (content_id -> module bytes)
    pub cached_modules: HashMap<ContentId, Vec<u8>>,
    /// Requests we issued and are awaiting responses for
    pub pending_requests: HashMap<[u8; 32], PendingComputeRequest>,
    /// Paid requests staged until cryptocurrency payment confirms
    pub payment_pending: HashMap<[u8; 32], PendingPayment>,
    /// Completed responses available for polling via the local API
    pub completed_results: HashMap<[u8; 32], ComputeResponse>,
    /// Reassembler for inbound compute/payment fragments
    pub reassembler: Reassembler,
    /// Number of successful executions (provider)
    pub successful_executions: u64,
    /// Number of failed executions (provider)
    pub failed_executions: u64,
}

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
    /// Backup state for tracking primary health and activation
    pub backup_state: Arc<Mutex<BackupState>>,
    /// Compute state for tracking executions and payments
    pub compute_state: Arc<Mutex<ComputeState>>,
    /// Merkle proofs for published content (chunk_id -> (root, proof))
    ///
    /// Generated at publish time over the encrypted chunks (data + parity).
    /// Rotation swap proposals attach these so receivers can verify chunk
    /// integrity. Stored for the node's lifetime (bounded by published
    /// content); lease expiry does not clean them (MVP). The manifest
    /// chunk intentionally has no proof: it stays with the publisher and
    /// never rotates.
    pub merkle_proofs: Arc<Mutex<HashMap<ChunkId, (MerkleRoot, MerkleProof)>>>,
    /// Manifests of content this node published (content_id -> manifest)
    ///
    /// The challenger side of verification needs the per-segment hashes;
    /// they live in the manifest and the node has no other manifest
    /// store. Populated in `publish_content` (both full and seed-only
    /// paths); seed-only nodes keep hashes for the chunks their sponsor
    /// stores.
    pub manifests: Arc<Mutex<HashMap<ContentId, ContentManifest>>>,
    /// Chunk integrity verification state (item 14)
    pub verification_state: Arc<Mutex<VerificationState>>,
    /// Blockchain watchers for payment verification (currency byte -> watcher)
    ///
    /// Built from the accepted currencies in [`NodeConfig::compute_config`].
    /// Immutable after construction; tests may replace entries with mocks.
    pub payment_watchers: HashMap<u8, Arc<dyn BlockchainWatcher>>,
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
        let (mut transport, inbound_rx) =
            create_transport_state(node_id, mix_node, cover_config, capacity.clone());

        // Backup-only nodes start dormant: they hold chunks but do not
        // serve them until the primary fails (see backup_health_loop).
        if matches!(config.mode, NodeMode::BackupOnly) {
            transport
                .serve_enabled
                .store(false, std::sync::atomic::Ordering::Relaxed);
        }

        // Advertise compute capability in handshakes when enabled.
        if let Some(transport) = Arc::get_mut(&mut transport) {
            transport.compute_enabled = config.compute_config.enabled;
            transport.compute_capacity = config.compute_config.capacity.min(u8::MAX as u32) as u8;
        }

        // Build blockchain watchers for the currencies this provider accepts.
        let mut payment_watchers: HashMap<u8, Arc<dyn BlockchainWatcher>> = HashMap::new();
        for currency in &config.compute_config.pricing.accepted_currencies {
            payment_watchers.insert(
                currency.to_byte(),
                crate::payment::create_watcher(*currency, &config.compute_config.blockchain_config),
            );
        }

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
            backup_state: Arc::new(Mutex::new(BackupState::default())),
            compute_state: Arc::new(Mutex::new(ComputeState::default())),
            merkle_proofs: Arc::new(Mutex::new(HashMap::new())),
            manifests: Arc::new(Mutex::new(HashMap::new())),
            verification_state: Arc::new(Mutex::new(VerificationState::default())),
            payment_watchers,
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
                // Dormant backup: the listener runs and swaps are
                // accepted (chunks accumulate), but chunk serving is
                // disabled (serve_enabled=false, set in new()) until
                // the primary's heartbeat timeout fires.
                info!(
                    "Backup-only mode: dormant, monitoring primary {} (heartbeat timeout {}s)",
                    self.config.backup_config.primary_address.as_deref().unwrap_or("<unresolved>"),
                    self.config.backup_config.heartbeat_timeout_secs
                );
                let backup_state = self.backup_state.clone();
                let backup_config = self.config.backup_config.clone();
                let transport_for_backup = self.transport.clone();
                let leases_for_backup = self.leases.clone();
                tokio::spawn(async move {
                    backup_health_loop(
                        backup_state,
                        backup_config,
                        transport_for_backup,
                        leases_for_backup,
                    )
                    .await;
                });
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
        // then the monitored primary (backup-only), then bootstrap peers.
        let mut dial_addrs: Vec<String> = Vec::new();
        if matches!(self.config.mode, NodeMode::SeedOnly) {
            if let Some(sponsor) = &self.config.sponsor {
                dial_addrs.push(sponsor.clone());
            } else if self.config.bootstrap_peers.is_empty() {
                warn!("Seed-only node has no --sponsor configured; cannot publish until a sponsor is connected");
            }
        }
        if matches!(self.config.mode, NodeMode::BackupOnly) {
            match &self.config.backup_config.primary_address {
                Some(primary) => dial_addrs.push(primary.clone()),
                None => {
                    if self.config.backup_config.primary_node_id.is_none() {
                        warn!("Backup-only node has no primary configured; it will stay dormant (no liveness signal to monitor)");
                    }
                }
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
            let merkle_proofs_for_rotation = self.merkle_proofs.clone();
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
                    merkle_proofs_for_rotation,
                    rotation_node_id,
                )
                .await;
            });
        }

        // Start payment watch loop (provider side: confirms timed-out and
        // paid compute requests; no-op for free-tier-only providers).
        if self.config.compute_config.enabled {
            let runner_for_payments = self.clone();
            tokio::spawn(async move {
                payment_watch_loop(runner_for_payments).await;
            });
        }

        // Start chunk integrity verification loop (item 14). Full nodes
        // only: dormant backups do not serve, seed-only nodes hold no
        // chunks (rotation_loop precedent).
        if matches!(self.config.mode, NodeMode::Full) {
            let runner_for_verification = self.clone();
            tokio::spawn(async move {
                verification_loop(runner_for_verification).await;
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
            if let Err(e) = self.handle_inbound(inbound).await {                warn!("Error handling inbound message: {}", e);
            }
        }

        info!("Node shutting down.");
        Ok(())
    }

    /// Handle an inbound message from the transport layer
    async fn handle_inbound(self: &Arc<Self>, inbound: InboundMessage) -> anyhow::Result<()> {
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
                // Backup-only nodes are dormant and do not serve chunks
                // or compute. Dormant backups still process nothing here;
                // every other mode proceeds to retrieval/compute handling.
                if matches!(self.config.mode, NodeMode::BackupOnly) {
                    debug!("Backup-only node dormant: ignoring Sphinx packet");
                    return Ok(());
                }
                debug!("Received Sphinx packet (destination) from {:02x?}", inbound.from);

                {
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

                // Compute dispatch: reassemble compute fragments and route
                // by message type byte (requests to the provider role,
                // responses to the requester role). Non-compute bodies are
                // ignored.
                self.handle_compute_fragment(&packet.body).await;

                // Verification dispatch (item 14): reassemble verification
                // fragments and route by type byte (challenges to the
                // responder role, responses to the challenger role).
                // Dormant backups never reach this point: the gate above
                // returns early, so they neither answer nor challenge.
                self.handle_verification_fragment(&packet.body).await;
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

    /// Reassemble a compute/payment fragment and dispatch by message type
    ///
    /// Inbound Sphinx bodies that are not chunk requests arrive here.
    /// Bodies that do not parse as fragments are ignored; reassembled
    /// payloads whose type byte is not a compute/payment message are
    /// discarded (this keeps stray traffic — e.g. chunk responses — out
    /// of the compute path).
    async fn handle_compute_fragment(self: &Arc<Self>, body: &[u8]) {
        let fragment = match deserialize_fragment(body) {
            Ok(fragment) => fragment,
            Err(_) => return,
        };

        let completed = {
            let mut state = self.compute_state.lock().await;
            if !state.reassembler.add_fragment(fragment) {
                return;
            }
            if !state.reassembler.is_complete() {
                return;
            }
            match state.reassembler.reassemble() {
                Ok(payload) => Some(payload),
                Err(_) => {
                    // Corrupt reassembly: reset for the next exchange
                    state.reassembler = Reassembler::new();
                    None
                }
            }
        };

        let Some(payload) = completed else {
            return;
        };
        // One reassembly has completed; reset for the next exchange.
        self.compute_state.lock().await.reassembler = Reassembler::new();

        match payload.first().copied() {
            Some(m) if m == static_storage::compute::MSG_COMPUTE_REQUEST => {
                match static_storage::compute::deserialize_request(&payload) {
                    Ok(request) => self.handle_compute_request(request).await,
                    Err(_) => debug!("Dropping malformed compute request"),
                }
            }
            Some(m) if m == static_storage::compute::MSG_COMPUTE_RESPONSE => {
                match static_storage::compute::deserialize_response(&payload) {
                    Ok(response) => self.handle_compute_response(response).await,
                    Err(_) => debug!("Dropping malformed compute response"),
                }
            }
            Some(m) if m == static_storage::compute::MSG_PAYMENT_REQUEST => {
                match deserialize_payment_request(&payload) {
                    Ok(quote) => self.handle_payment_request(quote).await,
                    Err(_) => debug!("Dropping malformed payment request"),
                }
            }
            Some(m) if m == static_storage::compute::MSG_PAYMENT_CONFIRMATION => {
                match deserialize_payment_confirmation(&payload) {
                    Ok(confirmation) => self.handle_payment_confirmation(confirmation).await,
                    Err(_) => debug!("Dropping malformed payment confirmation"),
                }
            }
            _ => debug!("Discarding non-compute payload after reassembly"),
        }
    }

    /// Reassemble a verification fragment and dispatch by message type
    ///
    /// Inbound Sphinx bodies that are neither chunk requests nor compute
    /// arrive here. Bodies that do not parse as fragments are ignored;
    /// reassembled payloads whose type byte is not a verification message
    /// are discarded. Type `0x07` challenges are answered from the local
    /// chunk holder (responder role), type `0x08` responses are matched
    /// against pending challenges and recorded in accounting (challenger
    /// role).
    async fn handle_verification_fragment(self: &Arc<Self>, body: &[u8]) {
        let fragment = match deserialize_fragment(body) {
            Ok(fragment) => fragment,
            Err(_) => return,
        };

        let completed = {
            let mut state = self.verification_state.lock().await;
            if !state.reassembler.add_fragment(fragment) {
                return;
            }
            if !state.reassembler.is_complete() {
                return;
            }
            match state.reassembler.reassemble() {
                Ok(payload) => Some(payload),
                Err(_) => {
                    // Corrupt reassembly: reset for the next exchange
                    state.reassembler = Reassembler::new();
                    None
                }
            }
        };

        let Some(payload) = completed else {
            return;
        };
        // One reassembly has completed; reset for the next exchange.
        self.verification_state.lock().await.reassembler = Reassembler::new();

        match payload.first().copied() {
            Some(m) if m == static_storage::verification::MSG_VERIFICATION_CHALLENGE => {
                match deserialize_challenge(&payload) {
                    Ok(challenge) => self.handle_verification_challenge(challenge).await,
                    Err(_) => debug!("Dropping malformed verification challenge"),
                }
            }
            Some(m) if m == static_storage::verification::MSG_VERIFICATION_RESPONSE => {
                match deserialize_response(&payload) {
                    Ok(response) => self.handle_verification_response(response).await,
                    Err(_) => debug!("Dropping malformed verification response"),
                }
            }
            _ => debug!("Discarding non-verification payload after reassembly"),
        }
    }

    /// Answer a verification challenge from local storage (responder role)
    ///
    /// Slices the requested segment out of the held encrypted chunk and
    /// sends it back over the challenge's return route. A chunk we do not
    /// hold (or an out-of-range segment index) produces a `found: false`
    /// response so the challenger can record the failure. The last
    /// segment of a full chunk is shorter than `SEGMENT_SIZE` (the 16
    /// byte AEAD tail); slicing mirrors how publish-time hashes were
    /// computed.
    async fn handle_verification_challenge(&self, challenge: VerificationChallenge) {
        let segment_data = {
            let holder = self.transport.chunk_holder.lock().await;
            holder.get_chunk(&challenge.chunk_id).and_then(|data| {
                let start = challenge.segment_index as usize * SEGMENT_SIZE;
                if start >= data.len() {
                    return None;
                }
                let end = (start + SEGMENT_SIZE).min(data.len());
                Some(data[start..end].to_vec())
            })
        };

        let found = segment_data.is_some();
        let response = VerificationResponse {
            chunk_id: challenge.chunk_id,
            segment_index: challenge.segment_index,
            segment_data: segment_data.unwrap_or_default(),
            nonce: challenge.nonce,
            found,
        };

        match self
            .send_verification_response(&response, &challenge.return_route)
            .await
        {
            Ok(()) => debug!(
                "Answered verification challenge for chunk {:02x?} segment {} (found={})",
                challenge.chunk_id, challenge.segment_index, found
            ),
            Err(e) => warn!("Failed to send verification response: {}", e),
        }
    }

    /// Send a verification response over a challenge's return route
    async fn send_verification_response(
        &self,
        response: &VerificationResponse,
        return_route: &VerificationReturnRoute,
    ) -> anyhow::Result<()> {
        let payload = serialize_response(response)?;
        let route = return_route.to_sphinx_route();
        let packets = build_fragment_packets(&payload, &route)?;

        let first_hop = return_route
            .hops
            .first()
            .map(|h| h.node_id)
            .ok_or_else(|| anyhow::anyhow!("empty return route"))?;
        let connections = self.transport.connections.read().await;
        if let Some(sender) = connections.get(&first_hop) {
            for packet in packets {
                let _ = sender.send(WireMessage::Sphinx(packet)).await;
            }
            Ok(())
        } else {
            anyhow::bail!("no connection to return route first hop");
        }
    }

    /// Verify an inbound challenge response (challenger role)
    ///
    /// Matches the response to a pending challenge by nonce; unknown
    /// nonces (stale or unsolicited) are discarded. `found: false` and
    /// hash mismatches record a failure; segment data whose blake3 hash
    /// matches the manifest's hash records a success. Results feed the
    /// deprioritization gate in
    /// [`static_accounting::AccountingState::should_serve`].
    async fn handle_verification_response(&self, response: VerificationResponse) {
        let pending = {
            let mut state = self.verification_state.lock().await;
            state.pending.remove(&response.nonce)
        };
        let Some(pending) = pending else {
            debug!("Discarding verification response with unknown nonce");
            return;
        };

        let verified = static_storage::verification::verify_segment_response(
            &response,
            &pending.expected_hash,
        );
        if verified {
            info!(
                "Chunk {:02x?} integrity verified for peer {:02x?}",
                pending.chunk_id, pending.challenged_node
            );
            self.accounting
                .lock()
                .await
                .record_challenge_success(&pending.challenged_node);
        } else {
            warn!(
                "Chunk {:02x?} integrity check FAILED for peer {:02x?}",
                pending.chunk_id, pending.challenged_node
            );
            self.accounting
                .lock()
                .await
                .record_challenge_failure(&pending.challenged_node);
        }
    }

    /// Handle a compute request (provider role)
    ///
    /// Free-tier providers (all-zero pricing) execute immediately. Paid
    /// providers stage the request and quote a cryptocurrency payment;
    /// execution is triggered by [`run_payment_watch_tick`] once the
    /// payment confirms on-chain. Rejections get an anonymous error
    /// response over the request's return route.
    async fn handle_compute_request(self: &Arc<Self>, request: ComputeRequest) {
        if !self.transport.compute_enabled {
            debug!("Ignoring compute request (compute disabled)");
            return;
        }

        if self.config.compute_config.pricing.is_free() {
            if let Err(err) = self.accept_compute_request(&request).await {
                debug!("Rejecting compute request {:02x?}: {}", request.request_id, err);
                self.send_compute_error(&request, &err, false, None).await;
                return;
            }

            debug!("Accepted free-tier compute request {:02x?}", request.request_id);
            let runner = self.clone();
            tokio::spawn(async move {
                runner.run_compute_execution(request).await;
            });
            return;
        }

        // Paid tier: stage the request off the inbound loop and quote a
        // payment with a fresh receive address.
        let runner = self.clone();
        tokio::spawn(async move {
            runner.initiate_paid_execution(request).await;
        });
    }

    /// Gate a compute request and register it as an active execution
    ///
    /// Checks capacity, then records the execution. Duplicate request IDs
    /// are accepted idempotently (the first registration wins) so retried
    /// fragments cannot double-book an execution.
    async fn accept_compute_request(
        &self,
        request: &ComputeRequest,
    ) -> Result<(), ComputeError> {
        let mut state = self.compute_state.lock().await;

        if state.active_executions.contains_key(&request.request_id) {
            return Ok(());
        }
        if state.active_executions.len() >= usize::from(self.transport.compute_capacity) {
            return Err(ComputeError::CapacityExceeded);
        }

        state.active_executions.insert(
            request.request_id,
            ComputeExecution {
                request_id: request.request_id,
                from_node: request.from_node,
                module_content_id: request.module_content_id,
                input_data: request.input_data.clone(),
                started_at: current_timestamp(),
            },
        );
        Ok(())
    }

    /// Stage a paid compute request and send the requester a payment quote
    ///
    /// Reserves a capacity slot (staged and executing requests count
    /// together), generates a fresh receive address via the currency's
    /// [`BlockchainWatcher`], and sends a [`PaymentRequest`] over the
    /// request's return route. If the quote cannot be delivered the slot
    /// is kept for retry and reclaimed by the payment timeout.
    async fn initiate_paid_execution(self: Arc<Self>, request: ComputeRequest) {
        let watcher = match Currency::from_byte(request.currency) {
            Some(currency) if self.config.compute_config.pricing.accepts(currency) => {
                self.payment_watchers.get(&currency.to_byte()).cloned()
            }
            _ => None,
        };
        let Some(watcher) = watcher else {
            let err = ComputeError::Payment(format!(
                "unsupported payment currency byte {}",
                request.currency
            ));
            debug!("Rejecting compute request {:02x?}: {}", request.request_id, err);
            self.send_compute_error(&request, &err, false, None).await;
            return;
        };

        // Reserve the slot before the async address generation so retried
        // fragments cannot double-book; only the first reservation quotes.
        match self.reserve_payment_slot(&request).await {
            Err(err) => {
                debug!("Rejecting compute request {:02x?}: {}", request.request_id, err);
                self.send_compute_error(&request, &err, false, None).await;
                return;
            }
            Ok(false) => return, // duplicate fragment; the first quote wins
            Ok(true) => {}
        }

        let address = match watcher.generate_address().await {
            Ok(address) => address,
            Err(e) => {
                warn!(
                    "Address generation failed for compute request {:02x?}: {}",
                    request.request_id, e
                );
                self.compute_state
                    .lock()
                    .await
                    .payment_pending
                    .remove(&request.request_id);
                let err = ComputeError::Payment(e.to_string());
                self.send_compute_error(&request, &err, false, None).await;
                return;
            }
        };

        let payment = PaymentRequest {
            request_id: request.request_id,
            currency: watcher.currency(),
            amount: self.config.compute_config.pricing.amount_due(
                self.config.compute_config.max_cpu_ms,
                u64::from(self.config.compute_config.max_memory_mb),
            ),
            address,
            required_confirmations: self.config.compute_config.pricing.required_confirmations,
        };

        {
            let mut state = self.compute_state.lock().await;
            match state.payment_pending.get_mut(&request.request_id) {
                Some(entry) => {
                    entry.payment = payment.clone();
                    entry.sent_at = current_timestamp();
                }
                // The slot vanished (only the payment tick removes entries);
                // drop silently rather than resurrect it.
                None => return,
            }
        }

        if let Err(e) = self.send_payment_request(&payment, &request.return_route).await {
            warn!(
                "Failed to deliver payment quote for {:02x?}: {} (kept for timeout)",
                request.request_id, e
            );
        } else {
            info!(
                "Quoted {} {} for compute request {:02x?} (address {})",
                payment.amount,
                payment.currency.as_str(),
                request.request_id,
                payment.address
            );
        }
    }

    /// Reserve a payment slot (dedupe + capacity check with a placeholder
    /// quote). Returns `Ok(true)` for a fresh reservation, `Ok(false)` for
    /// an already-tracked request.
    async fn reserve_payment_slot(
        &self,
        request: &ComputeRequest,
    ) -> Result<bool, ComputeError> {
        let mut state = self.compute_state.lock().await;
        if state.active_executions.contains_key(&request.request_id)
            || state.payment_pending.contains_key(&request.request_id)
        {
            return Ok(false);
        }
        if state.active_executions.len() + state.payment_pending.len()
            >= usize::from(self.transport.compute_capacity)
        {
            return Err(ComputeError::CapacityExceeded);
        }
        state.payment_pending.insert(
            request.request_id,
            PendingPayment {
                request_id: request.request_id,
                request: request.clone(),
                payment: PaymentRequest {
                    request_id: request.request_id,
                    currency: Currency::Monero, // placeholder until quoted
                    amount: 0,
                    address: String::new(),
                    required_confirmations: 0,
                },
                sent_at: current_timestamp(),
                claimed_tx_hash: None,
            },
        );
        Ok(true)
    }

    /// Fetch a WASM module from cache or the network (provider role)
    async fn obtain_module(
        &self,
        request: &ComputeRequest,
    ) -> Result<Vec<u8>, ComputeError> {
        {
            let state = self.compute_state.lock().await;
            if let Some(bytes) = state.cached_modules.get(&request.module_content_id) {
                return Ok(bytes.clone());
            }
        }

        // Fetch the published module content through the normal retrieval
        // protocol (manifest chunk request + reassembly). Once fetched the
        // module is cached for future requests.
        let bytes = self
            .retrieve_content(&request.module_content_pub_key)
            .await
            .map_err(|_| ComputeError::ModuleNotFound)?;
        if bytes.is_empty() {
            return Err(ComputeError::ModuleNotFound);
        }
        Ok(bytes)
    }

    /// Execute an accepted compute request and send the response
    async fn run_compute_execution(self: Arc<Self>, request: ComputeRequest) {
        let module_bytes = match self.obtain_module(&request).await {
            Ok(bytes) => bytes,
            Err(err) => {
                self.finish_failed_execution(&request, err).await;
                return;
            }
        };

        self.compute_state
            .lock()
            .await
            .cached_modules
            .insert(request.module_content_id, module_bytes.clone());

        let compute_config = self.config.compute_config.clone();
        let input_data = request.input_data.clone();
        let exec = tokio::task::spawn_blocking(move || {
            execute_wasm(
                &module_bytes,
                &input_data,
                compute_config.max_cpu_ms,
                compute_config.max_memory_mb,
            )
        })
        .await;

        match exec {
            Ok(Ok((output_data, cpu_time_ms, memory_used))) => {
                let output_len = output_data.len();

                {
                    let mut state = self.compute_state.lock().await;
                    state.active_executions.remove(&request.request_id);
                    state.successful_executions += 1;
                }

                debug!(
                    "Compute execution {:02x?} succeeded: {} bytes output, {} ms",
                    request.request_id, output_len, cpu_time_ms
                );

                let response = ComputeResponse {
                    request_id: request.request_id,
                    output_data,
                    success: true,
                    error: None,
                    cpu_time_ms,
                    memory_used,
                    payment_required: false,
                    payment_request: vec![],
                };
                if let Err(e) = self.send_compute_response(response, &request.return_route).await {
                    warn!("Failed to send compute response: {}", e);
                }
            }
            Ok(Err(err)) => {
                self.finish_failed_execution(&request, err).await;
            }
            Err(join_err) => {
                self.finish_failed_execution(
                    &request,
                    ComputeError::ExecutionFailed(join_err.to_string()),
                )
                .await;
            }
        }
    }

    /// Deregister a failed execution and send an anonymous error response
    async fn finish_failed_execution(
        self: Arc<Self>,
        request: &ComputeRequest,
        error: ComputeError,
    ) {
        {
            let mut state = self.compute_state.lock().await;
            state.active_executions.remove(&request.request_id);
            state.failed_executions += 1;
        }
        warn!(
            "Compute execution {:02x?} failed: {}",
            request.request_id, error
        );

        let response = ComputeResponse {
            request_id: request.request_id,
            output_data: vec![],
            success: false,
            error: Some(error.to_string()),
            cpu_time_ms: 0,
            memory_used: 0,
            payment_required: false,
            payment_request: vec![],
        };
        if let Err(e) = self.send_compute_response(response, &request.return_route).await {
            warn!("Failed to send compute error response: {}", e);
        }
    }

    /// Send an error `ComputeResponse` for a request
    ///
    /// Used for pre-execution rejections. When `payment_required` is set,
    /// `quote` is embedded so the requester can still see what to pay.
    async fn send_compute_error(
        &self,
        request: &ComputeRequest,
        error: &ComputeError,
        payment_required: bool,
        quote: Option<&PaymentRequest>,
    ) {
        let response = ComputeResponse {
            request_id: request.request_id,
            output_data: vec![],
            success: false,
            error: Some(error.to_string()),
            cpu_time_ms: 0,
            memory_used: 0,
            payment_required,
            payment_request: match quote {
                Some(q) => serialize_payment_request(q).unwrap_or_default(),
                None => vec![],
            },
        };
        if let Err(e) = self.send_compute_response(response, &request.return_route).await {
            warn!("Failed to send compute rejection: {}", e);
        }
    }

    /// Send a compute response over the request's return route
    async fn send_compute_response(
        &self,
        response: ComputeResponse,
        return_route: &ReturnRoute,
    ) -> anyhow::Result<()> {
        let packets = build_response_packets(&response, return_route)
            .map_err(|e| anyhow::anyhow!("response packet build failed: {}", e))?;
        self.send_packets(packets, return_route).await
    }

    /// Send a payment quote over the request's return route
    async fn send_payment_request(
        &self,
        quote: &PaymentRequest,
        return_route: &ReturnRoute,
    ) -> anyhow::Result<()> {
        let payload = serialize_payment_request(quote)?;
        let route = return_route.to_sphinx_route();
        let packets = build_fragment_packets(&payload, &route)?;
        self.send_packets(packets, return_route).await
    }

    /// Send pre-built Sphinx packets to a return route's first hop
    async fn send_packets(
        &self,
        packets: Vec<static_sphinx::SphinxPacket>,
        return_route: &ReturnRoute,
    ) -> anyhow::Result<()> {
        let first_hop = return_route
            .hops
            .first()
            .map(|h| h.node_id)
            .ok_or_else(|| anyhow::anyhow!("empty return route"))?;

        let connections = self.transport.connections.read().await;
        if let Some(sender) = connections.get(&first_hop) {
            for packet in packets {
                let _ = sender.send(WireMessage::Sphinx(packet)).await;
            }
        } else {
            anyhow::bail!("no connection to return route first hop");
        }
        Ok(())
    }

    /// Handle a compute response (requester role)
    ///
    /// Records the result for API polling.
    async fn handle_compute_response(&self, response: ComputeResponse) {
        {
            let mut state = self.compute_state.lock().await;
            if state
                .pending_requests
                .remove(&response.request_id)
                .is_none()
            {
                debug!(
                    "Ignoring compute response for unknown request {:02x?}",
                    response.request_id
                );
                return;
            }
        }

        if response.success {
            info!(
                "Compute execution {:02x?} succeeded: {} bytes output, {} ms CPU, {} bytes memory",
                response.request_id, response.output_data.len(), response.cpu_time_ms,
                response.memory_used
            );
        } else {
            warn!(
                "Compute execution {:02x?} failed: {}",
                response.request_id,
                response.error.clone().unwrap_or_default()
            );
        }

        let mut state = self.compute_state.lock().await;
        if state.completed_results.len() >= MAX_COMPLETED_COMPUTE_RESULTS {
            state.completed_results.clear();
        }
        state.completed_results.insert(response.request_id, response);
    }

    /// Handle a payment quote from a provider (requester role)
    ///
    /// Attaches the quote to the matching pending request so the local
    /// API can surface the payment address and amount.
    async fn handle_payment_request(&self, quote: PaymentRequest) {
        let mut state = self.compute_state.lock().await;
        match state.pending_requests.get_mut(&quote.request_id) {
            Some(pending) => {
                info!(
                    "Payment quote for compute request {:02x?}: {} {} to {}",
                    quote.request_id,
                    quote.amount,
                    quote.currency.as_str(),
                    quote.address
                );
                pending.payment = Some(quote);
            }
            None => debug!(
                "Ignoring payment request for unknown compute request {:02x?}",
                quote.request_id
            ),
        }
    }

    /// Handle a payment confirmation from a requester (provider role)
    ///
    /// Records the claimed transaction hash; [`run_payment_watch_tick`]
    /// verifies the payment on-chain (the claim is only a hint).
    async fn handle_payment_confirmation(&self, confirmation: PaymentConfirmation) {
        let mut state = self.compute_state.lock().await;
        match state.payment_pending.get_mut(&confirmation.request_id) {
            Some(entry) => {
                if entry.payment.currency != confirmation.currency {
                    debug!(
                        "Payment confirmation currency mismatch for compute request {:02x?}",
                        confirmation.request_id
                    );
                    return;
                }
                debug!(
                    "Payment claimed for compute request {:02x?} (tx {})",
                    confirmation.request_id, confirmation.tx_hash
                );
                entry.claimed_tx_hash = Some(confirmation.tx_hash);
            }
            None => debug!(
                "Ignoring payment confirmation for unknown compute request {:02x?}",
                confirmation.request_id
            ),
        }
    }

    /// Submit a compute request to the most capable compute peer
    ///
    /// `currency` selects the cryptocurrency the requester intends to pay
    /// in (ignored by free-tier providers). Returns the request ID used to
    /// poll for the quote via [`NodeRunner::pending_payment`] and for the
    /// result via [`NodeRunner::compute_result`].
    pub async fn submit_compute_request(
        &self,
        module_content_pub_key: &[u8; 32],
        input_data: Vec<u8>,
        currency: Currency,
    ) -> anyhow::Result<[u8; 32]> {
        if input_data.len() > MAX_COMPUTE_INPUT_SIZE {
            anyhow::bail!(
                "input too large: {} bytes (max {})",
                input_data.len(),
                MAX_COMPUTE_INPUT_SIZE
            );
        }

        let routing_table = self.transport.routing_table.read().await;
        let peer = routing_table
            .nodes
            .values()
            .filter(|n| n.compute_enabled)
            .max_by_key(|n| n.compute_capacity)
            .cloned();
        drop(routing_table);
        let Some(peer) = peer else {
            anyhow::bail!("No compute-capable peers available");
        };

        let module_content_id =
            static_storage::hidden_service::content_id_from_public(module_content_pub_key);

        let mut request_id = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut request_id);

        let our_pubkey = self.transport.mix_node.lock().await.public_key;
        let our_node_id = self.transport.node_id;
        let return_route = ReturnRoute::from_sphinx_route(&Route {
            hops: vec![RouteHop {
                public_key: our_pubkey,
                node_id: our_node_id,
            }],
            destination: our_node_id,
        });

        let request = ComputeRequest {
            from_node: our_node_id,
            module_content_id,
            module_content_pub_key: *module_content_pub_key,
            currency: currency.to_byte(),
            payment_address: vec![], // the provider quotes a fresh address
            request_id,
            return_route,
            input_data,
        };

        let forward_route = Route {
            hops: vec![RouteHop {
                public_key: peer.public_key,
                node_id: peer.node_id,
            }],
            destination: peer.node_id,
        };
        let packets = build_request_packets(&request, &forward_route)?;

        self.compute_state.lock().await.pending_requests.insert(
            request_id,
            PendingComputeRequest {
                request_id,
                provider: peer.node_id,
                payment: None,
                started_at: current_timestamp(),
            },
        );

        // Each fragment travels as its own Sphinx packet, indistinguishable
        // from cover traffic.
        for packet in packets {
            send_sphinx(&self.transport, peer.node_id, packet).await?;
        }

        debug!(
            "Submitted compute request {:02x?} to {:02x?}",
            request_id, peer.node_id
        );
        Ok(request_id)
    }

    /// Poll the payment quote for a submitted compute request
    ///
    /// Returns `None` until the provider's `PaymentRequest` arrives.
    pub async fn pending_payment(&self, request_id: &[u8; 32]) -> Option<PaymentRequest> {
        self.compute_state
            .lock()
            .await
            .pending_requests
            .get(request_id)
            .and_then(|pending| pending.payment.clone())
    }

    /// Send a payment confirmation to the compute provider (requester role)
    ///
    /// Called from the local API after the user has sent the on-chain
    /// payment from their own wallet. The confirmation travels as a fresh
    /// 1-hop Sphinx message to the provider node the request was routed
    /// to (same MVP pattern as chunk retrieval).
    pub async fn confirm_compute_payment(
        &self,
        request_id: &[u8; 32],
        tx_hash: String,
    ) -> anyhow::Result<()> {
        let (provider, currency) = {
            let state = self.compute_state.lock().await;
            let pending = state
                .pending_requests
                .get(request_id)
                .ok_or_else(|| anyhow::anyhow!("unknown compute request"))?;
            let quote = pending
                .payment
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("no payment quote received yet"))?;
            (pending.provider, quote.currency)
        };

        let confirmation = PaymentConfirmation {
            request_id: *request_id,
            tx_hash,
            currency,
        };
        let payload = serialize_payment_confirmation(&confirmation)?;
        let forward_route = Route {
            hops: vec![RouteHop {
                public_key: self.provider_mix_key(provider).await,
                node_id: provider,
            }],
            destination: provider,
        };
        let packets = build_fragment_packets(&payload, &forward_route)?;
        for packet in packets {
            send_sphinx(&self.transport, provider, packet).await?;
        }

        info!("Sent payment confirmation for compute request {:02x?}", request_id);
        Ok(())
    }

    /// Look up a peer's mix public key from the routing table
    async fn provider_mix_key(&self, provider: NodeId) -> [u8; 32] {
        let routing_table = self.transport.routing_table.read().await;
        routing_table
            .nodes
            .values()
            .find(|n| n.node_id == provider)
            .map(|n| n.public_key)
            .unwrap_or([0u8; 32])
    }

    /// Poll a submitted compute request for its completed result
    ///
    /// Returns `None` while the response has not arrived.
    pub async fn compute_result(&self, request_id: &[u8; 32]) -> Option<ComputeResponse> {
        self.compute_state
            .lock()
            .await
            .completed_results
            .get(request_id)
            .cloned()
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

    /// Register content to be backed up by this node
    ///
    /// Programmatic registration for content whose chunks are (or will
    /// be) held locally. Chunks that arrive via swap are auto-registered
    /// by the health loop as per-chunk entries (swaps carry no content
    /// binding); this method is for callers that know the real content
    /// identity and the primary's node ID.
    pub async fn register_backup_content(
        &self,
        content_id: ContentId,
        primary_node_id: NodeId,
        chunk_ids: Vec<ChunkId>,
    ) {
        let now = current_timestamp();
        let mut state = self.backup_state.lock().await;
        state.backed_up_content.insert(
            content_id,
            BackupContentState {
                content_id,
                primary_node_id: Some(primary_node_id),
                is_active: false,
                last_heartbeat: now,
                chunk_ids,
            },
        );
        info!(
            "Registered backup for content {:02x?} (primary: {:02x?})",
            content_id, primary_node_id
        );
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

        // Compute per-segment hashes (item 14) so any manifest holder can
        // challenge storage nodes to prove possession. Hashes ride inside
        // the encrypted manifest: only nodes with the content public key
        // can challenge. Registered before the mode split so seed-only
        // publishers keep hashes for the chunks their sponsor stores.
        manifest.segment_hashes =
            static_storage::verification::compute_segment_hashes(&chunks);
        self.manifests.lock().await.insert(content_id, manifest.clone());

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

        // Generate Merkle integrity proofs over the encrypted chunks (data
        // + parity). Rotation swap proposals attach these so receivers can
        // verify chunks are real shards of this content. The manifest
        // chunk is intentionally left unproven: it stays with the
        // publisher and never rotates.
        let (content_root, chunk_proofs) = static_storage::integrity::generate_proofs(&chunks);
        {
            let mut proofs = self.merkle_proofs.lock().await;
            for (chunk, proof) in chunks.iter().zip(chunk_proofs) {
                proofs.insert(chunk.id, (content_root, proof));
            }
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

/// Fragment a payload into Sphinx packets for the given route
fn build_fragment_packets(
    payload: &[u8],
    route: &static_sphinx::Route,
) -> Result<Vec<static_sphinx::SphinxPacket>, ComputeError> {
    let mut packets = Vec::new();
    for fragment in static_mesh::fragment::fragment_payload(payload) {
        let body = static_mesh::fragment::serialize_fragment(&fragment);
        let packet = static_sphinx::create_packet(route, &body)
            .map_err(|_| ComputeError::SphinxError)?;
        packets.push(packet);
    }
    Ok(packets)
}

/// Background loop polling the blockchain for pending compute payments
async fn payment_watch_loop(runner: Arc<NodeRunner>) {
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(
        PAYMENT_WATCH_INTERVAL_SECS.max(1),
    ));
    loop {
        interval.tick().await;
        run_payment_watch_tick(&runner).await;
    }
}

/// Run one payment-watch sweep (provider side)
///
/// 1. Times out staged requests past `payment_timeout_secs`, sending a
///    courtesy error response that carries the original quote.
/// 2. Asks each staged request's blockchain watcher for confirmations; a
///    fully confirmed payment moves the staged request into execution.
///
/// No two guards are ever held at once: state snapshots are cloned under
/// short locks and watchers are awaited guard-free.
pub(crate) async fn run_payment_watch_tick(runner: &Arc<NodeRunner>) {
    let now = current_timestamp();
    let timeout_secs = runner
        .config
        .compute_config
        .blockchain_config
        .payment_timeout_secs;

    // 1. Timeout sweep
    let expired: Vec<[u8; 32]> = {
        let state = runner.compute_state.lock().await;
        state
            .payment_pending
            .iter()
            .filter(|(_, entry)| now.saturating_sub(entry.sent_at) > timeout_secs)
            .map(|(id, _)| *id)
            .collect()
    };
    for request_id in expired {
        let entry = runner
            .compute_state
            .lock()
            .await
            .payment_pending
            .remove(&request_id);
        if let Some(entry) = entry {
            warn!("Compute request {:02x?} payment timed out", request_id);
            let err = ComputeError::Payment("payment timeout".to_string());
            runner
                .send_compute_error(&entry.request, &err, true, Some(&entry.payment))
                .await;
        }
    }

    // 2. Confirmation sweep
    let staged: Vec<PendingPayment> = {
        let state = runner.compute_state.lock().await;
        state.payment_pending.values().cloned().collect()
    };
    for entry in staged {
        let Some(watcher) = runner.payment_watchers.get(&entry.payment.currency.to_byte())
        else {
            continue;
        };
        let confirmations = watcher
            .check_payment(
                &entry.payment.address,
                entry.payment.amount,
                entry.claimed_tx_hash.as_deref(),
            )
            .await;

        match confirmations {
            Ok(Some(confirmations))
                if confirmations >= entry.payment.required_confirmations =>
            {
                let staged = runner
                    .compute_state
                    .lock()
                    .await
                    .payment_pending
                    .remove(&entry.request_id);
                let Some(staged) = staged else { continue };

                // Re-check capacity before moving into execution; if the
                // node filled up while payment was in flight, the request
                // goes back to staged and the next tick retries.
                {
                    let mut state = runner.compute_state.lock().await;
                    if state.active_executions.len()
                        >= usize::from(runner.transport.compute_capacity)
                    {
                        state.payment_pending.insert(staged.request_id, staged);
                        continue;
                    }
                    state.active_executions.insert(
                        staged.request_id,
                        ComputeExecution {
                            request_id: staged.request_id,
                            from_node: staged.request.from_node,
                            module_content_id: staged.request.module_content_id,
                            input_data: staged.request.input_data.clone(),
                            started_at: current_timestamp(),
                        },
                    );
                }

                info!(
                    "Payment for compute request {:02x?} confirmed ({} confirmations); executing",
                    staged.request_id, confirmations
                );
                let runner_clone = runner.clone();
                tokio::spawn(async move {
                    runner_clone.run_compute_execution(staged.request).await;
                });
            }
            Ok(_) => {}
            Err(e) => debug!(
                "Payment check for compute request {:02x?} failed: {}",
                entry.request_id, e
            ),
        }
    }
}

/// Background loop periodically challenging peers to prove chunk possession
///
/// Full nodes only (dormant backups do not serve, seed-only nodes hold
/// no chunks). Independent task: never touches cover traffic state.
async fn verification_loop(runner: Arc<NodeRunner>) {
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(
        runner.config.verification_interval_secs.max(1),
    ));
    loop {
        interval.tick().await;
        if !runner.config.verification_enabled {
            continue;
        }
        run_verification_tick(&runner).await;
    }
}

/// Run one verification sweep (challenger role)
///
/// 1. Expires pending challenges older than
///    [`VERIFICATION_TIMEOUT_SECS`]. No answer counts as a failure —
///    non-response is the freeloader signature — and the >10-challenge
///    gate in `should_serve` damps network-glitch false positives.
/// 2. Issues at most one new challenge per tick against a swap-accepted
///    claim: `SwapState::active_swaps` (chunk -> partner who accepted
///    storing it) is the only evidence that a peer claims a chunk, so
///    peers without such evidence are never challenged (no punishment
///    for chunks they never agreed to hold). The chunk must appear in a
///    manifest we hold, so we know the expected segment hash.
///
/// Lock discipline: state snapshots are taken under short locks, no two
/// guards are ever held at once.
async fn run_verification_tick(runner: &Arc<NodeRunner>) {
    let now = current_timestamp();

    // 1. Timeout sweep: unanswered challenges are failures.
    let expired: Vec<VerificationPending> = {
        let mut state = runner.verification_state.lock().await;
        let due: Vec<[u8; 32]> = state
            .pending
            .iter()
            .filter(|(_, pending)| now.saturating_sub(pending.sent_at) > VERIFICATION_TIMEOUT_SECS)
            .map(|(nonce, _)| *nonce)
            .collect();
        due.into_iter()
            .filter_map(|nonce| state.pending.remove(&nonce))
            .collect()
    };
    for pending in &expired {
        warn!(
            "Verification challenge for chunk {:02x?} timed out (peer {:02x?})",
            pending.chunk_id, pending.challenged_node
        );
        runner
            .accounting
            .lock()
            .await
            .record_challenge_failure(&pending.challenged_node);
    }

    // 2. Issue at most one new challenge per tick.
    let (claims, connected): (Vec<(ChunkId, NodeId)>, HashSet<NodeId>) = {
        let swaps = runner.swaps.lock().await;
        let conns = runner.transport.connections.read().await;
        (
            swaps.active_swaps.iter().map(|(c, p)| (*c, *p)).collect(),
            conns.keys().copied().collect(),
        )
    };
    let known_chunks: HashSet<ChunkId> = {
        let manifests = runner.manifests.lock().await;
        manifests
            .values()
            .flat_map(|m| m.chunk_ids.iter().copied())
            .collect()
    };

    let candidates: Vec<(ChunkId, NodeId)> = claims
        .into_iter()
        .filter(|(_, partner)| {
            connected.contains(partner) && *partner != runner.transport.node_id
        })
        .filter(|(chunk_id, _)| known_chunks.contains(chunk_id))
        .collect();
    if candidates.is_empty() {
        return;
    }

    let (chunk_id, partner) = candidates[rand::random::<usize>() % candidates.len()];

    // Segment hashes for the challenged chunk come from a manifest we hold.
    let segment_hashes = {
        let manifests = runner.manifests.lock().await;
        manifests.values().find_map(|manifest| {
            manifest
                .chunk_ids
                .iter()
                .position(|id| id == &chunk_id)
                .and_then(|index| manifest.segment_hashes.get(index))
                .cloned()
        })
    };
    let Some(segment_hashes) = segment_hashes.filter(|h| !h.is_empty()) else {
        return;
    };

    let segment_index = rand::random::<usize>() % segment_hashes.len();
    let expected_hash = segment_hashes[segment_index];
    let mut nonce = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut nonce);

    // Return route back to us (1-hop, same MVP pattern as retrieval).
    let our_pubkey = runner.transport.mix_node.lock().await.public_key;
    let our_node_id = runner.transport.node_id;
    let return_route = VerificationReturnRoute {
        hops: vec![static_storage::verification::RouteHopInfo {
            public_key: our_pubkey,
            node_id: our_node_id,
        }],
        destination: our_node_id,
    };

    let challenge = VerificationChallenge {
        chunk_id,
        segment_index: segment_index as u32,
        nonce,
        return_route,
    };

    // Record pending BEFORE sending so a fast response cannot race the
    // registration; removed again if delivery fails.
    runner.verification_state.lock().await.pending.insert(
        nonce,
        VerificationPending {
            chunk_id,
            segment_index: segment_index as u32,
            expected_hash,
            challenged_node: partner,
            sent_at: now,
        },
    );

    // Wrap the challenge in Sphinx toward the peer (1-hop forward route,
    // fragmented like compute submissions).
    let peer_pubkey = {
        let routing = runner.transport.routing_table.read().await;
        routing
            .nodes
            .values()
            .find(|n| n.node_id == partner)
            .map(|n| n.public_key)
    };
    let Some(peer_pubkey) = peer_pubkey else {
        runner.verification_state.lock().await.pending.remove(&nonce);
        return;
    };
    let forward_route = Route {
        hops: vec![RouteHop {
            public_key: peer_pubkey,
            node_id: partner,
        }],
        destination: partner,
    };

    let payload = match serialize_challenge(&challenge) {
        Ok(payload) => payload,
        Err(e) => {
            warn!("Failed to serialize verification challenge: {}", e);
            runner.verification_state.lock().await.pending.remove(&nonce);
            return;
        }
    };
    let packets = match build_fragment_packets(&payload, &forward_route) {
        Ok(packets) => packets,
        Err(e) => {
            warn!("Failed to build verification challenge packets: {}", e);
            runner.verification_state.lock().await.pending.remove(&nonce);
            return;
        }
    };

    let mut sent = true;
    for packet in packets {
        if send_sphinx(&runner.transport, partner, packet).await.is_err() {
            sent = false;
            break;
        }
    }
    if sent {
        debug!(
            "Challenged peer {:02x?} for chunk {:02x?} segment {}",
            partner, chunk_id, segment_index
        );
    } else {
        runner.verification_state.lock().await.pending.remove(&nonce);
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
    merkle_proofs: Arc<Mutex<HashMap<ChunkId, (MerkleRoot, MerkleProof)>>>,
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
            // Chunks without a stored proof (cached chunks, manifest
            // chunks) can never pass receiver validation, so they are
            // skipped rather than sent to certain rejection.
            let Some((content_root, merkle_proof)) =
                merkle_proofs.lock().await.get(chunk_id).cloned()
            else {
                debug!(
                    "Skipping rotation of chunk {:02x?}: no Merkle proof",
                    chunk_id
                );
                continue;
            };
            // Leases here are minted with our own key: rotation proposals
            // are time-validated barters, not ownership proofs (MVP).
            let proposal = static_storage::swap::create_swap_proposal(
                node_id,
                chunk,
                &master_key,
                static_storage::swap::DEFAULT_LEASE_DURATION_SECS,
                content_root,
                merkle_proof,
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

/// Background loop monitoring the primary's health (backup-only nodes)
///
/// Ticks once a minute and runs one [`run_backup_health_tick`] sweep.
async fn backup_health_loop(
    backup_state: Arc<Mutex<BackupState>>,
    backup_config: BackupConfig,
    transport: Arc<TransportState>,
    leases: Arc<Mutex<LeaseManager>>,
) {
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));

    loop {
        interval.tick().await;
        let now = current_timestamp();
        if let Err(e) =
            run_backup_health_tick(&backup_state, &backup_config, &transport, &leases, now).await
        {
            warn!("Backup health tick failed: {}", e);
        }
    }
}

/// Run one backup health-check sweep
///
/// Lock discipline is strictly sequential — routing table read,
/// activity snapshot, chunk holder snapshot, backup state, then
/// leases — and no two guards are ever held at once. The sweep:
///
/// 1. Resolves the primary node ID (config, else routing-table lookup
///    by the configured address).
/// 2. Auto-registers any held chunks not yet tracked (swap-delivered
///    chunks carry no content binding, so each becomes its own entry).
/// 3. Refreshes `last_heartbeat` from the transport's peer-activity
///    map: any inbound message from the primary is the heartbeat.
/// 4. Activates entries whose primary has been silent past the
///    heartbeat timeout and flips the transport's `serve_enabled`
///    flag on the first activation. Entries with no known primary
///    never activate (no liveness signal to monitor).
/// 5. Extends the leases of held chunks: dormant entries with a
///    healthy primary (so the expiration loop cannot destroy the
///    backup before the primary fails), and activated entries per the
///    `permanent_takeover` policy — extended every tick when true,
///    once at activation when false (leases then lapse naturally).
///
/// Returns the number of entries activated by this sweep.
async fn run_backup_health_tick(
    backup_state: &Arc<Mutex<BackupState>>,
    backup_config: &BackupConfig,
    transport: &Arc<TransportState>,
    leases: &Arc<Mutex<LeaseManager>>,
    now: u64,
) -> anyhow::Result<usize> {
    // 1. Resolve the primary.
    let resolved_primary: Option<NodeId> = match backup_config.primary_node_id {
        Some(id) => Some(id),
        None => match &backup_config.primary_address {
            Some(addr) => transport
                .routing_table
                .read()
                .await
                .nodes
                .values()
                .find(|n| &n.address == addr)
                .map(|n| n.node_id),
            None => None,
        },
    };

    // 2/3/4. Snapshot holder and activity, then mutate backup state.
    let activity = transport.peer_activity_snapshot();
    let held_chunk_ids: Vec<ChunkId> = {
        transport
            .chunk_holder
            .lock()
            .await
            .chunks
            .keys()
            .cloned()
            .collect()
    };

    let mut newly_activated: Vec<ContentId> = Vec::new();
    let mut extend_lease_ids: Vec<ChunkId> = Vec::new();
    let mut activated_any = false;

    {
        let mut state = backup_state.lock().await;

        for chunk_id in held_chunk_ids {
            if !state.backed_up_content.contains_key(&chunk_id) {
                debug!("Auto-registered backup entry for chunk {:02x?}", chunk_id);
                state.backed_up_content.insert(
                    chunk_id,
                    BackupContentState {
                        content_id: chunk_id,
                        primary_node_id: None,
                        is_active: false,
                        last_heartbeat: now,
                        chunk_ids: vec![chunk_id],
                    },
                );
            }
        }

        for (content_id, entry) in state.backed_up_content.iter_mut() {
            // Fill in the primary once it is known.
            if entry.primary_node_id.is_none() {
                entry.primary_node_id = resolved_primary;
            }

            // Heartbeat refresh: recent inbound activity from the
            // primary counts as a heartbeat.
            if let Some(primary) = entry.primary_node_id {
                if let Some(&last_seen) = activity.get(&primary) {
                    if last_seen > entry.last_heartbeat {
                        entry.last_heartbeat = last_seen;
                    }
                }
            }

            if entry.is_active {
                // Activated entries stay active (failover is permanent
                // for MVP). Keep their leases alive only under the
                // permanent-takeover policy.
                if backup_config.permanent_takeover {
                    extend_lease_ids.extend(entry.chunk_ids.iter().copied());
                }
                continue;
            }

            if entry.primary_node_id.is_none() {
                debug!(
                    "Backup entry {:02x?} has no known primary yet; waiting",
                    content_id
                );
                continue;
            }

            let healthy =
                now.saturating_sub(entry.last_heartbeat) <= backup_config.heartbeat_timeout_secs;
            if healthy {
                // Dormant + healthy: keep our copies' leases alive so
                // the lease expiration loop cannot destroy the backup
                // before the primary ever fails.
                extend_lease_ids.extend(entry.chunk_ids.iter().copied());
                continue;
            }

            // Primary silent past the timeout: activate. Leases are
            // extended now under both policies; with permanent takeover
            // they keep being extended every tick afterwards, without
            // it they lapse naturally (de facto deactivation).
            let silent_for = now.saturating_sub(entry.last_heartbeat);
            entry.is_active = true;
            newly_activated.push(*content_id);
            extend_lease_ids.extend(entry.chunk_ids.iter().copied());
            info!(
                "Primary for content {:02x?} silent for {}s (timeout {}s). Activating backup.",
                content_id, silent_for, backup_config.heartbeat_timeout_secs
            );
        }

        if !newly_activated.is_empty() {
            state.any_active = true;
            activated_any = true;
        }
    }

    // 4b. Flip the serving flag on first activation (backup state
    // guard is dropped).
    if activated_any {
        transport
            .serve_enabled
            .store(true, std::sync::atomic::Ordering::Relaxed);
        info!("Backup node activated. Now serving chunks.");
    }

    // 5. Lease extension (sequential: no other guard is held).
    if !extend_lease_ids.is_empty() {
        let mut lease_mgr = leases.lock().await;
        let new_expiry = now + static_storage::swap::DEFAULT_LEASE_DURATION_SECS;
        for chunk_id in &extend_lease_ids {
            if let Some(lease) = lease_mgr.leases.get_mut(chunk_id) {
                if lease.expires_at < new_expiry {
                    lease.expires_at = new_expiry;
                }
            }
        }
    }

    Ok(newly_activated.len())
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

    #[tokio::test]
    async fn test_backup_state_creation() {
        let state = BackupState::default();
        assert!(state.backed_up_content.is_empty());
        assert!(!state.any_active);
    }

    #[tokio::test]
    async fn test_backup_content_registration() {
        let runner = NodeRunner::new(NodeConfig::default(), [0x42u8; 16], MixNode::new());

        let content_id = [0x11u8; 32];
        let primary = [0x22u8; 16];
        let chunk_ids = vec![[0x33u8; 32], [0x34u8; 32]];
        runner
            .register_backup_content(content_id, primary, chunk_ids.clone())
            .await;

        let state = runner.backup_state.lock().await;
        assert_eq!(state.backed_up_content.len(), 1);
        let entry = state.backed_up_content.get(&content_id).unwrap();
        assert_eq!(entry.content_id, content_id);
        assert_eq!(entry.primary_node_id, Some(primary));
        assert!(!entry.is_active);
        assert_eq!(entry.chunk_ids, chunk_ids);
    }

    #[tokio::test]
    async fn test_backup_activation_on_timeout() {
        let mut config = NodeConfig::default();
        config.mode = NodeMode::BackupOnly;
        config.backup_config.heartbeat_timeout_secs = 5400;
        let runner = NodeRunner::new(config, [0x42u8; 16], MixNode::new());

        // Backup nodes start dormant.
        assert!(
            !runner
                .transport
                .serve_enabled
                .load(std::sync::atomic::Ordering::Relaxed)
        );

        let content_id = [0x11u8; 32];
        let primary = [0x22u8; 16];
        runner
            .register_backup_content(content_id, primary, vec![[0x33u8; 32]])
            .await;

        // Primary silent for 2 hours (past the 90-minute timeout).
        let now = current_timestamp();
        {
            let mut state = runner.backup_state.lock().await;
            state
                .backed_up_content
                .get_mut(&content_id)
                .unwrap()
                .last_heartbeat = now.saturating_sub(7200);
        }

        let activated = run_backup_health_tick(
            &runner.backup_state,
            &runner.config.backup_config,
            &runner.transport,
            &runner.leases,
            now,
        )
        .await
        .unwrap();
        assert_eq!(activated, 1);

        let state = runner.backup_state.lock().await;
        assert!(state.backed_up_content.get(&content_id).unwrap().is_active);
        assert!(state.any_active);
        drop(state);
        assert!(
            runner
                .transport
                .serve_enabled
                .load(std::sync::atomic::Ordering::Relaxed)
        );
    }

    #[tokio::test]
    async fn test_backup_no_activation_when_healthy() {
        let mut config = NodeConfig::default();
        config.mode = NodeMode::BackupOnly;
        let runner = NodeRunner::new(config, [0x42u8; 16], MixNode::new());

        let content_id = [0x11u8; 32];
        let primary = [0x22u8; 16];
        runner
            .register_backup_content(content_id, primary, vec![[0x33u8; 32]])
            .await;

        // Fresh registration: heartbeat is current, primary healthy.
        let now = current_timestamp();
        let activated = run_backup_health_tick(
            &runner.backup_state,
            &runner.config.backup_config,
            &runner.transport,
            &runner.leases,
            now,
        )
        .await
        .unwrap();
        assert_eq!(activated, 0);

        let state = runner.backup_state.lock().await;
        assert!(!state.backed_up_content.get(&content_id).unwrap().is_active);
        assert!(!state.any_active);
        drop(state);
        assert!(
            !runner
                .transport
                .serve_enabled
                .load(std::sync::atomic::Ordering::Relaxed)
        );
    }

    #[tokio::test]
    async fn test_serve_enabled_flag() {
        // Full nodes serve from the start.
        let full = NodeRunner::new(NodeConfig::default(), [0x42u8; 16], MixNode::new());
        assert!(
            full.transport
                .serve_enabled
                .load(std::sync::atomic::Ordering::Relaxed)
        );

        // Backup nodes start dormant and flip on activation.
        let mut config = NodeConfig::default();
        config.mode = NodeMode::BackupOnly;
        let backup = NodeRunner::new(config, [0x42u8; 16], MixNode::new());
        assert!(
            !backup
                .transport
                .serve_enabled
                .load(std::sync::atomic::Ordering::Relaxed)
        );

        backup
            .register_backup_content([0x11u8; 32], [0x22u8; 16], vec![[0x33u8; 32]])
            .await;
        let now = current_timestamp();
        {
            let mut state = backup.backup_state.lock().await;
            state
                .backed_up_content
                .get_mut(&[0x11u8; 32])
                .unwrap()
                .last_heartbeat = now.saturating_sub(7200);
        }
        run_backup_health_tick(
            &backup.backup_state,
            &backup.config.backup_config,
            &backup.transport,
            &backup.leases,
            now,
        )
        .await
        .unwrap();
        assert!(
            backup
                .transport
                .serve_enabled
                .load(std::sync::atomic::Ordering::Relaxed)
        );
    }

    fn test_compute_request(request_id: [u8; 32]) -> ComputeRequest {
        ComputeRequest {
            from_node: [0x11u8; 16],
            module_content_id: [0x22u8; 32],
            module_content_pub_key: [0x33u8; 32],
            currency: crate::payment::Currency::Monero.to_byte(),
            payment_address: vec![], // empty in initial requests
            request_id,
            return_route: ReturnRoute {
                hops: vec![],
                destination: [0x44u8; 16],
            },
            input_data: b"compute input".to_vec(),
        }
    }

    /// Mock blockchain watcher: returns a fixed address and a settable
    /// confirmation count.
    struct MockWatcher {
        confirmations: std::sync::Mutex<Option<u32>>,
    }

    #[async_trait::async_trait]
    impl BlockchainWatcher for MockWatcher {
        async fn generate_address(&self) -> Result<String, crate::payment::PaymentError> {
            Ok("mock-address-0123456789".to_string())
        }

        async fn check_payment(
            &self,
            _address: &str,
            expected_amount: u64,
            _tx_hash: Option<&str>,
        ) -> Result<Option<u32>, crate::payment::PaymentError> {
            // The watch tick must verify the quoted amount.
            assert_eq!(expected_amount, 100);
            Ok(*self.confirmations.lock().unwrap())
        }

        fn currency(&self) -> crate::payment::Currency {
            crate::payment::Currency::Monero
        }
    }

    #[tokio::test]
    async fn test_compute_state_creation() {
        let state = ComputeState::default();
        assert!(state.active_executions.is_empty());
        assert!(state.cached_modules.is_empty());
        assert!(state.pending_requests.is_empty());
        assert!(state.payment_pending.is_empty());
        assert!(state.completed_results.is_empty());
        assert_eq!(state.successful_executions, 0);
        assert_eq!(state.failed_executions, 0);
    }

    #[tokio::test]
    async fn test_compute_capacity_check() {
        let mut config = NodeConfig::default();
        config.compute_config = crate::ComputeConfig {
            enabled: true,
            capacity: 1,
            ..Default::default()
        };
        let runner = Arc::new(NodeRunner::new(config, [0x42u8; 16], MixNode::new()));

        // First request is accepted and tracked.
        runner
            .accept_compute_request(&test_compute_request([0xA1u8; 32]))
            .await
            .expect("first request should be accepted");
        assert_eq!(runner.compute_state.lock().await.active_executions.len(), 1);

        // Second concurrent request exceeds capacity and is rejected.
        let err = runner
            .accept_compute_request(&test_compute_request([0xA2u8; 32]))
            .await
            .expect_err("second request should be rejected");
        assert!(matches!(err, ComputeError::CapacityExceeded));
    }

    #[tokio::test]
    async fn test_compute_execution_tracking() {
        let mut config = NodeConfig::default();
        config.compute_config = crate::ComputeConfig {
            enabled: true,
            ..Default::default()
        };
        let runner = Arc::new(NodeRunner::new(config, [0x42u8; 16], MixNode::new()));

        let request = test_compute_request([0xC1u8; 32]);
        runner
            .accept_compute_request(&request)
            .await
            .expect("request should be accepted");
        assert!(runner.compute_state.lock().await.active_executions.contains_key(&request.request_id));

        // A failed execution deregisters and counts.
        runner
            .clone()
            .finish_failed_execution(&request, ComputeError::ModuleNotFound)
            .await;
        let state = runner.compute_state.lock().await;
        assert!(!state.active_executions.contains_key(&request.request_id));
        assert_eq!(state.failed_executions, 1);
        assert_eq!(state.successful_executions, 0);
    }

    #[tokio::test]
    async fn test_compute_response_handling() {
        let runner = Arc::new(NodeRunner::new(NodeConfig::default(), [0x42u8; 16], MixNode::new()));

        let request_id = [0xD1u8; 32];
        runner.compute_state.lock().await.pending_requests.insert(
            request_id,
            PendingComputeRequest {
                request_id,
                provider: [0x99u8; 16],
                payment: None,
                started_at: current_timestamp(),
            },
        );

        let response = ComputeResponse {
            request_id,
            output_data: vec![1, 2, 3],
            success: true,
            error: None,
            cpu_time_ms: 10,
            memory_used: 4096,
            payment_required: false,
            payment_request: vec![],
        };
        runner.handle_compute_response(response).await;

        // Result stored for polling; no barter credits are booked anymore.
        let state = runner.compute_state.lock().await;
        assert!(state.pending_requests.is_empty());
        let stored = state.completed_results.get(&request_id).expect("result stored");
        assert_eq!(stored.output_data, vec![1, 2, 3]);
        assert!(runner.accounting.lock().await.peers.is_empty());
    }

    #[tokio::test]
    async fn test_compute_request_ignored_when_disabled() {
        // Compute is disabled by default.
        let runner = Arc::new(NodeRunner::new(NodeConfig::default(), [0x42u8; 16], MixNode::new()));
        assert!(!runner.transport.compute_enabled);

        let payload = static_storage::compute::serialize_request(&test_compute_request([0xE1u8; 32]))
            .unwrap();
        for fragment in static_mesh::fragment::fragment_payload(&payload) {
            let body = static_mesh::fragment::serialize_fragment(&fragment);
            runner.handle_compute_fragment(&body).await;
        }

        // Disabled nodes neither track nor execute compute requests.
        assert!(runner.compute_state.lock().await.active_executions.is_empty());
    }

    #[tokio::test]
    async fn test_compute_request_no_fee_field() {
        // Wire layout: [0x03][16][32][32][currency 1][addr_len 4][addr..]
        // [request_id 32][hops 4][dest 16][input_len 4][input..]. The
        // 8-byte fee_offer field is gone; the currency byte sits at
        // offset 81 where the fee used to start.
        let mut request = test_compute_request([0xE2u8; 32]);
        request.input_data.clear();
        let serialized = static_storage::compute::serialize_request(&request).unwrap();

        assert_eq!(serialized[0], static_storage::compute::MSG_COMPUTE_REQUEST);
        assert_eq!(serialized[81], crate::payment::Currency::Monero.to_byte());
        assert_eq!(&serialized[82..86], &0u32.to_be_bytes());
        // 1+16+32+32+1+4+0+32+4+16+4 = 142 bytes (the old layout was 150).
        assert_eq!(serialized.len(), 142);

        let back = static_storage::compute::deserialize_request(&serialized).unwrap();
        assert_eq!(back, request);
    }

    #[tokio::test]
    async fn test_compute_response_no_fee_field() {
        let response = ComputeResponse {
            request_id: [0xD2u8; 32],
            output_data: vec![0xABu8; 8],
            success: true,
            error: None,
            cpu_time_ms: 1,
            memory_used: 2,
            payment_required: false,
            payment_request: vec![],
        };
        let serialized = static_storage::compute::serialize_response(&response).unwrap();

        assert_eq!(serialized[0], static_storage::compute::MSG_COMPUTE_RESPONSE);
        // 1+32+1+4+8+8+1+4+0+4+8 = 71 bytes (the old fee_charged layout
        // was 78).
        assert_eq!(serialized.len(), 71);

        let back = static_storage::compute::deserialize_response(&serialized).unwrap();
        assert_eq!(back, response);
    }

    #[tokio::test]
    async fn test_payment_flow_integration() {
        let mut config = NodeConfig::default();
        config.compute_config = crate::ComputeConfig {
            enabled: true,
            pricing: crate::payment::ComputePricing {
                price_per_execution: 100,
                accepted_currencies: vec![crate::payment::Currency::Monero],
                required_confirmations: 1,
                ..Default::default()
            },
            ..Default::default()
        };
        let mut runner = NodeRunner::new(config, [0x42u8; 16], MixNode::new());
        let mock = Arc::new(MockWatcher {
            confirmations: std::sync::Mutex::new(None),
        });
        runner
            .payment_watchers
            .insert(crate::payment::Currency::Monero.to_byte(), mock.clone());
        let runner = Arc::new(runner);

        // 1. A paid request arrives -> staged with a fresh-address quote.
        let request = test_compute_request([0xF1u8; 32]);
        let payload = static_storage::compute::serialize_request(&request).unwrap();
        for fragment in static_mesh::fragment::fragment_payload(&payload) {
            let body = static_mesh::fragment::serialize_fragment(&fragment);
            runner.handle_compute_fragment(&body).await;
        }

        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            let state = runner.compute_state.lock().await;
            if let Some(entry) = state.payment_pending.get(&request.request_id) {
                assert!(state.active_executions.is_empty());
                assert_eq!(entry.payment.address, "mock-address-0123456789");
                assert_eq!(entry.payment.amount, 100);
                assert_eq!(entry.payment.currency, crate::payment::Currency::Monero);
                assert_eq!(entry.payment.required_confirmations, 1);
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "request was never staged"
            );
            drop(state);
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }

        // 2. The requester claims the payment with a tx hash.
        runner
            .handle_payment_confirmation(PaymentConfirmation {
                request_id: request.request_id,
                tx_hash: "cafebabe".to_string(),
                currency: crate::payment::Currency::Monero,
            })
            .await;
        assert_eq!(
            runner
                .compute_state
                .lock()
                .await
                .payment_pending
                .get(&request.request_id)
                .unwrap()
                .claimed_tx_hash
                .as_deref(),
            Some("cafebabe")
        );

        // 3. The payment confirms on-chain -> execution starts. It fails
        //    fast (no peers to fetch the module from) and is counted.
        *mock.confirmations.lock().unwrap() = Some(1);
        run_payment_watch_tick(&runner).await;

        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            let state = runner.compute_state.lock().await;
            if state.payment_pending.is_empty() && state.failed_executions >= 1 {
                assert!(state.active_executions.is_empty());
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "execution did not finish in time"
            );
            drop(state);
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
    }

    #[tokio::test]
    async fn test_payment_timeout() {
        let mut config = NodeConfig::default();
        config.compute_config = crate::ComputeConfig {
            enabled: true,
            pricing: crate::payment::ComputePricing {
                price_per_execution: 100,
                ..Default::default()
            },
            ..Default::default()
        };
        let mut runner = NodeRunner::new(config, [0x42u8; 16], MixNode::new());
        runner.payment_watchers.insert(
            crate::payment::Currency::Monero.to_byte(),
            Arc::new(MockWatcher {
                confirmations: std::sync::Mutex::new(None),
            }),
        );
        let runner = Arc::new(runner);

        // Stage a request whose quote was sent 90 minutes ago (past the
        // default 3600 s payment timeout).
        let request = test_compute_request([0xF2u8; 32]);
        runner.compute_state.lock().await.payment_pending.insert(
            request.request_id,
            PendingPayment {
                request_id: request.request_id,
                request: request.clone(),
                payment: PaymentRequest {
                    request_id: request.request_id,
                    currency: crate::payment::Currency::Monero,
                    amount: 100,
                    address: "addr".to_string(),
                    required_confirmations: 1,
                },
                sent_at: current_timestamp().saturating_sub(5400),
                claimed_tx_hash: None,
            },
        );

        // A payment that never arrived does not trigger execution.
        run_payment_watch_tick(&runner).await;

        let state = runner.compute_state.lock().await;
        assert!(state.payment_pending.is_empty());
        assert!(state.active_executions.is_empty());
    }

    #[tokio::test]
    async fn test_verification_state_creation() {
        let state = VerificationState::default();
        assert!(state.pending.is_empty());
        assert_eq!(state.reassembler.received_count(), 0);
        assert_eq!(state.reassembler.total_expected(), None);

        // The runner's verification state starts empty too.
        let runner = NodeRunner::new(NodeConfig::default(), [0x42u8; 16], MixNode::new());
        assert!(runner.verification_state.lock().await.pending.is_empty());
        assert!(runner.manifests.lock().await.is_empty());
   }

    #[tokio::test]
    async fn test_challenge_response_matching() {
        let runner = Arc::new(NodeRunner::new(
            NodeConfig::default(),
            [0x42u8; 16],
            MixNode::new(),
        ));
        let peer: NodeId = [0x77u8; 16];
        let chunk_id: ChunkId = [0x88u8; 32];
        let nonce = [0x99u8; 32];

        // Expected hash comes from the same publish-time computation.
        let chunk = EncryptedChunk {
            id: chunk_id,
            data: vec![0xABu8; SEGMENT_SIZE],
        };
        let hashes = static_storage::verification::compute_segment_hashes(&[chunk]);
        let expected_hash = hashes[0][0];

        runner.verification_state.lock().await.pending.insert(
            nonce,
            VerificationPending {
                chunk_id,
                segment_index: 0,
                expected_hash,
                challenged_node: peer,
                sent_at: current_timestamp(),
            },
        );

        let response = VerificationResponse {
            chunk_id,
            segment_index: 0,
            segment_data: vec![0xABu8; SEGMENT_SIZE],
            nonce,
            found: true,
        };
        runner.handle_verification_response(response).await;

        // Pending consumed; success recorded against the challenged peer.
        assert!(runner.verification_state.lock().await.pending.is_empty());
        let accounting = runner.accounting.lock().await;
        let credit = accounting.peers.get(&peer).expect("peer tracked");
        assert_eq!(credit.successful_challenges, 1);
        assert_eq!(credit.failed_challenges, 0);
    }

    #[tokio::test]
    async fn test_challenge_response_wrong_hash() {
        let runner = Arc::new(NodeRunner::new(
            NodeConfig::default(),
            [0x42u8; 16],
            MixNode::new(),
        ));
        let peer: NodeId = [0x78u8; 16];
        let chunk_id: ChunkId = [0x89u8; 32];
        let nonce = [0x9Au8; 32];

        let chunk = EncryptedChunk {
            id: chunk_id,
            data: vec![0xABu8; SEGMENT_SIZE],
        };
        let hashes = static_storage::verification::compute_segment_hashes(&[chunk]);
        let expected_hash = hashes[0][0];

        runner.verification_state.lock().await.pending.insert(
            nonce,
            VerificationPending {
                chunk_id,
                segment_index: 0,
                expected_hash,
                challenged_node: peer,
                sent_at: current_timestamp(),
            },
        );

        // Same length, different bytes: a freeloader's garbage.
        let response = VerificationResponse {
            chunk_id,
            segment_index: 0,
            segment_data: vec![0xCDu8; SEGMENT_SIZE],
            nonce,
            found: true,
        };
        runner.handle_verification_response(response).await;

        assert!(runner.verification_state.lock().await.pending.is_empty());
        let accounting = runner.accounting.lock().await;
        let credit = accounting.peers.get(&peer).expect("peer tracked");
        assert_eq!(credit.failed_challenges, 1);
        assert_eq!(credit.successful_challenges, 0);
    }
}
