//! static-accounting - Local peer-to-peer accounting without a blockchain
//!
//! Implements:
//! - Local credit tracking (contribution ratios, per-peer credits)
//! - Proof of Space-Time challenges (verify nodes store what they claim)
//! - Tit-for-tat reciprocity (serve to others, get priority in return)
//! - Freeloader deprioritization (local enforcement, no global authority)
//!
//! There is no blockchain, no global ledger, no consensus. Each node
//! tracks its own contributions and enforces fairness locally.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use blake3;
use rand::rngs::OsRng;
use rand::RngCore;
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

/// Size of a node ID
pub const NODE_ID_SIZE: usize = 16;

/// Size of a chunk ID
pub const CHUNK_ID_SIZE: usize = 32;

/// Size of a challenge nonce
pub const CHALLENGE_NONCE_SIZE: usize = 32;

/// A node ID
pub type NodeId = [u8; NODE_ID_SIZE];

/// A chunk ID
pub type ChunkId = [u8; CHUNK_ID_SIZE];

/// Get the current unix timestamp in seconds
pub fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock went backwards")
        .as_secs()
}

/// Maximum number of seed-only nodes a single sponsor will host
pub const MAX_SPONSORED_SEEDS: usize = 5;

/// Minimum interval between prepayments for the same content (1 hour)
pub const PREPAY_RATE_LIMIT_SECS: u64 = 3600;

/// Maximum clock-skew tolerated in reconciliation timestamps (5 minutes).
///
/// Entries with `last_interaction` further than this beyond `now` are
/// ignored as future-dated (faulty clock or forgery attempt).
pub const RECONCILE_FUTURE_SKEW_SECS: u64 = 300;

/// Sanity bound for reconciled byte counters (2^60 ≈ 1 EiB).
///
/// Entries claiming more than this in any byte field are ignored as
/// corrupt or malicious.
pub const MAX_ACCOUNTING_BYTES: u64 = 1 << 60;

/// Per-peer credit state
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PeerCredit {
    /// Bytes this node has served to this peer
    pub bytes_served: u64,
    /// Bytes this node has received from this peer
    pub bytes_received: u64,
    /// Net credit (served - received)
    pub net_credit: i64,
    /// Last interaction timestamp
    pub last_interaction: u64,
    /// Number of successful Proof of Space-Time challenges
    pub successful_challenges: u32,
    /// Number of failed Proof of Space-Time challenges
    pub failed_challenges: u32,
    /// Bytes this node has prepaid to this peer (for seed-only mode)
    #[serde(default)]
    pub prepaid_bytes: u64,
}

impl PeerCredit {
    /// Create a new peer credit state
    pub fn new() -> Self {
        Self {
            bytes_served: 0,
            bytes_received: 0,
            net_credit: 0,
            last_interaction: 0,
            successful_challenges: 0,
            failed_challenges: 0,
            prepaid_bytes: 0,
        }
    }

    /// Get the contribution ratio (served / received)
    /// Returns infinity if received is 0
    pub fn ratio(&self) -> f64 {
        if self.bytes_received == 0 {
            f64::INFINITY
        } else {
            self.bytes_served as f64 / self.bytes_received as f64
        }
    }

    /// Check if this peer has sufficient credit for a request
    pub fn has_credit(&self, needed: u64) -> bool {
        self.net_credit >= needed as i64
    }

    /// Record bytes served to this peer
    pub fn record_served(&mut self, bytes: u64, timestamp: u64) {
        self.bytes_served += bytes;
        self.net_credit += bytes as i64;
        self.last_interaction = timestamp;
    }

    /// Record bytes received from this peer
    pub fn record_received(&mut self, bytes: u64, timestamp: u64) {
        self.bytes_received += bytes;
        self.net_credit -= bytes as i64;
        self.last_interaction = timestamp;
    }

    /// Record a successful challenge
    pub fn record_challenge_success(&mut self, timestamp: u64) {
        self.successful_challenges += 1;
        self.last_interaction = timestamp;
    }

    /// Record a failed challenge
    pub fn record_challenge_failure(&mut self, timestamp: u64) {
        self.failed_challenges += 1;
        self.last_interaction = timestamp;
    }

    /// Get the challenge success rate (0.0 to 1.0)
    pub fn challenge_success_rate(&self) -> f64 {
        let total = self.successful_challenges + self.failed_challenges;
        if total == 0 {
            1.0
        } else {
            self.successful_challenges as f64 / total as f64
        }
    }

    /// Check if prepaid balance covers a request (seed-only 1:1 via prepayment)
    pub fn has_prepaid(&self, needed: u64) -> bool {
        self.prepaid_bytes >= needed
    }

    /// Effective credit including prepayments (net_credit + prepaid_bytes)
    pub fn effective_credit(&self) -> i64 {
        self.net_credit + self.prepaid_bytes as i64
    }
}

impl Default for PeerCredit {
    fn default() -> Self {
        Self::new()
    }
}

/// Reputation info for a seed-only node sponsored by this node
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SponsoredSeedInfo {
    /// The seed-only node's ID
    pub node_id: NodeId,
    /// Content IDs this seed has prepaid for
    pub content_ids: Vec<[u8; 32]>,
    /// Total bytes prepaid by this seed
    pub total_prepaid: u64,
    /// Heartbeats received from this seed
    pub heartbeats_received: u64,
    /// Prepayment renewals received
    pub prepayment_renewals: u32,
    /// Rate-limit / abuse violations
    pub rate_violations: u32,
    /// Last-seen timestamp (unix secs)
    pub last_seen: u64,
    /// Whether this seed was flagged as misbehaving (dropped)
    pub misbehaving: bool,
}

impl SponsoredSeedInfo {
    /// Create a new sponsored-seed record
    pub fn new(node_id: NodeId, content_id: [u8; 32], prepaid: u64, now: u64) -> Self {
        Self {
            node_id,
            content_ids: vec![content_id],
            total_prepaid: prepaid,
            heartbeats_received: 0,
            prepayment_renewals: 0,
            rate_violations: 0,
            last_seen: now,
            misbehaving: false,
        }
    }
}

/// Local accounting state for a node
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AccountingState {
    /// Total bytes this node has contributed to others
    pub total_bytes_served: u64,
    /// Total bytes this node has received from others
    pub total_bytes_received: u64,
    /// Per-peer credit tracking
    pub peers: HashMap<NodeId, PeerCredit>,
    /// Minimum ratio required to receive service (default 0.5)
    pub min_ratio: f64,
    /// Bytes of credit granted to new peers (goodwill)
    pub initial_credit: u64,
    /// Seed-only nodes this node sponsors (seed NodeId -> info)
    #[serde(default)]
    pub sponsored_seeds: HashMap<NodeId, SponsoredSeedInfo>,
    /// Last prepayment timestamp per (seed, content_id) for rate limiting
    #[serde(default)]
    pub prepayment_attempts: HashMap<(NodeId, [u8; 32]), u64>,
}

impl AccountingState {
    /// Create a new accounting state with default settings
    pub fn new() -> Self {
        Self {
            total_bytes_served: 0,
            total_bytes_received: 0,
            peers: HashMap::new(),
            min_ratio: 0.5,
            initial_credit: 1024 * 1024, // 1 MiB goodwill (new-ID cost)
            sponsored_seeds: HashMap::new(),
            prepayment_attempts: HashMap::new(),
        }
    }

    /// Get or create peer credit for a node
    pub fn get_or_create_peer(&mut self, peer: &NodeId) -> &mut PeerCredit {
        self.peers
            .entry(*peer)
            .or_insert_with(|| PeerCredit::new())
    }

    /// Record bytes served to a peer
    pub fn record_served(&mut self, peer: NodeId, bytes: u64) {
        let ts = current_timestamp();
        self.total_bytes_served += bytes;
        self.get_or_create_peer(&peer).record_served(bytes, ts);
    }

    /// Record bytes received from a peer
    pub fn record_received(&mut self, peer: NodeId, bytes: u64) {
        let ts = current_timestamp();
        self.total_bytes_received += bytes;
        self.get_or_create_peer(&peer).record_received(bytes, ts);
    }

    /// Record a successful chunk integrity challenge against a peer
    ///
    /// The peer returned segment data matching the manifest hash: it
    /// really stores the chunk it claims to store.
    pub fn record_challenge_success(&mut self, peer: &NodeId) {
        let ts = current_timestamp();
        self.get_or_create_peer(peer).record_challenge_success(ts);
    }

    /// Record a failed chunk integrity challenge against a peer
    ///
    /// Covers wrong segment data, `found: false` answers, and timed-out
    /// (unanswered) challenges. Repeated failures deprioritize the peer
    /// via [`AccountingState::should_serve`].
    pub fn record_challenge_failure(&mut self, peer: &NodeId) {
        let ts = current_timestamp();
        self.get_or_create_peer(peer).record_challenge_failure(ts);
    }

    /// Record a prepayment to a sponsor peer
    ///
    /// Prepayments count toward the seed-only node's 1:1 contribution:
    /// `bytes_used <= local_hosted + prepaid_hosted`.
    pub fn record_prepayment(&mut self, peer: NodeId, bytes: u64) {
        self.get_or_create_peer(&peer).prepaid_bytes += bytes;
    }

    /// Get total prepaid bytes across all peers
    pub fn total_prepaid_bytes(&self) -> u64 {
        self.peers.values().map(|c| c.prepaid_bytes).sum()
    }

    /// Effective bytes contributed including prepayments
    pub fn effective_bytes_served(&self) -> u64 {
        self.total_bytes_served.saturating_add(self.total_prepaid_bytes())
    }

    /// Check if this node has excess capacity to act as a sponsor
    ///
    /// A sponsor must have its own 1:1 ratio satisfied with surplus:
    /// `(served - used) > threshold`.
    pub fn has_excess_capacity(&self, threshold: u64) -> bool {
        (self.total_bytes_served as i64 - self.total_bytes_received as i64)
            > threshold as i64
    }

    /// Check whether a prepayment is allowed under the rate limit
    ///
    /// A seed-only node may send at most one prepayment per content ID
    /// per hour. Returns `true` if allowed.
    pub fn check_prepay_rate_limit(
        &self,
        from: &NodeId,
        content_id: &[u8; 32],
        now: u64,
    ) -> bool {
        match self.prepayment_attempts.get(&(*from, *content_id)) {
            None => true,
            Some(last) => now.saturating_sub(*last) >= PREPAY_RATE_LIMIT_SECS,
        }
    }

    /// Record a prepayment attempt for rate limiting
    pub fn record_prepay_attempt(&mut self, from: NodeId, content_id: [u8; 32], now: u64) {
        self.prepayment_attempts.insert((from, content_id), now);
    }

    /// Number of seed-only nodes currently sponsored
    pub fn sponsor_seed_count(&self) -> usize {
        self.sponsored_seeds
            .values()
            .filter(|s| !s.misbehaving)
            .count()
    }

    /// Check whether this node can sponsor another seed (sponsor limit)
    pub fn can_sponsor(&self) -> bool {
        self.sponsor_seed_count() < MAX_SPONSORED_SEEDS
    }

    /// Check whether a seed is already sponsored by this node
    pub fn is_sponsored(&self, seed: &NodeId) -> bool {
        self.sponsored_seeds.contains_key(seed)
    }

    /// Register (or renew) a sponsored seed-only node
    ///
    /// Returns `Err` if the sponsor is at capacity and this is a new seed.
    /// Existing seeds are treated as renewals and always accepted.
    pub fn register_sponsored_seed(
        &mut self,
        seed: NodeId,
        content_id: [u8; 32],
        prepaid_bytes: u64,
        now: u64,
    ) -> Result<(), SponsorError> {
        if let Some(info) = self.sponsored_seeds.get_mut(&seed) {
            if !info.content_ids.contains(&content_id) {
                info.content_ids.push(content_id);
            }
            info.total_prepaid += prepaid_bytes;
            info.prepayment_renewals += 1;
            info.last_seen = now;
            return Ok(());
        }
        if !self.can_sponsor() {
            return Err(SponsorError::AtCapacity);
        }
        self.sponsored_seeds
            .insert(seed, SponsoredSeedInfo::new(seed, content_id, prepaid_bytes, now));
        Ok(())
    }

    /// Record a heartbeat received from a sponsored seed (reputation)
    pub fn record_seed_heartbeat(&mut self, seed: &NodeId, now: u64) {
        if let Some(info) = self.sponsored_seeds.get_mut(seed) {
            info.heartbeats_received += 1;
            info.last_seen = now;
        }
    }

    /// Record a rate-limit / abuse violation for a sponsored seed
    pub fn record_seed_violation(&mut self, seed: &NodeId) {
        if let Some(info) = self.sponsored_seeds.get_mut(seed) {
            info.rate_violations += 1;
            // Three strikes: flag as misbehaving; content is allowed to expire.
            if info.rate_violations >= 3 {
                info.misbehaving = true;
            }
        }
    }

    /// Check if a sponsored seed was flagged as misbehaving
    pub fn is_seed_misbehaving(&self, seed: &NodeId) -> bool {
        self.sponsored_seeds
            .get(seed)
            .map(|s| s.misbehaving)
            .unwrap_or(false)
    }

    /// Check if a node is running (placeholder for API compat)
    /// Returns true; real liveness is tracked via heartbeats/gossip.
    pub fn is_seed_healthy(&self, seed: &NodeId) -> bool {
        self.sponsored_seeds
            .get(seed)
            .map(|s| !s.misbehaving)
            .unwrap_or(false)
    }

    /// Check if a peer should be allowed to receive service (C5 AND-gate).
    ///
    /// All three gates must pass:
    /// 1. Credit gate: `has_credit(requested)` OR `has_prepaid(requested)`
    ///    OR `effective_credit() > 0` OR new peer within goodwill.
    /// 2. Ratio gate: `ratio() >= min_ratio` OR new peer within goodwill
    ///    (goodwill = never served and
    ///    `bytes_received + requested <= initial_credit + prepaid_bytes`;
    ///    prepayments extend goodwill so seed-only nodes that prepaid stay
    ///    servable after exhausting the base 1 MiB).
    /// 3. Challenge gate: NOT (`total_challenges > 10` AND
    ///    `success_rate < 0.5`). Peers with a meaningful failure history
    ///    are denied even with credit (item 14 freeloader gate; the >10
    ///    threshold damps network-glitch false positives).
    ///
    /// Unknown peers get `initial_credit` (1 MiB) goodwill, bounding the
    /// new-ID (Sybil) cost. `initial_credit` is 1 MiB.
    pub fn should_serve(&self, peer: &NodeId, requested_bytes: u64) -> bool {
        let credit = self.peers.get(peer);

        match credit {
            None => {
                // New peer: allow if within 1 MiB goodwill.
                requested_bytes <= self.initial_credit
            }
            Some(c) => {
                // Gate 3: challenge gate (hard deny before anything else).
                let total_challenges = c.successful_challenges + c.failed_challenges;
                if total_challenges > 10 && c.challenge_success_rate() < 0.5 {
                    return false;
                }

                // Goodwill: never served and within base credit plus any
                // prepaid extension.
                let goodwill = c.bytes_served == 0
                    && c.bytes_received.saturating_add(requested_bytes)
                        <= self.initial_credit.saturating_add(c.prepaid_bytes);

                // Gate 1: credit gate.
                let credit_ok = c.has_credit(requested_bytes)
                    || c.has_prepaid(requested_bytes)
                    || c.effective_credit() > 0
                    || goodwill;

                // Gate 2: ratio gate.
                let ratio_ok = c.ratio() >= self.min_ratio || goodwill;

                credit_ok && ratio_ok
            }
        }
    }

    /// Get the overall contribution ratio
    pub fn overall_ratio(&self) -> f64 {
        if self.total_bytes_received == 0 {
            f64::INFINITY
        } else {
            self.total_bytes_served as f64 / self.total_bytes_received as f64
        }
    }

    /// Get a sorted list of peers by credit (highest first)
    pub fn peers_by_credit(&self) -> Vec<(NodeId, &PeerCredit)> {
        let mut peers: Vec<_> = self.peers.iter().collect();
        peers.sort_by(|a, b| b.1.net_credit.cmp(&a.1.net_credit));
        peers.into_iter().map(|(k, v)| (*k, v)).collect()
    }

    /// Get a sorted list of peers by ratio (highest first)
    pub fn peers_by_ratio(&self) -> Vec<(NodeId, &PeerCredit)> {
        let mut peers: Vec<_> = self.peers.iter().collect();
        peers.sort_by(|a, b| {
            b.1.ratio()
                .partial_cmp(&a.1.ratio())
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        peers.into_iter().map(|(k, v)| (*k, v)).collect()
    }

    /// Remove peers that haven't interacted in a long time
    pub fn prune_inactive_peers(&mut self, max_age_secs: u64) {
        let now = current_timestamp();
        self.peers
            .retain(|_, credit| now - credit.last_interaction < max_age_secs);
    }

    /// Remove inactive peers, giving partitioned peers a grace period
    ///
    /// Peers flagged by [`AccountingState::was_partitioned`] are retained
    /// for an additional `grace_secs` beyond `max_age_secs` so a healed
    /// partition can still reconcile instead of losing history.
    pub fn prune_inactive_peers_with_grace(
        &mut self,
        max_age_secs: u64,
        partition_threshold_secs: u64,
        grace_secs: u64,
    ) {
        let now = current_timestamp();
        self.peers.retain(|_, credit| {
            let age = now.saturating_sub(credit.last_interaction);
            if age > partition_threshold_secs {
                age < max_age_secs.saturating_add(grace_secs)
            } else {
                age < max_age_secs
            }
        });
    }

    /// Export peer credits for reconciliation with a reconnected peer
    ///
    /// Returns owned `(peer_id, credit)` pairs. The caller (which owns
    /// both accounting and wire types) converts these into wire
    /// `ReconciliationEntry` values, batching at ~50 per message.
    pub fn export_for_reconciliation(&self) -> Vec<(NodeId, PeerCredit)> {
        self.peers
            .iter()
            .map(|(id, credit)| (*id, credit.clone()))
            .collect()
    }

    /// Reconcile with a peer's exported accounting state (last-write-wins)
    ///
    /// For each incoming `(peer_id, credit)` entry:
    /// 1. Future-dated (`last_interaction > now + 300`) → ignore.
    /// 2. Absurd (`bytes_served`, `bytes_received`, or `prepaid_bytes`
    ///    `> 2^60`) → ignore as corrupt/malicious.
    /// 3. Unknown peer → adopt the incoming entry.
    /// 4. Known peer with newer `last_interaction` → adopt incoming.
    /// 5. Known peer with newer-or-equal local entry → keep ours.
    ///
    /// Idempotent: processing the same batch twice yields the same state,
    /// so multi-message batched exchanges converge. Sender totals are
    /// informational only — no global consistency is enforced (accounting
    /// stays purely local, peer-to-peer).
    pub fn reconcile(&mut self, incoming: &[(NodeId, PeerCredit)]) {
        let now = current_timestamp();
        let future_bound = now.saturating_add(RECONCILE_FUTURE_SKEW_SECS);
        for (peer_id, remote) in incoming {
            // Bound 1: ignore future timestamps beyond clock-skew tolerance.
            if remote.last_interaction > future_bound {
                continue;
            }
            // Bound 2: sanity — ignore absurd byte counts.
            if remote.bytes_served > MAX_ACCOUNTING_BYTES
                || remote.bytes_received > MAX_ACCOUNTING_BYTES
                || remote.prepaid_bytes > MAX_ACCOUNTING_BYTES
            {
                continue;
            }
            match self.peers.get_mut(peer_id) {
                Some(ours) => {
                    if remote.last_interaction > ours.last_interaction {
                        ours.bytes_served = remote.bytes_served;
                        ours.bytes_received = remote.bytes_received;
                        ours.net_credit = remote.net_credit;
                        ours.prepaid_bytes = remote.prepaid_bytes;
                        ours.successful_challenges = remote.successful_challenges;
                        ours.failed_challenges = remote.failed_challenges;
                        ours.last_interaction = remote.last_interaction;
                    }
                }
                None => {
                    self.peers.insert(*peer_id, remote.clone());
                }
            }
        }
    }

    /// Check if a peer was in a partition (unreachable for a long time)
    ///
    /// Returns true if the peer is still recorded but its
    /// `last_interaction` is older than `partition_threshold_secs`.
    /// Unknown peers return false.
    pub fn was_partitioned(
        &self,
        peer: &NodeId,
        partition_threshold_secs: u64,
        current_time: u64,
    ) -> bool {
        match self.peers.get(peer) {
            Some(credit) => current_time.saturating_sub(credit.last_interaction) > partition_threshold_secs,
            None => false,
        }
    }
}

impl Default for AccountingState {
    fn default() -> Self {
        Self::new()
    }
}

/// A Proof of Space-Time challenge
///
/// Verifies that a node is actually storing the chunk it claims to store.
/// The challenge includes a nonce and a deadline. The challenged node must
/// produce a proof that involves the chunk's content without revealing it.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Challenge {
    /// The chunk ID being challenged
    pub chunk_id: ChunkId,
    /// Random nonce for this challenge
    pub nonce: [u8; CHALLENGE_NONCE_SIZE],
    /// When the challenge was issued (unix timestamp)
    pub issued_at: u64,
    /// Challenge deadline (unix timestamp)
    pub deadline: u64,
    /// The challenging node's ID
    pub challenger: NodeId,
}

/// A proof response to a Proof of Space-Time challenge
///
/// The proof is a blake3 hash of (chunk_data || nonce || context).
/// The verifier can check this without seeing the chunk data if they
/// also have the chunk, or the prover can reveal the hash.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ChallengeProof {
    /// The challenge being responded to
    pub challenge: Challenge,
    /// The proof: blake3(chunk_data || nonce || "space_time_proof")
    pub proof: [u8; 32],
}

/// Errors that can occur during accounting operations
#[derive(Debug, thiserror::Error)]
pub enum AccountingError {
    /// Challenge deadline expired
    #[error("challenge deadline expired")]
    ChallengeExpired,
    /// Proof verification failed
    #[error("proof verification failed")]
    ProofFailed,
    /// Peer not found
    #[error("peer not found")]
    PeerNotFound,
}

/// Errors that can occur during sponsor operations
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SponsorError {
    /// Sponsor is at capacity (already sponsors MAX_SPONSORED_SEEDS seeds)
    #[error("sponsor at capacity")]
    AtCapacity,
    /// Prepayment rate limit exceeded (one per content per hour)
    #[error("prepayment rate limit exceeded")]
    RateLimited,
    /// Insufficient stake (prepayment must cover content size)
    #[error("insufficient stake")]
    InsufficientStake,
    /// Seed was flagged as misbehaving
    #[error("seed misbehaving")]
    Misbehaving,
}

/// Create a new Proof of Space-Time challenge
pub fn create_challenge(
    chunk_id: ChunkId,
    challenger: NodeId,
    duration_secs: u64,
) -> Challenge {
    let mut nonce = [0u8; CHALLENGE_NONCE_SIZE];
    OsRng.fill_bytes(&mut nonce);

    let now = current_timestamp();

    Challenge {
        chunk_id,
        nonce,
        issued_at: now,
        deadline: now + duration_secs,
        challenger,
    }
}

/// Create a proof for a challenge.
///
/// The proof is: blake3(chunk_data || nonce || "space_time_proof")
/// This proves the node has access to the chunk data at this point in time.
pub fn create_proof(challenge: &Challenge, chunk_data: &[u8]) -> ChallengeProof {
    let mut input = Vec::with_capacity(chunk_data.len() + CHALLENGE_NONCE_SIZE + 16);
    input.extend_from_slice(chunk_data);
    input.extend_from_slice(&challenge.nonce);
    input.extend_from_slice(b"space_time_proof");

    let hash = blake3::hash(&input);
    let mut proof = [0u8; 32];
    proof.copy_from_slice(hash.as_bytes());

    ChallengeProof {
        challenge: challenge.clone(),
        proof,
    }
}

/// Verify a proof of space-time.
///
/// Checks that:
/// 1. The challenge has not expired
/// 2. The proof matches the chunk data
pub fn verify_proof(
    proof: &ChallengeProof,
    chunk_data: &[u8],
    current_time: u64,
) -> Result<(), AccountingError> {
    // Check deadline
    if current_time > proof.challenge.deadline {
        return Err(AccountingError::ChallengeExpired);
    }

    // Recompute the proof
    let mut input = Vec::with_capacity(chunk_data.len() + CHALLENGE_NONCE_SIZE + 16);
    input.extend_from_slice(chunk_data);
    input.extend_from_slice(&proof.challenge.nonce);
    input.extend_from_slice(b"space_time_proof");

    let expected_hash = blake3::hash(&input);
    let mut expected_proof = [0u8; 32];
    expected_proof.copy_from_slice(expected_hash.as_bytes());

    if proof.proof != expected_proof {
        return Err(AccountingError::ProofFailed);
    }

    Ok(())
}

/// Verify a proof without the chunk data (for relay nodes).
///
/// This only checks the deadline, not the actual proof.
/// The actual proof verification is done by nodes that have the chunk.
pub fn verify_proof_deadline(
    proof: &ChallengeProof,
    current_time: u64,
) -> Result<(), AccountingError> {
    if current_time > proof.challenge.deadline {
        return Err(AccountingError::ChallengeExpired);
    }
    Ok(())
}

/// Tit-for-tat decision: should this node serve a chunk to a peer?
///
/// Considers:
/// 1. Net credit
/// 2. Contribution ratio
/// 3. Challenge success rate
/// 4. Recency of interaction
pub fn tit_for_tat_decision(
    state: &AccountingState,
    peer: &NodeId,
    requested_bytes: u64,
    min_challenge_success_rate: f64,
) -> bool {
    // Basic credit check
    if !state.should_serve(peer, requested_bytes) {
        return false;
    }

    // Check challenge success rate
    if let Some(credit) = state.peers.get(peer) {
        if credit.challenge_success_rate() < min_challenge_success_rate {
            return false;
        }
    }

    true
}

/// Determine which peers to prioritize for serving.
///
/// Returns a list of (peer_id, priority) sorted by priority (highest first).
/// Priority is based on:
/// 1. Net credit (peers who owe us get higher priority)
/// 2. Challenge success rate
/// 3. Recency of interaction
pub fn prioritize_peers(state: &AccountingState) -> Vec<(NodeId, f64)> {
    let now = current_timestamp();

    let mut priorities: Vec<(NodeId, f64)> = state
        .peers
        .iter()
        .map(|(peer, credit)| {
            let mut score = 0.0;

            // Net credit component (capped at 100 MiB)
            let credit_score = (credit.net_credit as f64 / (100.0 * 1024.0 * 1024.0)).max(-1.0).min(1.0);
            score += credit_score * 0.5;

            // Challenge success rate component
            score += credit.challenge_success_rate() * 0.3;

            // Recency component (peers active in last hour get bonus)
            let age = now.saturating_sub(credit.last_interaction);
            if age < 3600 {
                score += 0.2 * (1.0 - age as f64 / 3600.0);
            }

            (*peer, score)
        })
        .collect();

    priorities.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
    priorities
}

#[cfg(test)]
mod tests {
    use super::*;

    fn random_node_id() -> NodeId {
        let mut id = [0u8; NODE_ID_SIZE];
        OsRng.fill_bytes(&mut id);
        id
    }

    fn random_chunk_id() -> ChunkId {
        let mut id = [0u8; CHUNK_ID_SIZE];
        OsRng.fill_bytes(&mut id);
        id
    }

    #[test]
    fn test_peer_credit_creation() {
        let credit = PeerCredit::new();
        assert_eq!(credit.bytes_served, 0);
        assert_eq!(credit.bytes_received, 0);
        assert_eq!(credit.net_credit, 0);
        assert_eq!(credit.successful_challenges, 0);
        assert_eq!(credit.failed_challenges, 0);
    }

    #[test]
    fn test_peer_credit_ratio() {
        let mut credit = PeerCredit::new();
        credit.record_served(1000, 0);
        credit.record_received(500, 0);
        assert_eq!(credit.ratio(), 2.0);
        assert_eq!(credit.net_credit, 500);
    }

    #[test]
    fn test_peer_credit_infinite_ratio() {
        let mut credit = PeerCredit::new();
        credit.record_served(1000, 0);
        assert!(credit.ratio().is_infinite());
    }

    #[test]
    fn test_peer_credit_has_credit() {
        let mut credit = PeerCredit::new();
        credit.record_served(1000, 0);
        assert!(credit.has_credit(500));
        assert!(credit.has_credit(1000));
        assert!(!credit.has_credit(1001));
    }

    #[test]
    fn test_peer_credit_challenge_tracking() {
        let mut credit = PeerCredit::new();
        credit.record_challenge_success(0);
        credit.record_challenge_success(0);
        credit.record_challenge_failure(0);
        assert_eq!(credit.challenge_success_rate(), 2.0 / 3.0);
    }

    #[test]
    fn test_accounting_state_new() {
        let state = AccountingState::new();
        assert_eq!(state.total_bytes_served, 0);
        assert_eq!(state.total_bytes_received, 0);
        assert_eq!(state.peers.len(), 0);
        assert_eq!(state.min_ratio, 0.5);
        // Goodwill hardened to 1 MiB (new-ID cost).
        assert_eq!(state.initial_credit, 1024 * 1024);
    }

    #[test]
    fn test_accounting_record_served() {
        let mut state = AccountingState::new();
        let peer = random_node_id();
        state.record_served(peer, 1000);
        assert_eq!(state.total_bytes_served, 1000);
        assert_eq!(state.peers[&peer].bytes_served, 1000);
        assert_eq!(state.peers[&peer].net_credit, 1000);
    }

    #[test]
    fn test_accounting_record_received() {
        let mut state = AccountingState::new();
        let peer = random_node_id();
        state.record_received(peer, 500);
        assert_eq!(state.total_bytes_received, 500);
        assert_eq!(state.peers[&peer].bytes_received, 500);
        assert_eq!(state.peers[&peer].net_credit, -500);
    }

    #[test]
    fn test_should_serve_new_peer() {
        let state = AccountingState::new();
        // Goodwill is exactly 1 MiB (new-ID cost).
        assert_eq!(state.initial_credit, 1024 * 1024);
        let peer = random_node_id();
        // New peer gets initial credit
        assert!(state.should_serve(&peer, state.initial_credit));
        assert!(!state.should_serve(&peer, state.initial_credit + 1));
    }

    #[test]
    fn test_new_peers_get_1mib() {
        // C5: unknown peers get 1 MiB goodwill, bounding Sybil new-ID cost.
        let state = AccountingState::new();
        assert_eq!(state.initial_credit, 1024 * 1024);
        let peer = random_node_id();
        assert!(state.should_serve(&peer, 1024 * 1024));
        assert!(!state.should_serve(&peer, 1024 * 1024 + 1));
        // Known new peer within goodwill (served==0, small received) passes.
        let mut state2 = AccountingState::new();
        let peer2 = random_node_id();
        state2.record_received(peer2, 1000);
        // 1000 received + 1000 requested <= 1 MiB goodwill.
        assert!(state2.should_serve(&peer2, 1000));
        // Exhausting goodwill denies.
        state2.record_received(peer2, 1024 * 1024);
        assert!(!state2.should_serve(&peer2, 1));
    }

    #[test]
    fn test_freeloader_negative_net_denied() {
        // C5 AND-gate: negative net + bad ratio => denied even for tiny asks.
        let mut state = AccountingState::new();
        let peer = random_node_id();
        state.record_served(peer, 100);
        state.record_received(peer, 10_000);
        let credit = &state.peers[&peer];
        assert!(credit.net_credit < 0);
        assert!(credit.ratio() < state.min_ratio);
        assert!(!state.should_serve(&peer, 1));
        assert!(!state.should_serve(&peer, 100));
    }

    #[test]
    fn test_should_serve_with_credit() {
        let mut state = AccountingState::new();
        let peer = random_node_id();
        state.record_served(peer, 5000);
        assert!(state.should_serve(&peer, 3000));
    }

    #[test]
    fn test_should_serve_no_credit() {
        let mut state = AccountingState::new();
        let peer = random_node_id();
        state.record_received(peer, state.initial_credit + 1);
        assert!(!state.should_serve(&peer, 1));
    }

    #[test]
    fn test_should_serve_with_good_ratio() {
        let mut state = AccountingState::new();
        let peer = random_node_id();
        state.record_served(peer, 10000);
        state.record_received(peer, 5000);
        // Ratio is 2.0, above min_ratio of 0.5
        assert!(state.should_serve(&peer, 100));
    }

    #[test]
    fn test_should_serve_with_bad_ratio() {
        let mut state = AccountingState::new();
        let peer = random_node_id();
        state.record_served(peer, 100);
        state.record_received(peer, 1000);
        // Ratio is 0.1, below min_ratio of 0.5
        // No net credit and bad ratio
        assert!(!state.should_serve(&peer, 100));
    }

    #[test]
    fn test_challenge_success_tracking() {
        let mut state = AccountingState::new();
        let peer = random_node_id();

        // Recording creates the peer entry (no silent drops) and
        // updates the counters.
        state.record_challenge_success(&peer);
        state.record_challenge_success(&peer);
        state.record_challenge_failure(&peer);

        let credit = &state.peers[&peer];
        assert_eq!(credit.successful_challenges, 2);
        assert_eq!(credit.failed_challenges, 1);
        assert_eq!(credit.challenge_success_rate(), 2.0 / 3.0);
    }

    #[test]
    fn test_should_serve_rejects_low_success_rate() {
        let mut state = AccountingState::new();
        let peer = random_node_id();

        // Ample credit would normally allow any small request...
        state.record_served(peer, 10_000);
        // ...but 11 challenges with a 5/11 (~45%) success rate flag the
        // peer as a freeloader.
        for _ in 0..5 {
            state.record_challenge_success(&peer);
        }
        for _ in 0..6 {
            state.record_challenge_failure(&peer);
        }

        assert!(!state.should_serve(&peer, 100));
    }

    #[test]
    fn test_challenge_gate_denies_even_with_credit() {
        // C5: challenge gate is ANDed — large credit + good ratio still
        // denied when total>10 and success<50%.
        let mut state = AccountingState::new();
        let peer = random_node_id();
        // Large credit and perfect ratio (served >> received).
        state.record_served(peer, 10 * 1024 * 1024);
        state.record_received(peer, 1000);
        assert!(state.peers[&peer].net_credit > 0);
        assert!(state.peers[&peer].ratio() >= state.min_ratio);
        // Sanity: allowed before challenge history.
        assert!(state.should_serve(&peer, 1000));
        // Poison challenge history: 4/12 (~33%) success.
        for _ in 0..4 {
            state.record_challenge_success(&peer);
        }
        for _ in 0..8 {
            state.record_challenge_failure(&peer);
        }
        assert!(!state.should_serve(&peer, 1));
        assert!(!state.should_serve(&peer, 1000));
    }

    #[test]
    fn test_should_serve_allows_high_success_rate() {
        let mut state = AccountingState::new();
        let peer = random_node_id();

        state.record_served(peer, 10_000);
        for _ in 0..12 {
            state.record_challenge_success(&peer);
        }
        for _ in 0..2 {
            state.record_challenge_failure(&peer);
        }
        // 12/14 (~86%) success: the gate does not fire.
        assert!(state.should_serve(&peer, 100));

        // Boundary: exactly 10 challenges (even all failures) stays
        // under the >10 threshold, so no history means no penalty.
        let fresh = random_node_id();
        state.record_served(fresh, 10_000);
        for _ in 0..10 {
            state.record_challenge_failure(&fresh);
        }
        assert!(state.should_serve(&fresh, 100));
    }

    #[test]
    fn test_overall_ratio() {
        let mut state = AccountingState::new();
        state.record_served(random_node_id(), 2000);
        state.record_received(random_node_id(), 1000);
        assert_eq!(state.overall_ratio(), 2.0);
    }

    #[test]
    fn test_peers_by_credit() {
        let mut state = AccountingState::new();
        let peer1 = random_node_id();
        let peer2 = random_node_id();
        let peer3 = random_node_id();

        state.record_served(peer1, 1000);
        state.record_served(peer2, 2000);
        state.record_served(peer3, 500);

        let sorted = state.peers_by_credit();
        assert_eq!(sorted[0].0, peer2);
        assert_eq!(sorted[1].0, peer1);
        assert_eq!(sorted[2].0, peer3);
    }

    #[test]
    fn test_challenge_creation() {
        let chunk_id = random_chunk_id();
        let challenger = random_node_id();
        let challenge = create_challenge(chunk_id, challenger, 3600);

        assert_eq!(challenge.chunk_id, chunk_id);
        assert_eq!(challenge.challenger, challenger);
        assert!(challenge.deadline > challenge.issued_at);
        assert_ne!(challenge.nonce, [0u8; CHALLENGE_NONCE_SIZE]);
    }

    #[test]
    fn test_proof_creation_and_verification() {
        let chunk_id = random_chunk_id();
        let challenger = random_node_id();
        let challenge = create_challenge(chunk_id, challenger, 3600);

        let chunk_data = b"this is the chunk data being proven";
        let proof = create_proof(&challenge, chunk_data);

        let result = verify_proof(&proof, chunk_data, current_timestamp());
        assert!(result.is_ok());
    }

    #[test]
    fn test_proof_wrong_data() {
        let chunk_id = random_chunk_id();
        let challenger = random_node_id();
        let challenge = create_challenge(chunk_id, challenger, 3600);

        let chunk_data = b"this is the chunk data being proven";
        let wrong_data = b"this is NOT the chunk data";
        let proof = create_proof(&challenge, chunk_data);

        let result = verify_proof(&proof, wrong_data, current_timestamp());
        assert!(matches!(result, Err(AccountingError::ProofFailed)));
    }

    #[test]
    fn test_proof_expired() {
        let chunk_id = random_chunk_id();
        let challenger = random_node_id();
        let challenge = create_challenge(chunk_id, challenger, 3600);

        let chunk_data = b"chunk data";
        let proof = create_proof(&challenge, chunk_data);

        // Verify with a timestamp far in the future
        let result = verify_proof(&proof, chunk_data, current_timestamp() + 7200);
        assert!(matches!(result, Err(AccountingError::ChallengeExpired)));
    }

    #[test]
    fn test_tit_for_tat_decision() {
        let mut state = AccountingState::new();
        let peer = random_node_id();

        // New peer: allowed
        assert!(tit_for_tat_decision(&state, &peer, 1000, 0.8));

        // Peer with good credit and challenge history
        state.record_served(peer, 10000);
        state.record_received(peer, 5000);
        state.get_or_create_peer(&peer).record_challenge_success(0);
        state.get_or_create_peer(&peer).record_challenge_success(0);
        state.get_or_create_peer(&peer).record_challenge_success(0);

        assert!(tit_for_tat_decision(&state, &peer, 1000, 0.8));

        // Peer with bad challenge rate
        state.get_or_create_peer(&peer).record_challenge_failure(0);
        state.get_or_create_peer(&peer).record_challenge_failure(0);
        state.get_or_create_peer(&peer).record_challenge_failure(0);

        // Success rate is now 0.5, below 0.8 threshold
        assert!(!tit_for_tat_decision(&state, &peer, 1000, 0.8));
    }

    #[test]
    fn test_prioritize_peers() {
        let mut state = AccountingState::new();
        let peer1 = random_node_id();
        let peer2 = random_node_id();
        let peer3 = random_node_id();

        // peer1: high credit
        state.record_served(peer1, 50 * 1024 * 1024);

        // peer2: low credit
        state.record_served(peer2, 1000);

        // peer3: negative credit (received more than served)
        state.record_received(peer3, 10 * 1024 * 1024);

        let priorities = prioritize_peers(&state);
        assert!(!priorities.is_empty());

        // peer1 should be ranked highest
        assert_eq!(priorities[0].0, peer1);
    }

    #[test]
    fn test_prune_inactive_peers() {
        let mut state = AccountingState::new();
        let peer1 = random_node_id();
        let peer2 = random_node_id();

        state.record_served(peer1, 1000);
        state.record_served(peer2, 2000);

        // Manually set peer2's last interaction to far in the past
        let old_time = current_timestamp() - 86400 * 30; // 30 days ago
        state.peers.get_mut(&peer2).unwrap().last_interaction = old_time;

        // Prune peers inactive for more than 7 days
        state.prune_inactive_peers(86400 * 7);

        assert!(state.peers.contains_key(&peer1));
        assert!(!state.peers.contains_key(&peer2));
    }

    #[test]
    fn test_prepayment_recording() {
        let mut state = AccountingState::new();
        let peer = random_node_id();
        assert_eq!(state.total_prepaid_bytes(), 0);
        state.record_prepayment(peer, 1000);
        assert_eq!(state.peers[&peer].prepaid_bytes, 1000);
        assert_eq!(state.total_prepaid_bytes(), 1000);
        state.record_prepayment(peer, 500);
        assert_eq!(state.total_prepaid_bytes(), 1500);
    }

    #[test]
    fn test_excess_capacity_check() {
        let mut state = AccountingState::new();
        let peer = random_node_id();
        // No surplus initially
        assert!(!state.has_excess_capacity(0));
        state.record_served(peer, 2000);
        state.record_received(random_node_id(), 500);
        // served - used = 1500 > 1000
        assert!(state.has_excess_capacity(1000));
        assert!(!state.has_excess_capacity(2000));
    }

    #[test]
    fn test_seed_only_1to1_enforcement() {
        let mut state = AccountingState::new();
        let seed = random_node_id();
        // Seed consumed more than its goodwill: bad ratio, no credit.
        state.record_received(seed, state.initial_credit + 1);
        assert!(!state.should_serve(&seed, 1));
        // Prepayment satisfies 1:1: stored <= local + prepaid.
        state.record_prepayment(seed, 5000);
        assert!(state.should_serve(&seed, 1000));
        assert_eq!(state.effective_bytes_served(), 5000);
    }

    #[test]
    fn test_sybil_rate_limit() {
        let mut state = AccountingState::new();
        let seed = random_node_id();
        let content = [0xABu8; 32];
        let now = 1_000_000u64;
        // First prepayment allowed
        assert!(state.check_prepay_rate_limit(&seed, &content, now));
        state.record_prepay_attempt(seed, content, now);
        // Immediate second prepayment rejected
        assert!(!state.check_prepay_rate_limit(&seed, &content, now + 10));
        // After one hour allowed again
        assert!(state.check_prepay_rate_limit(
            &seed,
            &content,
            now + PREPAY_RATE_LIMIT_SECS
        ));
        // Different content ID is independent
        let other = [0xCDu8; 32];
        assert!(state.check_prepay_rate_limit(&seed, &other, now + 10));
    }

    #[test]
    fn test_sponsor_limit() {
        let mut state = AccountingState::new();
        let now = 1_000_000u64;
        // Fill sponsor slots
        for i in 0..MAX_SPONSORED_SEEDS {
            let mut id = [0u8; NODE_ID_SIZE];
            id[0] = i as u8 + 1;
            let content = [i as u8; 32];
            assert!(state.can_sponsor());
            state
                .register_sponsored_seed(id, content, 1000, now)
                .unwrap();
        }
        assert!(!state.can_sponsor());
        assert_eq!(state.sponsor_seed_count(), MAX_SPONSORED_SEEDS);
        // New seed rejected
        let extra = [0xFFu8; NODE_ID_SIZE];
        let result = state.register_sponsored_seed(extra, [0xEEu8; 32], 1000, now);
        assert!(matches!(result, Err(SponsorError::AtCapacity)));
        // Renewal from existing seed still accepted (does not consume slot)
        let mut first = [0u8; NODE_ID_SIZE];
        first[0] = 1;
        assert!(state
            .register_sponsored_seed(first, [0xDDu8; 32], 500, now)
            .is_ok());
        // Reputation: violations flag misbehaving seeds
        state.record_seed_heartbeat(&first, now + 1);
        assert_eq!(state.sponsored_seeds[&first].heartbeats_received, 1);
        state.record_seed_violation(&first);
        state.record_seed_violation(&first);
        state.record_seed_violation(&first);
        assert!(state.is_seed_misbehaving(&first));
    }

    fn make_remote_credit(served: u64, received: u64, last: u64) -> PeerCredit {
        let mut c = PeerCredit::new();
        c.bytes_served = served;
        c.bytes_received = received;
        c.net_credit = served as i64 - received as i64;
        c.last_interaction = last;
        c
    }

    #[test]
    fn test_reconciliation_new_peer() {
        let mut state = AccountingState::new();
        let peer = random_node_id();
        assert!(!state.peers.contains_key(&peer));
        let remote = make_remote_credit(1000, 200, 5000);
        state.reconcile(&[(peer, remote)]);
        let adopted = &state.peers[&peer];
        assert_eq!(adopted.bytes_served, 1000);
        assert_eq!(adopted.bytes_received, 200);
        assert_eq!(adopted.net_credit, 800);
        assert_eq!(adopted.last_interaction, 5000);
    }

    #[test]
    fn test_reconciliation_last_write_wins() {
        let mut state = AccountingState::new();
        let peer = random_node_id();
        let mut ours = make_remote_credit(5000, 1000, 9000);
        ours.prepaid_bytes = 111;
        state.peers.insert(peer, ours);
        // Incoming is older — keep ours (incl. prepaid).
        let mut stale = make_remote_credit(100, 100, 1000);
        stale.prepaid_bytes = 999;
        state.reconcile(&[(peer, stale)]);
        let kept = &state.peers[&peer];
        assert_eq!(kept.bytes_served, 5000);
        assert_eq!(kept.prepaid_bytes, 111);
        assert_eq!(kept.last_interaction, 9000);
    }

    #[test]
    fn test_reconciliation_older_overwritten() {
        let mut state = AccountingState::new();
        let peer = random_node_id();
        let mut ours = make_remote_credit(100, 100, 1000);
        ours.prepaid_bytes = 1;
        ours.successful_challenges = 2;
        state.peers.insert(peer, ours);
        // Incoming is newer — adopt everything.
        let mut fresh = make_remote_credit(7000, 3000, 9000);
        fresh.prepaid_bytes = 42;
        fresh.successful_challenges = 7;
        fresh.failed_challenges = 3;
        state.reconcile(&[(peer, fresh)]);
        let adopted = &state.peers[&peer];
        assert_eq!(adopted.bytes_served, 7000);
        assert_eq!(adopted.bytes_received, 3000);
        assert_eq!(adopted.prepaid_bytes, 42);
        assert_eq!(adopted.successful_challenges, 7);
        assert_eq!(adopted.failed_challenges, 3);
        assert_eq!(adopted.last_interaction, 9000);
    }

    #[test]
    fn test_partition_detection() {
        let mut state = AccountingState::new();
        let peer = random_node_id();
        let now = current_timestamp();
        let credit = make_remote_credit(100, 100, now - 5000);
        state.peers.insert(peer, credit);
        // Age 5000 > threshold 3600 → partitioned.
        assert!(state.was_partitioned(&peer, 3600, now));
        // Recent peer is not partitioned.
        let fresh = random_node_id();
        state
            .peers
            .insert(fresh, make_remote_credit(100, 100, now - 500));
        assert!(!state.was_partitioned(&fresh, 3600, now));
        // Unknown peer → false.
        assert!(!state.was_partitioned(&random_node_id(), 3600, now));
        // Grace pruning keeps the partitioned peer: max_age 6000 covers
        // age 5000, and grace extends it further.
        state.prune_inactive_peers_with_grace(6000, 3600, 86400);
        assert!(state.peers.contains_key(&peer));
        assert!(state.peers.contains_key(&fresh));
        // Tight threshold with no grace prunes the old peer only.
        state.prune_inactive_peers_with_grace(1000, 3600, 0);
        assert!(!state.peers.contains_key(&peer));
        assert!(state.peers.contains_key(&fresh));
    }

    #[test]
    fn test_reconciliation_preserves_prepayments() {
        let mut state = AccountingState::new();
        let peer = random_node_id();
        let mut remote = make_remote_credit(2000, 500, 8000);
        remote.prepaid_bytes = 12345;
        state.reconcile(&[(peer, remote)]);
        assert_eq!(state.peers[&peer].prepaid_bytes, 12345);
        assert_eq!(state.total_prepaid_bytes(), 12345);
        // Export round-trips the prepaid field.
        let exported = state.export_for_reconciliation();
        assert_eq!(exported.len(), 1);
        assert_eq!(exported[0].1.prepaid_bytes, 12345);
    }

    #[test]
    fn test_reconciliation_rejects_future_timestamp() {
        // Entries more than 300s in the future are ignored (clock-skew bound).
        let mut state = AccountingState::new();
        let peer = random_node_id();
        let now = current_timestamp();

        // New peer with future timestamp → not adopted.
        let future = make_remote_credit(1000, 200, now + RECONCILE_FUTURE_SKEW_SECS + 1000);
        state.reconcile(&[(peer, future)]);
        assert!(!state.peers.contains_key(&peer));

        // Known peer: future-dated newer entry does not overwrite.
        let ours = make_remote_credit(5000, 1000, now);
        state.peers.insert(peer, ours.clone());
        let mut evil = make_remote_credit(9999, 1, now + 10_000);
        evil.prepaid_bytes = 777;
        state.reconcile(&[(peer, evil)]);
        let kept = &state.peers[&peer];
        assert_eq!(kept.bytes_served, 5000);
        assert_eq!(kept.bytes_received, 1000);
        assert_eq!(kept.last_interaction, now);

        // Boundary: exactly now+300 is accepted (not > bound).
        let fresh = random_node_id();
        let edge = make_remote_credit(111, 22, now + RECONCILE_FUTURE_SKEW_SECS);
        state.reconcile(&[(fresh, edge)]);
        assert!(state.peers.contains_key(&fresh));
        assert_eq!(state.peers[&fresh].bytes_served, 111);
    }

    #[test]
    fn test_reconciliation_rejects_absurd_bytes() {
        // Entries with any byte field > 2^60 are ignored as corrupt/malicious.
        let mut state = AccountingState::new();
        let now = current_timestamp();

        let bad_served = {
            let c = make_remote_credit(1 << 61, 0, now);
            c
        };
        let peer1 = random_node_id();
        state.reconcile(&[(peer1, bad_served)]);
        assert!(!state.peers.contains_key(&peer1));

        let bad_received = make_remote_credit(0, (1 << 60) + 1, now);
        let peer2 = random_node_id();
        state.reconcile(&[(peer2, bad_received)]);
        assert!(!state.peers.contains_key(&peer2));

        let mut bad_prepaid = make_remote_credit(100, 100, now);
        bad_prepaid.prepaid_bytes = 1 << 61;
        let peer3 = random_node_id();
        state.reconcile(&[(peer3, bad_prepaid)]);
        assert!(!state.peers.contains_key(&peer3));

        // Sane values still adopted.
        let peer4 = random_node_id();
        state.reconcile(&[(peer4, make_remote_credit(100, 100, now))]);
        assert!(state.peers.contains_key(&peer4));
    }
}
