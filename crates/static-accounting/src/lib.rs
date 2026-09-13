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
}

impl Default for PeerCredit {
    fn default() -> Self {
        Self::new()
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
}

impl AccountingState {
    /// Create a new accounting state with default settings
    pub fn new() -> Self {
        Self {
            total_bytes_served: 0,
            total_bytes_received: 0,
            peers: HashMap::new(),
            min_ratio: 0.5,
            initial_credit: 10 * 1024 * 1024, // 10 MiB goodwill
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

    /// Check if a peer should be allowed to receive service
    ///
    /// A peer is allowed if:
    /// 1. They have sufficient net credit, OR
    /// 2. Their ratio is above the minimum, OR
    /// 3. They are new (get initial credit)
    pub fn should_serve(&self, peer: &NodeId, requested_bytes: u64) -> bool {
        let credit = self.peers.get(peer);

        match credit {
            None => {
                // New peer: allow if within initial credit
                requested_bytes <= self.initial_credit
            }
            Some(c) => {
                // Check net credit first
                if c.has_credit(requested_bytes) {
                    return true;
                }

                // Check ratio
                if c.ratio() >= self.min_ratio {
                    return true;
                }

                // Check if they're new enough for initial credit
                if c.bytes_served == 0 && c.bytes_received < self.initial_credit {
                    return requested_bytes <= self.initial_credit - c.bytes_received;
                }

                false
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
        let peer = random_node_id();
        // New peer gets initial credit
        assert!(state.should_serve(&peer, state.initial_credit));
        assert!(!state.should_serve(&peer, state.initial_credit + 1));
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
}
