//! Storage swap barter protocol
//!
//! Implements the 1:1 storage barter system where nodes exchange
//! opaque encrypted chunks without knowing what they contain.
//!
//! Protocol flow:
//! 1. Node A wants to store 1 MiB. It creates a SwapProposal
//!    containing one of its chunks and sends it to Node B.
//! 2. Node B receives the proposal. If it has storage capacity and
//!    accepts the barter, it creates a SwapAccept containing one of
//!    its own chunks and sends it back.
//! 3. Node A receives the acceptance. Both nodes now hold each
//!    other's chunks and track the barter locally.
//! 4. If Node B rejects, it sends a SwapReject.
//!
//! The swap happens at the chunk level. Neither node knows what
//! the chunks contain. The swap is a barter of opaque storage slots,
//! not a barter of identified content.

use crate::{
    EncryptedChunk, ChunkLease, ChunkId, NodeId,
    StorageError, create_lease, is_lease_valid,
};
use static_crypto::SymmetricKey;
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

/// Swap proposal message type
pub const SWAP_PROPOSAL: u8 = 0x01;

/// Swap accept message type
pub const SWAP_ACCEPT: u8 = 0x02;

/// Swap reject message type
pub const SWAP_REJECT: u8 = 0x03;

/// Default lease duration for swapped chunks (24 hours)
pub const DEFAULT_LEASE_DURATION_SECS: u64 = 86400;

/// Get current unix timestamp
fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock went backwards")
        .as_secs()
}

/// A swap proposal from one node to another
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SwapProposal {
    /// The proposing node's ID
    pub from_node: NodeId,
    /// The chunk being offered
    pub chunk: EncryptedChunk,
    /// The lease associated with the chunk
    pub lease: ChunkLease,
    /// The master key (encrypted to the receiving node, or shared for barter)
    /// In a pure barter, the key is not shared - the chunk is opaque
    pub encrypted_master_key: Vec<u8>,
}

/// A swap acceptance
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SwapAccept {
    /// The accepting node's ID
    pub from_node: NodeId,
    /// The chunk being offered in return
    pub chunk: EncryptedChunk,
    /// The lease associated with the return chunk
    pub lease: ChunkLease,
    /// The proposal ID this accepts (hash of the original proposal)
    pub proposal_id: [u8; 32],
    /// The master key for the return chunk (encrypted to the proposer)
    pub encrypted_master_key: Vec<u8>,
}

/// A swap rejection
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SwapReject {
    /// The rejecting node's ID
    pub from_node: NodeId,
    /// The proposal ID being rejected
    pub proposal_id: [u8; 32],
    /// Reason for rejection
    pub reason: SwapRejectReason,
}

/// Reasons for rejecting a swap
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum SwapRejectReason {
    /// No storage capacity available
    NoCapacity = 0,
    /// Already storing too many chunks from this peer
    TooManyFromPeer = 1,
    /// Chunk size mismatch (expected 1 MiB)
    InvalidChunkSize = 2,
    /// Invalid lease
    InvalidLease = 3,
}

impl TryFrom<u8> for SwapRejectReason {
    type Error = StorageError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(SwapRejectReason::NoCapacity),
            1 => Ok(SwapRejectReason::TooManyFromPeer),
            2 => Ok(SwapRejectReason::InvalidChunkSize),
            3 => Ok(SwapRejectReason::InvalidLease),
            _ => Err(StorageError::InvalidChunkSize {
                expected: 0,
                actual: value as usize,
            }),
        }
    }
}

/// Local state for tracking pending and active swaps
#[derive(Debug, Clone, Default)]
pub struct SwapState {
    /// Pending proposals (proposal_id -> proposal)
    pub pending_proposals: HashMap<[u8; 32], SwapProposal>,
    /// Active swaps (chunk_id -> swap partner node ID)
    pub active_swaps: HashMap<ChunkId, NodeId>,
    /// Total bytes currently swapped
    pub total_swapped_bytes: u64,
    /// Number of successful swaps
    pub successful_swaps: u64,
    /// Number of rejected swaps
    pub rejected_swaps: u64,
}

impl SwapState {
    /// Create new swap state
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a pending proposal
    pub fn record_proposal(&mut self, proposal: &SwapProposal) {
        let id = proposal_id(proposal);
        self.pending_proposals.insert(id, proposal.clone());
    }

    /// Remove a pending proposal (after accept or reject)
    pub fn remove_proposal(&mut self, proposal_id: &[u8; 32]) -> Option<SwapProposal> {
        self.pending_proposals.remove(proposal_id)
    }

    /// Record an active swap
    pub fn record_swap(&mut self, chunk_id: ChunkId, partner: NodeId, bytes: u64) {
        self.active_swaps.insert(chunk_id, partner);
        self.total_swapped_bytes += bytes;
        self.successful_swaps += 1;
    }

    /// Remove an active swap (chunk revoked or partner disconnected)
    pub fn remove_swap(&mut self, chunk_id: &ChunkId) -> Option<NodeId> {
        let partner = self.active_swaps.remove(chunk_id);
        if partner.is_some() {
            // Note: we don't decrement total_swapped_bytes as it's cumulative
        }
        partner
    }

    /// Get the swap partner for a chunk
    pub fn get_swap_partner(&self, chunk_id: &ChunkId) -> Option<&NodeId> {
        self.active_swaps.get(chunk_id)
    }

    /// Get statistics
    pub fn stats(&self) -> SwapStats {
        SwapStats {
            pending_count: self.pending_proposals.len(),
            active_count: self.active_swaps.len(),
            total_swapped_bytes: self.total_swapped_bytes,
            successful_swaps: self.successful_swaps,
            rejected_swaps: self.rejected_swaps,
        }
    }
}

/// Swap statistics
#[derive(Debug, Clone)]
pub struct SwapStats {
    /// Number of pending proposals
    pub pending_count: usize,
    /// Number of active swaps
    pub active_count: usize,
    /// Total bytes currently swapped
    pub total_swapped_bytes: u64,
    /// Number of successful swaps
    pub successful_swaps: u64,
    /// Number of rejected swaps
    pub rejected_swaps: u64,
}

/// Compute a proposal ID (blake3 hash of the chunk ID and from_node)
pub fn proposal_id(proposal: &SwapProposal) -> [u8; 32] {
    use blake3;
    let mut input = Vec::with_capacity(32 + 16);
    input.extend_from_slice(&proposal.chunk.id);
    input.extend_from_slice(&proposal.from_node);
    let hash = blake3::hash(&input);
    let mut id = [0u8; 32];
    id.copy_from_slice(hash.as_bytes());
    id
}

/// Create a swap proposal for a chunk
pub fn create_swap_proposal(
    from_node: NodeId,
    chunk: EncryptedChunk,
    master_key: &SymmetricKey,
    lease_duration_secs: u64,
) -> SwapProposal {
    let lease = create_lease(
        &chunk.id,
        master_key,
        lease_duration_secs,
        current_timestamp(),
    );

    // In a pure barter, we don't share the master key
    // The chunk is opaque to the receiver
    // For now, we include an empty encrypted_master_key
    // In a real implementation, this would be encrypted to the receiver's public key
    SwapProposal {
        from_node,
        chunk,
        lease,
        encrypted_master_key: vec![],
    }
}

/// Create a swap acceptance
pub fn create_swap_accept(
    from_node: NodeId,
    chunk: EncryptedChunk,
    master_key: &SymmetricKey,
    proposal_id: [u8; 32],
    lease_duration_secs: u64,
) -> SwapAccept {
    let lease = create_lease(
        &chunk.id,
        master_key,
        lease_duration_secs,
        current_timestamp(),
    );

    SwapAccept {
        from_node,
        chunk,
        lease,
        proposal_id,
        encrypted_master_key: vec![],
    }
}

/// Create a swap rejection
pub fn create_swap_reject(
    from_node: NodeId,
    proposal_id: [u8; 32],
    reason: SwapRejectReason,
) -> SwapReject {
    SwapReject {
        from_node,
        proposal_id,
        reason,
    }
}

/// Validate a swap proposal
///
/// Checks:
/// 1. Chunk size is correct (1 MiB + 16 byte tag)
/// 2. Lease is valid
pub fn validate_swap_proposal(
    proposal: &SwapProposal,
    expected_chunk_size: usize,
    current_time: u64,
) -> Result<(), SwapRejectReason> {
    // Check chunk size
    if proposal.chunk.data.len() != expected_chunk_size {
        return Err(SwapRejectReason::InvalidChunkSize);
    }

    // Check lease
    if !is_lease_valid(&proposal.lease, current_time) {
        return Err(SwapRejectReason::InvalidLease);
    }

    Ok(())
}

/// A node's storage capacity configuration
#[derive(Debug, Clone)]
pub struct StorageCapacity {
    /// Maximum bytes this node will store for others
    pub max_bytes: u64,
    /// Current bytes stored for others
    pub current_bytes: u64,
    /// Maximum chunks from a single peer
    pub max_chunks_per_peer: usize,
}

impl StorageCapacity {
    /// Create new capacity config
    pub fn new(max_bytes: u64) -> Self {
        Self {
            max_bytes,
            current_bytes: 0,
            max_chunks_per_peer: 100,
        }
    }

    /// Check if we can accept a chunk
    pub fn can_accept(&self, chunk_size: u64, peer_chunks: usize) -> bool {
        if self.current_bytes + chunk_size > self.max_bytes {
            return false;
        }
        if peer_chunks >= self.max_chunks_per_peer {
            return false;
        }
        true
    }

    /// Record accepting a chunk
    pub fn record_accept(&mut self, chunk_size: u64) {
        self.current_bytes += chunk_size;
    }

    /// Record removing a chunk
    pub fn record_remove(&mut self, chunk_size: u64) {
        self.current_bytes = self.current_bytes.saturating_sub(chunk_size);
    }
}

/// Decision function: should this node accept a swap proposal?
///
/// Considers:
/// 1. Available storage capacity
/// 2. Number of chunks already from this peer
/// 3. Chunk validity
/// 4. Peer's credit (from accounting)
pub fn decide_on_swap(
    proposal: &SwapProposal,
    capacity: &StorageCapacity,
    peer_chunks: usize,
    expected_chunk_size: usize,
    current_time: u64,
) -> Result<(), SwapRejectReason> {
    // Validate the proposal
    validate_swap_proposal(proposal, expected_chunk_size, current_time)?;

    // Check capacity
    if !capacity.can_accept(proposal.chunk.data.len() as u64, peer_chunks) {
        if peer_chunks >= capacity.max_chunks_per_peer {
            return Err(SwapRejectReason::TooManyFromPeer);
        }
        return Err(SwapRejectReason::NoCapacity);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CHUNK_SIZE, encrypt_chunk, EncryptedChunk};
    use static_crypto::{SymmetricKey, NonceBytes};
    use rand::RngCore;

    fn random_node_id() -> NodeId {
        let mut id = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut id);
        id
    }

    fn random_chunk() -> EncryptedChunk {
        let master = SymmetricKey::random();
        let nonce = NonceBytes::random();
        let plaintext = vec![0xABu8; 100];
        encrypt_chunk(&master, &nonce, 0, &plaintext).unwrap()
    }

    #[test]
    fn test_swap_proposal_creation() {
        let node_id = random_node_id();
        let chunk = random_chunk();
        let master = SymmetricKey::random();

        let proposal = create_swap_proposal(
            node_id,
            chunk.clone(),
            &master,
            DEFAULT_LEASE_DURATION_SECS,
        );

        assert_eq!(proposal.from_node, node_id);
        assert_eq!(proposal.chunk.id, chunk.id);
        assert!(is_lease_valid(&proposal.lease, current_timestamp()));
    }

    #[test]
    fn test_swap_accept_creation() {
        let node_id = random_node_id();
        let chunk = random_chunk();
        let master = SymmetricKey::random();
        let proposal_id = [0x42u8; 32];

        let accept = create_swap_accept(
            node_id,
            chunk.clone(),
            &master,
            proposal_id,
            DEFAULT_LEASE_DURATION_SECS,
        );

        assert_eq!(accept.from_node, node_id);
        assert_eq!(accept.chunk.id, chunk.id);
        assert_eq!(accept.proposal_id, proposal_id);
        assert!(is_lease_valid(&accept.lease, current_timestamp()));
    }

    #[test]
    fn test_swap_reject_creation() {
        let node_id = random_node_id();
        let proposal_id = [0x42u8; 32];

        let reject = create_swap_reject(node_id, proposal_id, SwapRejectReason::NoCapacity);

        assert_eq!(reject.from_node, node_id);
        assert_eq!(reject.proposal_id, proposal_id);
        assert_eq!(reject.reason, SwapRejectReason::NoCapacity);
    }

    #[test]
    fn test_proposal_id_deterministic() {
        let node_id = random_node_id();
        let chunk = random_chunk();
        let master = SymmetricKey::random();

        let proposal1 = create_swap_proposal(node_id, chunk.clone(), &master, 3600);
        let proposal2 = create_swap_proposal(node_id, chunk, &master, 3600);

        let id1 = proposal_id(&proposal1);
        let id2 = proposal_id(&proposal2);

        assert_eq!(id1, id2);
    }

    #[test]
    fn test_proposal_id_different_for_different_chunks() {
        let node_id = random_node_id();
        let chunk1 = random_chunk();
        let chunk2 = random_chunk();
        let master = SymmetricKey::random();

        let proposal1 = create_swap_proposal(node_id, chunk1, &master, 3600);
        let proposal2 = create_swap_proposal(node_id, chunk2, &master, 3600);

        let id1 = proposal_id(&proposal1);
        let id2 = proposal_id(&proposal2);

        assert_ne!(id1, id2);
    }

    #[test]
    fn test_validate_valid_proposal() {
        let node_id = random_node_id();
        let chunk = random_chunk();
        let master = SymmetricKey::random();

        let proposal = create_swap_proposal(node_id, chunk, &master, 3600);

        let result = validate_swap_proposal(&proposal, CHUNK_SIZE + 16, current_timestamp());
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_invalid_chunk_size() {
        let node_id = random_node_id();
        let chunk = random_chunk();
        let master = SymmetricKey::random();

        let proposal = create_swap_proposal(node_id, chunk, &master, 3600);

        // Wrong expected size
        let result = validate_swap_proposal(&proposal, 512, current_timestamp());
        assert_eq!(result.unwrap_err(), SwapRejectReason::InvalidChunkSize);
    }

    #[test]
    fn test_validate_expired_lease() {
        let node_id = random_node_id();
        let chunk = random_chunk();
        let master = SymmetricKey::random();

        let proposal = create_swap_proposal(node_id, chunk, &master, 3600);

        // Check with time far in the future
        let future_time = current_timestamp() + 7200;
        let result = validate_swap_proposal(&proposal, CHUNK_SIZE + 16, future_time);
        assert_eq!(result.unwrap_err(), SwapRejectReason::InvalidLease);
    }

    #[test]
    fn test_storage_capacity_can_accept() {
        let mut capacity = StorageCapacity::new(1024 * 1024 * 10); // 10 MB
        assert!(capacity.can_accept(1024 * 1024, 0));
        capacity.record_accept(1024 * 1024 * 9);
        assert!(capacity.can_accept(1024 * 1024, 0));
        capacity.record_accept(1024 * 1024);
        // Now at 10 MB, shouldn't accept more
        assert!(!capacity.can_accept(1024 * 1024, 0));
    }

    #[test]
    fn test_storage_capacity_max_per_peer() {
        let capacity = StorageCapacity::new(1024 * 1024 * 1000);
        // max_chunks_per_peer defaults to 100
        assert!(capacity.can_accept(1024, 99));
        assert!(!capacity.can_accept(1024, 100));
    }

    #[test]
    fn test_decide_on_swap_accept() {
        let node_id = random_node_id();
        let chunk = random_chunk();
        let master = SymmetricKey::random();
        let capacity = StorageCapacity::new(1024 * 1024 * 100);

        let proposal = create_swap_proposal(node_id, chunk, &master, 3600);

        let result = decide_on_swap(&proposal, &capacity, 0, CHUNK_SIZE + 16, current_timestamp());
        assert!(result.is_ok());
    }

    #[test]
    fn test_decide_on_swap_no_capacity() {
        let node_id = random_node_id();
        let chunk = random_chunk();
        let master = SymmetricKey::random();
        let capacity = StorageCapacity::new(1024 * 100); // Only 100 KB

        let proposal = create_swap_proposal(node_id, chunk, &master, 3600);

        let result = decide_on_swap(&proposal, &capacity, 0, CHUNK_SIZE + 16, current_timestamp());
        assert_eq!(result.unwrap_err(), SwapRejectReason::NoCapacity);
    }

    #[test]
    fn test_decide_on_swap_too_many_from_peer() {
        let node_id = random_node_id();
        let chunk = random_chunk();
        let master = SymmetricKey::random();
        let capacity = StorageCapacity::new(1024 * 1024 * 1000);

        let proposal = create_swap_proposal(node_id, chunk, &master, 3600);

        let result = decide_on_swap(&proposal, &capacity, 100, CHUNK_SIZE + 16, current_timestamp());
        assert_eq!(result.unwrap_err(), SwapRejectReason::TooManyFromPeer);
    }

    #[test]
    fn test_swap_state_tracking() {
        let mut state = SwapState::new();
        let node_id = random_node_id();
        let chunk = random_chunk();
        let master = SymmetricKey::random();

        let proposal = create_swap_proposal(node_id, chunk.clone(), &master, 3600);
        let _id = proposal_id(&proposal);

        state.record_proposal(&proposal);
        assert_eq!(state.pending_proposals.len(), 1);

        state.record_swap(chunk.id, node_id, chunk.data.len() as u64);
        assert_eq!(state.active_swaps.len(), 1);
        assert_eq!(state.total_swapped_bytes, chunk.data.len() as u64);
        assert_eq!(state.successful_swaps, 1);

        state.remove_swap(&chunk.id);
        assert_eq!(state.active_swaps.len(), 0);
    }

    #[test]
    fn test_swap_stats() {
        let mut state = SwapState::new();
        let node_id = random_node_id();
        let chunk = random_chunk();
        let master = SymmetricKey::random();

        let proposal = create_swap_proposal(node_id, chunk, &master, 3600);
        state.record_proposal(&proposal);

        let stats = state.stats();
        assert_eq!(stats.pending_count, 1);
        assert_eq!(stats.active_count, 0);
        assert_eq!(stats.successful_swaps, 0);
    }
}
