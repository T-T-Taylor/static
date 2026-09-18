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
    integrity::{MerkleProof, MerkleRoot},
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

/// Default timeout for pending 2-phase swaps (5 minutes)
///
/// A pending swap that has not committed within this window is aborted:
/// reserved capacity is released and no chunks are stored, preserving
/// the 1:1 barter ratio when a peer crashes mid-swap.
pub const DEFAULT_PENDING_SWAP_TIMEOUT_SECS: u64 = 300;

/// Maximum concurrent pending 2-phase swaps (DoS bound)
///
/// Each pending swap buffers two ~1 MiB chunk payloads until commit;
/// the cap bounds the memory a flood of proposals can pin.
pub const MAX_PENDING_SWAPS: usize = 32;

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
    /// Merkle root of the content this chunk belongs to
    pub content_root: MerkleRoot,
    /// Merkle proof verifying this chunk against `content_root`
    pub merkle_proof: MerkleProof,
    /// Content ID this chunk belongs to (`blake3(content_public_key)`)
    ///
    /// Binds the offered chunk to a content identity so receivers can
    /// attribute garbage-flooding to a stable key.
    #[serde(default)]
    pub content_id: [u8; 32],
    /// Ed25519 public key authorizing this content (`blake3(pub) == content_id`)
    #[serde(default)]
    pub content_public_key: [u8; 32],
    /// Ed25519 signature over [`SwapProposal::signing_bytes`]
    /// (`content_root || chunk.id || from_node`), 64 bytes when signed.
    ///
    /// Empty (`vec![]`) means unsigned — [`validate_swap_proposal`]
    /// rejects it with [`SwapRejectReason::InvalidSignature`].
    #[serde(default)]
    pub content_signature: Vec<u8>,
}

impl SwapProposal {
    /// Bytes covered by the content signature.
    ///
    /// `content_root (32) || chunk.id (32) || from_node (16)` = 80 bytes.
    /// Binds the offered chunk and its Merkle root to the sender so a
    /// captured signature cannot be replayed for a different root/chunk.
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(32 + 32 + 16);
        buf.extend_from_slice(&self.content_root);
        buf.extend_from_slice(&self.chunk.id);
        buf.extend_from_slice(&self.from_node);
        buf
    }

    /// Sign this proposal with the content signing key.
    ///
    /// Sets `content_public_key` from the key, `content_id` to
    /// `blake3(public_key)` (so the binding check passes), and
    /// `content_signature` to the Ed25519 signature over
    /// [`SwapProposal::signing_bytes`].
    pub fn sign(&mut self, content_signing_key: &ed25519_dalek::SigningKey) {
        use ed25519_dalek::Signer;
        let public = content_signing_key.verifying_key().to_bytes();
        self.content_public_key = public;
        self.content_id = *blake3::hash(&public).as_bytes();
        let sig = content_signing_key.sign(&self.signing_bytes());
        self.content_signature = sig.to_bytes().to_vec();
    }

    /// Verify the content binding and signature.
    ///
    /// Returns `Ok(())` when `blake3(content_public_key) == content_id`
    /// and the Ed25519 signature over [`SwapProposal::signing_bytes`]
    /// verifies. Returns `Err(InvalidSignature)` otherwise.
    pub fn verify_content_signature(&self) -> Result<(), SwapRejectReason> {
        // Binding: content_id must be blake3(content_public_key).
        let expected = *blake3::hash(&self.content_public_key).as_bytes();
        if expected != self.content_id {
            return Err(SwapRejectReason::InvalidSignature);
        }
        // Signature must be 64 bytes.
        if self.content_signature.len() != 64 {
            return Err(SwapRejectReason::InvalidSignature);
        }
        use ed25519_dalek::{Signature, Verifier, VerifyingKey};
        let Ok(public) = VerifyingKey::from_bytes(&self.content_public_key) else {
            return Err(SwapRejectReason::InvalidSignature);
        };
        let mut arr = [0u8; 64];
        arr.copy_from_slice(&self.content_signature);
        let sig = Signature::from_bytes(&arr);
        public
            .verify(&self.signing_bytes(), &sig)
            .map_err(|_| SwapRejectReason::InvalidSignature)
    }
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

/// A swap commit (2-phase commit finalize)
///
/// Sent after the sender holds the peer's chunk: committing means
/// "I have your chunk and am ready to store it". The receiver finalizes
/// the swap (stores chunks, converts the reservation) once it has both
/// sent and received a commit for the proposal.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SwapCommit {
    /// The proposal ID this commit is for
    pub proposal_id: [u8; 32],
    /// The sending node's ID
    pub from_node: NodeId,
}

/// A swap abort (2-phase commit cancel)
///
/// Sent when a side cannot proceed (capacity missing, retrieval failed)
/// or by the timeout sweep after [`DEFAULT_PENDING_SWAP_TIMEOUT_SECS`].
/// Both sides release reserved capacity and store nothing.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SwapAbort {
    /// The proposal ID this abort is for
    pub proposal_id: [u8; 32],
    /// The sending node's ID
    pub from_node: NodeId,
    /// Reason for abort
    pub reason: String,
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
    /// Chunk failed Merkle proof verification
    InvalidIntegrityTag = 4,
    /// Content binding or Ed25519 signature invalid
    ///
    /// Covers: `blake3(content_public_key) != content_id`, signature
    /// length != 64, unparseable public key, or failed verification
    /// over `content_root || chunk.id || from_node`.
    InvalidSignature = 5,
}

impl TryFrom<u8> for SwapRejectReason {
    type Error = StorageError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(SwapRejectReason::NoCapacity),
            1 => Ok(SwapRejectReason::TooManyFromPeer),
            2 => Ok(SwapRejectReason::InvalidChunkSize),
            3 => Ok(SwapRejectReason::InvalidLease),
            4 => Ok(SwapRejectReason::InvalidIntegrityTag),
            5 => Ok(SwapRejectReason::InvalidSignature),
            _ => Err(StorageError::InvalidChunkSize {
                expected: 0,
                actual: value as usize,
            }),
        }
    }
}

/// State of a pending 2-phase swap
///
/// Created in the prepare phase (proposal sent / accept sent): capacity
/// is reserved and chunk payloads are buffered, but nothing is stored in
/// the chunk holder. Storage happens only when both sides have sent and
/// received their [`SwapCommit`]-equivalent (see `SwapState::mark_commit_
/// received` callers); any failure or timeout aborts and releases the
/// reservation.
#[derive(Debug, Clone)]
pub struct PendingSwap {
    /// The proposal ID
    pub proposal_id: [u8; 32],
    /// The peer we're swapping with
    pub peer: NodeId,
    /// The chunk we offered (stays in our holder; tracked for the swap)
    pub our_chunk_id: ChunkId,
    /// The chunk they offered
    pub their_chunk_id: ChunkId,
    /// The chunk data they offered (held in reserve until commit)
    ///
    /// Swaps carry chunks in-band (inside [`SwapProposal`] /
    /// [`SwapAccept`]), so this is populated as soon as the peer's
    /// message arrives; it is held here — not in the chunk holder —
    /// until the commit phase.
    pub their_chunk_data: Vec<u8>,
    /// Size of the reserved capacity (bytes of `their_chunk_data`)
    pub reserved_bytes: u64,
    /// Whether we've received their chunk (always true for in-band swaps)
    pub received_their_chunk: bool,
    /// Whether we've sent our commit
    pub sent_commit: bool,
    /// Whether we've received their commit
    pub received_commit: bool,
    /// The renewal token for the held chunk (from the proposal's lease)
    pub renewal_token: [u8; 32],
    /// The lease expiry for the held chunk (from the proposal's lease)
    pub lease_expires_at: u64,
    /// The content owner's Ed25519 public key (for heartbeat verification)
    pub content_pub_key: [u8; 32],
    /// When the swap was initiated (for timeout)
    pub started_at: u64,
}

/// Local state for tracking pending and active swaps
#[derive(Debug, Clone, Default)]
pub struct SwapState {
    /// Pending proposals (proposal_id -> proposal)
    pub pending_proposals: HashMap<[u8; 32], SwapProposal>,
    /// Pending 2-phase swaps (proposal_id -> pending swap)
    pub pending_swaps: HashMap<[u8; 32], PendingSwap>,
    /// Active swaps (chunk_id -> swap partner node ID)
    pub active_swaps: HashMap<ChunkId, NodeId>,
    /// Completed 2-phase swaps (proposal IDs, for cleanup/inspection)
    pub completed_swaps: Vec<[u8; 32]>,
    /// Aborted 2-phase swaps (proposal IDs, for cleanup/inspection)
    pub aborted_swaps: Vec<[u8; 32]>,
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

    /// Track a pending 2-phase swap (prepare phase)
    pub fn start_pending_swap(&mut self, swap: PendingSwap) {
        self.pending_swaps.insert(swap.proposal_id, swap);
    }

    /// Mark their chunk as received in a pending swap
    pub fn mark_chunk_received(&mut self, proposal_id: &[u8; 32]) {
        if let Some(swap) = self.pending_swaps.get_mut(proposal_id) {
            swap.received_their_chunk = true;
        }
    }

    /// Mark our commit as sent in a pending swap
    pub fn mark_commit_sent(&mut self, proposal_id: &[u8; 32]) {
        if let Some(swap) = self.pending_swaps.get_mut(proposal_id) {
            swap.sent_commit = true;
        }
    }

    /// Mark their commit as received in a pending swap
    ///
    /// Returns `true` when the swap is ready to finalize (we have both
    /// sent and received our commit, and hold their chunk).
    pub fn mark_commit_received(&mut self, proposal_id: &[u8; 32]) -> bool {
        match self.pending_swaps.get_mut(proposal_id) {
            Some(swap) => {
                swap.received_commit = true;
                swap.sent_commit && swap.received_their_chunk
            }
            None => false,
        }
    }

    /// Finalize a pending swap: record it as active and completed
    ///
    /// Removes the pending entry, records the held chunk under the
    /// partner in `active_swaps`, and appends the proposal ID to
    /// `completed_swaps`. Returns the removed pending swap so the caller
    /// can release the reservation and store the chunk.
    pub fn complete_swap(&mut self, proposal_id: &[u8; 32]) -> Option<PendingSwap> {
        let swap = self.pending_swaps.remove(proposal_id)?;
        self.active_swaps.insert(swap.their_chunk_id, swap.peer);
        self.successful_swaps += 1;
        self.total_swapped_bytes += swap.reserved_bytes;
        self.completed_swaps.push(*proposal_id);
        Some(swap)
    }

    /// Abort a pending swap
    ///
    /// Removes the pending entry and appends the proposal ID to
    /// `aborted_swaps`. Returns the removed pending swap so the caller
    /// can release the reserved capacity.
    pub fn abort_swap(&mut self, proposal_id: &[u8; 32]) -> Option<PendingSwap> {
        let swap = self.pending_swaps.remove(proposal_id)?;
        self.aborted_swaps.push(*proposal_id);
        Some(swap)
    }

    /// Get a pending swap
    pub fn get_pending_swap(&self, proposal_id: &[u8; 32]) -> Option<&PendingSwap> {
        self.pending_swaps.get(proposal_id)
    }

    /// Expire pending swaps that exceeded the timeout
    ///
    /// Removes and returns every pending swap older than
    /// `timeout_secs` so the caller can notify the peer and release its
    /// reserved capacity. Expired proposal IDs are recorded in
    /// `aborted_swaps`.
    pub fn expire_pending_swaps(&mut self, current_time: u64, timeout_secs: u64) -> Vec<PendingSwap> {
        let expired: Vec<[u8; 32]> = self
            .pending_swaps
            .iter()
            .filter(|(_, swap)| current_time.saturating_sub(swap.started_at) > timeout_secs)
            .map(|(id, _)| *id)
            .collect();
        expired
            .into_iter()
            .filter_map(|id| {
                self.aborted_swaps.push(id);
                self.pending_swaps.remove(&id)
            })
            .collect()
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

/// Compute a proposal ID (C2 idempotency).
///
/// `blake3(chunk.id || from_node || content_root || lease.expires_at_be)`.
///
/// Binding the content root and lease expiry makes the ID unique per
/// (chunk, sender, content, lease): re-proposals for the same lease
/// deduplicate to the same ID, while a renewed lease (different
/// `expires_at`) yields a different ID so stale accepts/rejects cannot
/// be replayed across leases.
pub fn proposal_id(proposal: &SwapProposal) -> [u8; 32] {
    use blake3;
    let mut input = Vec::with_capacity(32 + 16 + 32 + 8);
    input.extend_from_slice(&proposal.chunk.id);
    input.extend_from_slice(&proposal.from_node);
    input.extend_from_slice(&proposal.content_root);
    input.extend_from_slice(&proposal.lease.expires_at.to_be_bytes());
    let hash = blake3::hash(&input);
    let mut id = [0u8; 32];
    id.copy_from_slice(hash.as_bytes());
    id
}

/// Create a swap proposal for a chunk
///
/// `content_root` and `merkle_proof` come from
/// [`crate::integrity::generate_proofs`] over the content's chunks; the
/// receiver verifies them before accepting.
///
/// `content_id` must be `blake3(content_public_key)`. If
/// `content_signing_key` is `Some`, the proposal is signed over
/// [`SwapProposal::signing_bytes`] (Ed25519 over
/// `content_root || chunk.id || from_node`); if `None`, the signature
/// is left empty (unsigned — validation rejects it, useful for tests
/// that exercise the unsigned path).
pub fn create_swap_proposal(
    from_node: NodeId,
    chunk: EncryptedChunk,
    master_key: &SymmetricKey,
    lease_duration_secs: u64,
    content_root: MerkleRoot,
    merkle_proof: MerkleProof,
    content_id: [u8; 32],
    content_public_key: [u8; 32],
    content_signing_key: Option<&ed25519_dalek::SigningKey>,
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
    let mut proposal = SwapProposal {
        from_node,
        chunk,
        lease,
        encrypted_master_key: vec![],
        content_root,
        merkle_proof,
        content_id,
        content_public_key,
        content_signature: vec![],
    };

    // Sign if a key is provided, preserving the caller-supplied
    // content_id / content_public_key so binding mismatches stay
    // detectable (validation rejects them with InvalidSignature).
    if let Some(sk) = content_signing_key {
        use ed25519_dalek::Signer;
        let sig = sk.sign(&proposal.signing_bytes());
        proposal.content_signature = sig.to_bytes().to_vec();
    }

    proposal
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
/// 3. Content binding: `blake3(content_public_key) == content_id`
/// 4. Content signature: 64-byte Ed25519 over
///    `content_root || chunk.id || from_node` verifies
/// 5. Chunk verifies against its Merkle proof and content root
///
/// Binding/signature failures return [`SwapRejectReason::InvalidSignature`].
/// The signature is checked before the Merkle proof so a tampered
/// `content_root` fails as `InvalidSignature` (auth), not
/// `InvalidIntegrityTag`.
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

    // Check content auth (binding + signature) before Merkle so root
    // tampering is attributed as an auth failure.
    proposal.verify_content_signature()?;

    // Check integrity: the chunk must hash up the Merkle proof to the
    // content root, proving it is a real shard of some published content
    // (garbage-flooding protection).
    if !crate::integrity::verify_chunk(
        &proposal.chunk,
        &proposal.merkle_proof,
        &proposal.content_root,
    ) {
        return Err(SwapRejectReason::InvalidIntegrityTag);
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
    /// Bytes reserved by pending 2-phase swaps
    ///
    /// Reserved capacity is not yet stored (the chunk waits in the
    /// pending swap), so it lives outside `current_bytes` — the periodic
    /// `reconcile()` snap to holder reality would otherwise erase it.
    /// `can_accept` counts it so concurrent swaps cannot overcommit.
    pub reserved_bytes: u64,
    /// Maximum chunks from a single peer
    pub max_chunks_per_peer: usize,
}

impl StorageCapacity {
    /// Create new capacity config
    pub fn new(max_bytes: u64) -> Self {
        Self {
            max_bytes,
            current_bytes: 0,
            reserved_bytes: 0,
            max_chunks_per_peer: 100,
        }
    }

    /// Check if we can accept a chunk
    ///
    /// Counts stored bytes plus bytes reserved by pending swaps.
    pub fn can_accept(&self, chunk_size: u64, peer_chunks: usize) -> bool {
        if self.current_bytes + self.reserved_bytes + chunk_size > self.max_bytes {
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

    /// Reserve capacity for a pending 2-phase swap
    pub fn reserve(&mut self, chunk_size: u64) {
        self.reserved_bytes += chunk_size;
    }

    /// Release reserved capacity (abort or commit finalization)
    ///
    /// `store` selects the destination: on abort the bytes simply
    /// disappear; on commit they move into `current_bytes` because the
    /// chunk is now actually stored.
    pub fn release_reserved(&mut self, chunk_size: u64, store: bool) {
        self.reserved_bytes = self.reserved_bytes.saturating_sub(chunk_size);
        if store {
            self.current_bytes += chunk_size;
        }
    }

    /// Reconcile current_bytes with the actual bytes held
    ///
    /// `current_bytes` is a cached counter maintained by the store/remove
    /// paths; any missed update drifts it from reality. Call this with
    /// `ChunkHolder::total_bytes()` before capacity decisions (and
    /// periodically as a safety net) so `can_accept()` decides on truth.
    pub fn reconcile(&mut self, actual_bytes: u64) {
        self.current_bytes = actual_bytes;
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

    fn random_chunk_id() -> ChunkId {
        let mut id = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut id);
        id
    }

    fn random_chunk() -> EncryptedChunk {
        let master = SymmetricKey::random();
        let nonce = NonceBytes::random();
        let plaintext = vec![0xABu8; 100];
        encrypt_chunk(&master, &nonce, 0, &plaintext).unwrap()
    }

    /// Build a swap proposal carrying a genuine Merkle proof for its chunk
    ///
    /// Validation now verifies integrity and content auth, so every
    /// proposal under test must carry a real proof generated over the
    /// chunk data plus a valid Ed25519 content signature with
    /// `content_id = blake3(content_public_key)`.
    fn make_proposal(
        node_id: NodeId,
        chunk: EncryptedChunk,
        master: &SymmetricKey,
        lease_duration_secs: u64,
    ) -> SwapProposal {
        let (root, proofs) = crate::integrity::generate_proofs(std::slice::from_ref(&chunk));
        // Fresh content keypair per proposal (random, no rand-version
        // coupling via from_bytes).
        let mut sk_bytes = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut sk_bytes);
        let content_signing_key = ed25519_dalek::SigningKey::from_bytes(&sk_bytes);
        let content_public_key = content_signing_key.verifying_key().to_bytes();
        let content_id = *blake3::hash(&content_public_key).as_bytes();
        create_swap_proposal(
            node_id,
            chunk,
            master,
            lease_duration_secs,
            root,
            proofs.into_iter().next().expect("one chunk, one proof"),
            content_id,
            content_public_key,
            Some(&content_signing_key),
        )
    }

    /// Build an unsigned proposal (empty signature) for negative tests.
    fn make_unsigned_proposal(
        node_id: NodeId,
        chunk: EncryptedChunk,
        master: &SymmetricKey,
        lease_duration_secs: u64,
    ) -> SwapProposal {
        let (root, proofs) = crate::integrity::generate_proofs(std::slice::from_ref(&chunk));
        let mut sk_bytes = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut sk_bytes);
        let sk = ed25519_dalek::SigningKey::from_bytes(&sk_bytes);
        let pk = sk.verifying_key().to_bytes();
        let cid = *blake3::hash(&pk).as_bytes();
        create_swap_proposal(
            node_id,
            chunk,
            master,
            lease_duration_secs,
            root,
            proofs.into_iter().next().expect("one chunk, one proof"),
            cid,
            pk,
            None,
        )
    }

    #[test]
    fn test_swap_proposal_creation() {
        let node_id = random_node_id();
        let chunk = random_chunk();
        let master = SymmetricKey::random();

        let proposal = make_proposal(
            node_id,
            chunk.clone(),
            &master,
            DEFAULT_LEASE_DURATION_SECS,
        );

        assert_eq!(proposal.from_node, node_id);
        assert_eq!(proposal.chunk.id, chunk.id);
        assert!(is_lease_valid(&proposal.lease, current_timestamp()));
        // Content auth is bound: blake3(pub) == content_id and signature verifies.
        assert_eq!(*blake3::hash(&proposal.content_public_key).as_bytes(), proposal.content_id);
        assert_eq!(proposal.content_signature.len(), 64);
        assert!(proposal.verify_content_signature().is_ok());
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

        let proposal1 = make_proposal(node_id, chunk.clone(), &master, 3600);
        let mut proposal2 = make_proposal(node_id, chunk, &master, 3600);
        // C2 id includes lease expiry; both minted within the same second
        // in practice, but normalize to rule out a 1s-boundary flake.
        proposal2.lease.expires_at = proposal1.lease.expires_at;

        let id1 = proposal_id(&proposal1);
        let id2 = proposal_id(&proposal2);

        assert_eq!(id1, id2);
    }

    #[test]
    fn test_proposal_id_changes_with_lease_expiry() {
        // C2: same chunk/peer/root but different lease expiry => different ID.
        let node_id = random_node_id();
        let chunk = random_chunk();
        let master = SymmetricKey::random();

        let proposal1 = make_proposal(node_id, chunk.clone(), &master, 3600);
        let mut proposal2 = make_proposal(node_id, chunk, &master, 3600);
        // Force identical except expiry, then diverge expiry.
        proposal2.content_root = proposal1.content_root;
        proposal2.lease.expires_at = proposal1.lease.expires_at;
        assert_eq!(proposal_id(&proposal1), proposal_id(&proposal2));

        proposal2.lease.expires_at = proposal1.lease.expires_at.saturating_add(1000);
        assert_ne!(proposal_id(&proposal1), proposal_id(&proposal2));
    }

    #[test]
    fn test_proposal_id_different_for_different_chunks() {
        let node_id = random_node_id();
        let chunk1 = random_chunk();
        let chunk2 = random_chunk();
        let master = SymmetricKey::random();

        let proposal1 = make_proposal(node_id, chunk1, &master, 3600);
        let proposal2 = make_proposal(node_id, chunk2, &master, 3600);

        let id1 = proposal_id(&proposal1);
        let id2 = proposal_id(&proposal2);

        assert_ne!(id1, id2);
    }

    #[test]
    fn test_validate_valid_proposal() {
        let node_id = random_node_id();
        let chunk = random_chunk();
        let master = SymmetricKey::random();

        let proposal = make_proposal(node_id, chunk, &master, 3600);

        let result = validate_swap_proposal(&proposal, CHUNK_SIZE + 16, current_timestamp());
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_invalid_chunk_size() {
        let node_id = random_node_id();
        let chunk = random_chunk();
        let master = SymmetricKey::random();

        let proposal = make_proposal(node_id, chunk, &master, 3600);

        // Wrong expected size
        let result = validate_swap_proposal(&proposal, 512, current_timestamp());
        assert_eq!(result.unwrap_err(), SwapRejectReason::InvalidChunkSize);
    }

    #[test]
    fn test_validate_expired_lease() {
        let node_id = random_node_id();
        let chunk = random_chunk();
        let master = SymmetricKey::random();

        let proposal = make_proposal(node_id, chunk, &master, 3600);

        // Check with time far in the future
        let future_time = current_timestamp() + 7200;
        let result = validate_swap_proposal(&proposal, CHUNK_SIZE + 16, future_time);
        assert_eq!(result.unwrap_err(), SwapRejectReason::InvalidLease);
    }

    #[test]
    fn test_validate_valid_integrity() {
        // A proposal carrying a genuine proof passes the integrity check.
        let node_id = random_node_id();
        let chunk = random_chunk();
        let master = SymmetricKey::random();

        let proposal = make_proposal(node_id, chunk, &master, 3600);

        let result = validate_swap_proposal(&proposal, CHUNK_SIZE + 16, current_timestamp());
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_invalid_integrity() {
        // Tampering with the chunk data after proof generation (same size,
        // different bytes) fails with InvalidIntegrityTag.
        let node_id = random_node_id();
        let master = SymmetricKey::random();

        let proposal = make_proposal(node_id, random_chunk(), &master, 3600);
        let mut tampered = proposal;
        tampered.chunk.data[0] ^= 0xFF;

        let result = validate_swap_proposal(&tampered, CHUNK_SIZE + 16, current_timestamp());
        assert_eq!(result.unwrap_err(), SwapRejectReason::InvalidIntegrityTag);
    }

    #[test]
    fn test_validate_tampered_root_fails_signature() {
        // Tampering with content_root after signing breaks the Ed25519
        // signature (which covers root||chunk.id||from_node), so it must
        // fail as InvalidSignature (checked before Merkle).
        let node_id = random_node_id();
        let master = SymmetricKey::random();

        let proposal = make_proposal(node_id, random_chunk(), &master, 3600);
        let mut tampered = proposal;
        tampered.content_root[0] ^= 0xFF;

        let result = validate_swap_proposal(&tampered, CHUNK_SIZE + 16, current_timestamp());
        assert_eq!(result.unwrap_err(), SwapRejectReason::InvalidSignature);
    }

    #[test]
    fn test_validate_wrong_content_id_binding_fails() {
        // content_id must equal blake3(content_public_key); a mismatched
        // binding fails even with an otherwise valid signature.
        let node_id = random_node_id();
        let master = SymmetricKey::random();

        let proposal = make_proposal(node_id, random_chunk(), &master, 3600);
        let mut tampered = proposal;
        tampered.content_id = [0xFFu8; 32];

        let result = validate_swap_proposal(&tampered, CHUNK_SIZE + 16, current_timestamp());
        assert_eq!(result.unwrap_err(), SwapRejectReason::InvalidSignature);
    }

    #[test]
    fn test_validate_unsigned_proposal_fails() {
        // Empty signature (created with None key) is rejected.
        let node_id = random_node_id();
        let master = SymmetricKey::random();

        let proposal = make_unsigned_proposal(node_id, random_chunk(), &master, 3600);
        assert!(proposal.content_signature.is_empty());

        let result = validate_swap_proposal(&proposal, CHUNK_SIZE + 16, current_timestamp());
        assert_eq!(result.unwrap_err(), SwapRejectReason::InvalidSignature);
    }

    #[test]
    fn test_validate_tampered_signature_fails() {
        // Flipping a signature byte breaks verification.
        let node_id = random_node_id();
        let master = SymmetricKey::random();

        let proposal = make_proposal(node_id, random_chunk(), &master, 3600);
        let mut tampered = proposal;
        tampered.content_signature[0] ^= 0xFF;

        let result = validate_swap_proposal(&tampered, CHUNK_SIZE + 16, current_timestamp());
        assert_eq!(result.unwrap_err(), SwapRejectReason::InvalidSignature);
    }

    #[test]
    fn test_reject_reason_try_from_signature() {
        assert_eq!(
            SwapRejectReason::try_from(5).unwrap(),
            SwapRejectReason::InvalidSignature
        );
        assert!(SwapRejectReason::try_from(6).is_err());
    }

    #[test]
    fn test_signing_bytes_binds_root_chunk_and_sender() {
        let node_id = random_node_id();
        let master = SymmetricKey::random();
        let proposal = make_proposal(node_id, random_chunk(), &master, 3600);

        let bytes = proposal.signing_bytes();
        assert_eq!(bytes.len(), 32 + 32 + 16);
        assert_eq!(&bytes[..32], &proposal.content_root);
        assert_eq!(&bytes[32..64], &proposal.chunk.id);
        assert_eq!(&bytes[64..], &proposal.from_node);
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
    fn test_reconcile_updates_current_bytes() {
        let mut capacity = StorageCapacity::new(1024 * 1024 * 10);
        capacity.record_accept(1024 * 1024 * 5);
        assert_eq!(capacity.current_bytes, 1024 * 1024 * 5);
        // Holder reality differs (e.g. untracked publish) -> snap to truth.
        capacity.reconcile(1024 * 1024 * 8);
        assert_eq!(capacity.current_bytes, 1024 * 1024 * 8);
        capacity.reconcile(0);
        assert_eq!(capacity.current_bytes, 0);
    }

    #[test]
    fn test_record_accept_increments() {
        let mut capacity = StorageCapacity::new(1024 * 1024 * 10);
        assert_eq!(capacity.current_bytes, 0);
        capacity.record_accept(100);
        capacity.record_accept(200);
        assert_eq!(capacity.current_bytes, 300);
    }

    #[test]
    fn test_record_remove_decrements() {
        let mut capacity = StorageCapacity::new(1024 * 1024 * 10);
        capacity.record_accept(1000);
        capacity.record_remove(400);
        assert_eq!(capacity.current_bytes, 600);
        // Saturates at zero instead of underflowing.
        capacity.record_remove(10_000);
        assert_eq!(capacity.current_bytes, 0);
    }

    #[test]
    fn test_can_accept_after_reconcile() {
        let mut capacity = StorageCapacity::new(1024);
        // Drifted counter claims full -> rejects.
        capacity.record_accept(1024);
        assert!(!capacity.can_accept(1, 0));
        // Reality is half-full -> reconcile restores correct decisions.
        capacity.reconcile(512);
        assert!(capacity.can_accept(512, 0));
        assert!(!capacity.can_accept(513, 0));
    }

    #[test]
    fn test_decide_on_swap_accept() {
        let node_id = random_node_id();
        let chunk = random_chunk();
        let master = SymmetricKey::random();
        let capacity = StorageCapacity::new(1024 * 1024 * 100);

        let proposal = make_proposal(node_id, chunk, &master, 3600);

        let result = decide_on_swap(&proposal, &capacity, 0, CHUNK_SIZE + 16, current_timestamp());
        assert!(result.is_ok());
    }

    #[test]
    fn test_decide_on_swap_no_capacity() {
        let node_id = random_node_id();
        let chunk = random_chunk();
        let master = SymmetricKey::random();
        let capacity = StorageCapacity::new(1024 * 100); // Only 100 KB

        let proposal = make_proposal(node_id, chunk, &master, 3600);

        let result = decide_on_swap(&proposal, &capacity, 0, CHUNK_SIZE + 16, current_timestamp());
        assert_eq!(result.unwrap_err(), SwapRejectReason::NoCapacity);
    }

    #[test]
    fn test_decide_on_swap_too_many_from_peer() {
        let node_id = random_node_id();
        let chunk = random_chunk();
        let master = SymmetricKey::random();
        let capacity = StorageCapacity::new(1024 * 1024 * 1000);

        let proposal = make_proposal(node_id, chunk, &master, 3600);

        let result = decide_on_swap(&proposal, &capacity, 100, CHUNK_SIZE + 16, current_timestamp());
        assert_eq!(result.unwrap_err(), SwapRejectReason::TooManyFromPeer);
    }

    #[test]
    fn test_swap_state_tracking() {
        let mut state = SwapState::new();
        let node_id = random_node_id();
        let chunk = random_chunk();
        let master = SymmetricKey::random();

        let proposal = make_proposal(node_id, chunk.clone(), &master, 3600);
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

        let proposal = make_proposal(node_id, chunk, &master, 3600);
        state.record_proposal(&proposal);

        let stats = state.stats();
        assert_eq!(stats.pending_count, 1);
        assert_eq!(stats.active_count, 0);
        assert_eq!(stats.successful_swaps, 0);
    }

    fn test_pending_swap(peer: NodeId, proposal_id: [u8; 32], chunk_id: ChunkId) -> PendingSwap {
        PendingSwap {
            proposal_id,
            peer,
            our_chunk_id: random_chunk_id(),
            their_chunk_id: chunk_id,
            their_chunk_data: vec![0xEEu8; 64],
            reserved_bytes: 64,
            received_their_chunk: true,
            sent_commit: false,
            received_commit: false,
            renewal_token: [0u8; 32],
            lease_expires_at: current_timestamp() + 3600,
            content_pub_key: [0x11u8; 32],
            started_at: current_timestamp(),
        }
    }

    #[test]
    fn test_pending_swap_creation() {
        // PendingSwap is tracked and retrievable by proposal ID.
        let peer = random_node_id();
        let chunk_id = random_chunk_id();
        let pid = [0x01u8; 32];
        let mut state = SwapState::new();

        state.start_pending_swap(test_pending_swap(peer, pid, chunk_id));
        assert_eq!(state.pending_swaps.len(), 1);

        let swap = state.get_pending_swap(&pid).unwrap();
        assert_eq!(swap.peer, peer);
        assert_eq!(swap.their_chunk_id, chunk_id);
        assert!(swap.received_their_chunk);
        assert!(!swap.sent_commit);
        assert!(!swap.received_commit);
    }

    #[test]
    fn test_pending_swap_both_commit() {
        // Both commits -> swap completes: chunk becomes active, pending
        // entry removed, completion recorded.
        let peer = random_node_id();
        let chunk_id = random_chunk_id();
        let pid = [0x02u8; 32];
        let mut state = SwapState::new();
        state.start_pending_swap(test_pending_swap(peer, pid, chunk_id));

        state.mark_commit_sent(&pid);
        // Their chunk arrived in-band with the proposal, so receiving
        // their commit completes the swap on our side immediately.
        assert!(state.mark_commit_received(&pid));
        let swap = state.complete_swap(&pid).unwrap();

        assert!(state.get_pending_swap(&pid).is_none());
        assert_eq!(state.get_swap_partner(&chunk_id), Some(&peer));
        assert_eq!(state.successful_swaps, 1);
        assert_eq!(state.total_swapped_bytes, 64);
        assert_eq!(state.completed_swaps, vec![pid]);
        assert_eq!(swap.their_chunk_data, vec![0xEEu8; 64]);
    }

    #[test]
    fn test_pending_swap_one_aborts() {
        // Abort -> swap cancelled; the caller releases reserved capacity.
        let peer = random_node_id();
        let chunk_id = random_chunk_id();
        let pid = [0x03u8; 32];
        let mut state = SwapState::new();
        state.start_pending_swap(test_pending_swap(peer, pid, chunk_id));

        state.mark_commit_sent(&pid);
        let mut capacity = StorageCapacity::new(1024);
        capacity.reserve(64);
        assert_eq!(capacity.reserved_bytes, 64);

        state.abort_swap(&pid);
        capacity.release_reserved(64, false);

        assert!(state.get_pending_swap(&pid).is_none());
        assert!(state.get_swap_partner(&chunk_id).is_none());
        assert_eq!(state.aborted_swaps, vec![pid]);
        assert_eq!(capacity.reserved_bytes, 0);
        assert_eq!(capacity.current_bytes, 0);
    }

    #[test]
    fn test_pending_swap_timeout() {
        // Timeout -> swap cancelled and returned for abort handling.
        let peer = random_node_id();
        let chunk_id = random_chunk_id();
        let pid = [0x04u8; 32];
        let mut state = SwapState::new();
        state.start_pending_swap(test_pending_swap(peer, pid, chunk_id));

        // Not yet timed out.
        assert!(state.expire_pending_swaps(current_timestamp(), 300).is_empty());
        assert!(state.get_pending_swap(&pid).is_some());

        // Past the timeout: expired and moved to aborted.
        let expired = state.expire_pending_swaps(current_timestamp() + 301, 300);
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0].proposal_id, pid);
        assert!(state.get_pending_swap(&pid).is_none());
        assert_eq!(state.aborted_swaps, vec![pid]);
    }

    #[test]
    fn test_pending_swap_partial_commit() {
        // Commit sent but never received (peer crashed): swap stays
        // pending until it expires.
        let peer = random_node_id();
        let chunk_id = random_chunk_id();
        let pid = [0x05u8; 32];
        let mut state = SwapState::new();
        state.start_pending_swap(test_pending_swap(peer, pid, chunk_id));

        state.mark_commit_sent(&pid);
        assert!(state.get_pending_swap(&pid).unwrap().sent_commit);
        assert!(!state.get_pending_swap(&pid).unwrap().received_commit);
        assert!(state.get_pending_swap(&pid).is_some());
        // Nothing finalized: no active swap, no completion record.
        assert!(state.get_swap_partner(&chunk_id).is_none());
        assert!(state.completed_swaps.is_empty());
    }

    #[test]
    fn test_capacity_reservation_gates_accept() {
        // Reserved bytes count against can_accept but not current_bytes;
        // commit moves them into current_bytes, abort discards them.
        let mut capacity = StorageCapacity::new(1024);
        capacity.record_accept(512);
        capacity.reserve(384);

        // current+reserved+chunk must fit: 512+384+128 = 1024 fits,
        // 512+384+256 = 1152 does not.
        assert!(capacity.can_accept(128, 0));
        assert!(!capacity.can_accept(256, 0));
        assert_eq!(capacity.current_bytes, 512);

        // reconcile snaps stored bytes without touching reservations.
        capacity.reconcile(600);
        assert_eq!(capacity.current_bytes, 600);
        assert_eq!(capacity.reserved_bytes, 384);
        assert!(!capacity.can_accept(64, 0));

        // Commit: reservation converts to stored bytes.
        capacity.release_reserved(384, true);
        assert_eq!(capacity.reserved_bytes, 0);
        assert_eq!(capacity.current_bytes, 984);

        // Abort: reservation simply disappears.
        capacity.reserve(128);
        capacity.release_reserved(128, false);
        assert_eq!(capacity.reserved_bytes, 0);
        assert_eq!(capacity.current_bytes, 984);

        // Release is saturating (no underflow).
        capacity.release_reserved(9999, false);
        assert_eq!(capacity.reserved_bytes, 0);
    }
}
