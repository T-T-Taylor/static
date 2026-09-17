//! Chunk repair protocol
//!
//! Detects when chunks have been lost (due to node departures) and
//! triggers re-replication from the remaining erasure-coded shards.
//!
//! The repair process:
//! 1. The content owner periodically sends "health check" requests
//!    to the network, asking how many copies of each chunk exist.
//! 2. If the count drops below the minimum threshold, the owner
//!    retrieves the remaining shards and reconstructs the missing ones.
//! 3. The reconstructed shards are re-distributed to new nodes.
//!
//! This ensures content persists even as nodes join and leave the network.

use crate::{
    EncryptedChunk, ChunkId, ContentId, ContentManifest,
    StorageError, erasure_decode, erasure_encode,
};
use std::collections::HashMap;

/// Minimum number of copies required for each chunk
pub const MIN_CHUNK_COPIES: usize = 3;

/// Maximum number of copies to maintain
pub const MAX_CHUNK_COPIES: usize = 10;

/// Result of a health check for a single chunk
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ChunkHealth {
    /// The chunk ID
    pub chunk_id: ChunkId,
    /// Number of known copies on the network
    pub copy_count: usize,
    /// Whether this chunk needs repair
    pub needs_repair: bool,
}

/// Result of a health check for all chunks in content
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ContentHealth {
    /// The content ID
    pub content_id: ContentId,
    /// Health status for each chunk
    pub chunk_health: Vec<ChunkHealth>,
    /// Whether the content is healthy (all chunks have enough copies)
    pub is_healthy: bool,
    /// Whether the content is recoverable (enough shards exist)
    pub is_recoverable: bool,
}

/// Check the health of content based on reported copy counts
pub fn check_content_health(
    content_id: ContentId,
    manifest: &ContentManifest,
    copy_counts: &HashMap<ChunkId, usize>,
) -> ContentHealth {
    let mut chunk_health = Vec::new();
    let mut is_healthy = true;

    for chunk_id in &manifest.chunk_ids {
        let count = copy_counts.get(chunk_id).copied().unwrap_or(0);
        let needs_repair = count < MIN_CHUNK_COPIES;
        
        if needs_repair {
            is_healthy = false;
        }

        chunk_health.push(ChunkHealth {
            chunk_id: *chunk_id,
            copy_count: count,
            needs_repair,
        });
    }

    // Check if we have enough shards to recover
    // With erasure coding (K=10, M=5), we need at least K=10 shards
    // to reconstruct. If fewer than K shards exist, content is unrecoverable.
    let total_shards = chunk_health.iter()
        .filter(|h| h.copy_count > 0)
        .count();
    let is_recoverable = total_shards >= manifest.data_shards;

    ContentHealth {
        content_id,
        chunk_health,
        is_healthy,
        is_recoverable,
    }
}

/// Determine which chunks need to be repaired
pub fn get_chunks_needing_repair(health: &ContentHealth) -> Vec<ChunkId> {
    health.chunk_health.iter()
        .filter(|h| h.needs_repair)
        .map(|h| h.chunk_id)
        .collect()
}

/// Reconstruct a missing chunk from remaining shards
///
/// Given a set of available shards (some may be None/missing),
/// reconstructs the missing shards using erasure coding.
/// Returns the reconstructed data shards.
pub fn reconstruct_missing_chunks(
    available_shards: &[Option<EncryptedChunk>],
    data_shards: usize,
    parity_shards: usize,
) -> Result<Vec<EncryptedChunk>, StorageError> {
    erasure_decode(available_shards, data_shards, parity_shards)
}

/// Create new parity shards after re-distribution
///
/// After reconstructing missing data shards, new parity shards
/// can be generated for additional redundancy.
pub fn regenerate_parity_shards(
    data_chunks: &[EncryptedChunk],
    data_shards: usize,
    parity_shards: usize,
) -> Result<Vec<EncryptedChunk>, StorageError> {
    erasure_encode(data_chunks, data_shards, parity_shards)
}

/// Repair plan for a piece of content
#[derive(Debug, Clone)]
pub struct RepairPlan {
    /// Content ID being repaired
    pub content_id: ContentId,
    /// Chunks that need to be reconstructed
    pub chunks_to_reconstruct: Vec<ChunkId>,
    /// Chunks that need to be re-distributed (existing + reconstructed)
    pub chunks_to_redistribute: Vec<ChunkId>,
    /// Target number of copies for each chunk
    pub target_copies: usize,
}

/// Create a repair plan based on health status
pub fn create_repair_plan(
    health: &ContentHealth,
    manifest: &ContentManifest,
) -> Option<RepairPlan> {
    if health.is_healthy {
        return None; // No repair needed
    }

    if !health.is_recoverable {
        return None; // Cannot repair - not enough shards
    }

    let chunks_to_reconstruct = get_chunks_needing_repair(health);
    
    // All chunks need to be re-distributed to maintain target copies
    let chunks_to_redistribute: Vec<ChunkId> = manifest.chunk_ids.clone();

    Some(RepairPlan {
        content_id: health.content_id,
        chunks_to_reconstruct,
        chunks_to_redistribute,
        target_copies: MIN_CHUNK_COPIES,
    })
}

/// Track repair state for content
#[derive(Debug, Clone)]
pub struct RepairState {
    /// Content IDs that are currently being repaired
    pub active_repairs: HashMap<ContentId, RepairPlan>,
    /// Content IDs that have been repaired successfully
    pub completed_repairs: Vec<ContentId>,
    /// Content IDs that could not be repaired (unrecoverable)
    pub failed_repairs: Vec<ContentId>,
}

impl RepairState {
    /// Create new repair state
    pub fn new() -> Self {
        Self {
            active_repairs: HashMap::new(),
            completed_repairs: Vec::new(),
            failed_repairs: Vec::new(),
        }
    }

    /// Start a repair for content
    pub fn start_repair(&mut self, plan: RepairPlan) {
        self.active_repairs.insert(plan.content_id, plan);
    }

    /// Mark a repair as complete
    pub fn complete_repair(&mut self, content_id: &ContentId) {
        self.active_repairs.remove(content_id);
        self.completed_repairs.push(*content_id);
    }

    /// Mark a repair as failed
    pub fn fail_repair(&mut self, content_id: &ContentId) {
        self.active_repairs.remove(content_id);
        self.failed_repairs.push(*content_id);
    }

    /// Check if content is currently being repaired
    pub fn is_being_repaired(&self, content_id: &ContentId) -> bool {
        self.active_repairs.contains_key(content_id)
    }

    /// Get the number of active repairs
    pub fn active_count(&self) -> usize {
        self.active_repairs.len()
    }

    /// Get the number of completed repairs
    pub fn completed_count(&self) -> usize {
        self.completed_repairs.len()
    }

    /// Get the number of failed repairs
    pub fn failed_count(&self) -> usize {
        self.failed_repairs.len()
    }
}

impl Default for RepairState {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{encrypt_chunk, CHUNK_SIZE};
    use static_crypto::{SymmetricKey, NonceBytes};
    use rand::RngCore;

    fn random_chunk_id() -> ChunkId {
        let mut id = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut id);
        id
    }

    fn random_content_id() -> ContentId {
        let mut id = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut id);
        id
    }

    fn create_test_manifest(num_chunks: usize, data_shards: usize, parity_shards: usize) -> ContentManifest {
        let mut chunk_ids = Vec::with_capacity(num_chunks);
        for _ in 0..num_chunks {
            chunk_ids.push(random_chunk_id());
        }

        ContentManifest {
            content_id: random_content_id(),
            encrypted_master_key: vec![],
            chunk_ids,
            original_size: num_chunks as u64 * CHUNK_SIZE as u64,
            data_shards,
            parity_shards,
            nonce: [0u8; 12],
        }
    }

    #[test]
    fn test_content_health_all_healthy() {
        let manifest = create_test_manifest(5, 5, 0);
        let mut copy_counts = HashMap::new();
        for chunk_id in &manifest.chunk_ids {
            copy_counts.insert(*chunk_id, MIN_CHUNK_COPIES + 1);
        }

        let health = check_content_health(manifest.content_id, &manifest, &copy_counts);
        
        assert!(health.is_healthy);
        assert!(health.is_recoverable);
        assert_eq!(health.chunk_health.len(), 5);
        assert!(health.chunk_health.iter().all(|h| !h.needs_repair));
    }

    #[test]
    fn test_content_health_needs_repair() {
        // 10 data + 5 parity = 15 total. Losing 3 leaves 12 (>= 10), so recoverable.
        let manifest = create_test_manifest(15, 10, 5);
        let mut copy_counts = HashMap::new();
        
        // 12 chunks have at least 3 copies (healthy), 3 chunks need repair
        copy_counts.insert(manifest.chunk_ids[0], 5);
        copy_counts.insert(manifest.chunk_ids[1], 1); // Needs repair
        copy_counts.insert(manifest.chunk_ids[2], 3);
        copy_counts.insert(manifest.chunk_ids[3], 0); // Needs repair (lost!)
        copy_counts.insert(manifest.chunk_ids[4], 4);
        copy_counts.insert(manifest.chunk_ids[5], 3);
        copy_counts.insert(manifest.chunk_ids[6], 3);
        copy_counts.insert(manifest.chunk_ids[7], 3);
        copy_counts.insert(manifest.chunk_ids[8], 3);
        copy_counts.insert(manifest.chunk_ids[9], 3);
        copy_counts.insert(manifest.chunk_ids[10], 3);
        copy_counts.insert(manifest.chunk_ids[11], 3);
        copy_counts.insert(manifest.chunk_ids[12], 0); // Needs repair (lost!)
        copy_counts.insert(manifest.chunk_ids[13], 3);
        copy_counts.insert(manifest.chunk_ids[14], 3);

        let health = check_content_health(manifest.content_id, &manifest, &copy_counts);
        
        assert!(!health.is_healthy);
        assert!(health.is_recoverable);
        
        let needing_repair = get_chunks_needing_repair(&health);
        assert_eq!(needing_repair.len(), 3);
        assert!(needing_repair.contains(&manifest.chunk_ids[1]));
        assert!(needing_repair.contains(&manifest.chunk_ids[3]));
        assert!(needing_repair.contains(&manifest.chunk_ids[12]));
    }

    #[test]
    fn test_content_health_unrecoverable() {
        let manifest = create_test_manifest(15, 10, 5); // 10 data + 5 parity
        let mut copy_counts = HashMap::new();
        
        // Only 5 chunks have copies (less than data_shards=10)
        for i in 0..5 {
            copy_counts.insert(manifest.chunk_ids[i], 2);
        }

        let health = check_content_health(manifest.content_id, &manifest, &copy_counts);
        
        assert!(!health.is_healthy);
        assert!(!health.is_recoverable); // Not enough shards to reconstruct
    }

    #[test]
    fn test_create_repair_plan_when_healthy() {
        let manifest = create_test_manifest(5, 5, 0);
        let mut copy_counts = HashMap::new();
        for chunk_id in &manifest.chunk_ids {
            copy_counts.insert(*chunk_id, MIN_CHUNK_COPIES + 1);
        }

        let health = check_content_health(manifest.content_id, &manifest, &copy_counts);
        let plan = create_repair_plan(&health, &manifest);

        assert!(plan.is_none()); // No repair needed
    }

    #[test]
    fn test_create_repair_plan_when_needs_repair() {
        let manifest = create_test_manifest(15, 10, 5);
        let mut copy_counts = HashMap::new();
        
        // 12 chunks have copies (enough to reconstruct: >= data_shards=10)
        for i in 0..12 {
            copy_counts.insert(manifest.chunk_ids[i], 3);
        }
        // 3 chunks are lost (below threshold)
        for i in 12..15 {
            copy_counts.insert(manifest.chunk_ids[i], 0);
        }

        let health = check_content_health(manifest.content_id, &manifest, &copy_counts);
        let plan = create_repair_plan(&health, &manifest);

        assert!(plan.is_some());
        let plan = plan.unwrap();
        assert_eq!(plan.content_id, manifest.content_id);
        assert_eq!(plan.chunks_to_reconstruct.len(), 3);
        assert_eq!(plan.target_copies, MIN_CHUNK_COPIES);
    }

    #[test]
    fn test_create_repair_plan_when_unrecoverable() {
        let manifest = create_test_manifest(15, 10, 5);
        let mut copy_counts = HashMap::new();
        
        // Only 5 chunks have copies (less than data_shards=10)
        for i in 0..5 {
            copy_counts.insert(manifest.chunk_ids[i], 2);
        }

        let health = check_content_health(manifest.content_id, &manifest, &copy_counts);
        let plan = create_repair_plan(&health, &manifest);

        assert!(plan.is_none()); // Cannot repair
    }

    #[test]
    fn test_repair_state_tracking() {
        let mut state = RepairState::new();
        let content_id = random_content_id();
        
        assert!(!state.is_being_repaired(&content_id));
        assert_eq!(state.active_count(), 0);

        let plan = RepairPlan {
            content_id,
            chunks_to_reconstruct: vec![random_chunk_id()],
            chunks_to_redistribute: vec![random_chunk_id()],
            target_copies: MIN_CHUNK_COPIES,
        };
        
        state.start_repair(plan);
        assert!(state.is_being_repaired(&content_id));
        assert_eq!(state.active_count(), 1);

        state.complete_repair(&content_id);
        assert!(!state.is_being_repaired(&content_id));
        assert_eq!(state.active_count(), 0);
        assert_eq!(state.completed_count(), 1);
    }

    #[test]
    fn test_repair_state_failed() {
        let mut state = RepairState::new();
        let content_id = random_content_id();
        
        let plan = RepairPlan {
            content_id,
            chunks_to_reconstruct: vec![random_chunk_id()],
            chunks_to_redistribute: vec![random_chunk_id()],
            target_copies: MIN_CHUNK_COPIES,
        };
        
        state.start_repair(plan);
        state.fail_repair(&content_id);
        
        assert!(!state.is_being_repaired(&content_id));
        assert_eq!(state.failed_count(), 1);
    }

    #[test]
    fn test_reconstruct_missing_chunks() {
        let master = SymmetricKey::random();
        let nonce = NonceBytes::random();
        
        // Create 10 data chunks
        let mut chunks = Vec::new();
        for i in 0..DEFAULT_DATA_SHARDS {
            let chunk = encrypt_chunk(&master, &nonce, i, &random_bytes(100)).unwrap();
            chunks.push(chunk);
        }

        // Encode with erasure coding
        let encoded = erasure_encode(&chunks, DEFAULT_DATA_SHARDS, DEFAULT_PARITY_SHARDS).unwrap();
        assert_eq!(encoded.len(), DEFAULT_DATA_SHARDS + DEFAULT_PARITY_SHARDS);

        // Drop 5 shards (we still have 10, which is enough)
        let mut shards: Vec<Option<EncryptedChunk>> = encoded.into_iter()
            .map(Some)
            .collect();
        
        shards[2] = None;
        shards[5] = None;
        shards[8] = None;
        shards[11] = None;
        shards[13] = None;

        // Reconstruct
        let reconstructed = reconstruct_missing_chunks(&shards, DEFAULT_DATA_SHARDS, DEFAULT_PARITY_SHARDS).unwrap();
        assert_eq!(reconstructed.len(), DEFAULT_DATA_SHARDS);

        // Verify reconstructed data matches original
        for i in 0..DEFAULT_DATA_SHARDS {
            assert_eq!(reconstructed[i].data, chunks[i].data);
        }
    }

    fn random_bytes(len: usize) -> Vec<u8> {
        let mut bytes = vec![0u8; len];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        bytes
    }
}
