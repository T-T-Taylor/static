//! Hot storage rotation — Freenet-style chunk migration
//!
//! Periodically rotates a percentage of held chunks to different nodes via
//! the existing swap barter system, and caches retrieved chunks locally.
//! No node retains the same chunks long-term, which improves deniability
//! (an adversary compromising a node sees a shifting set) and lets
//! popular chunks naturally distribute toward demand (load balancing).
//!
//! Design notes:
//! - Location rotation only: chunk bytes and IDs never change, so
//!   manifests stay immutable.
//! - Percentage-based epochs: a configurable share rotates per epoch,
//!   avoiding bandwidth spikes from rotating everything at once.
//! - Lease awareness: only chunks with healthy remaining lease time rotate.
//! - Capacity awareness: cached chunks count toward the 1:1 storage
//!   contribution; LRU eviction bounds the cache.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use crate::ChunkId;
use std::collections::HashMap;

/// Configuration for chunk rotation
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RotationConfig {
    /// Whether rotation is enabled
    pub enabled: bool,
    /// Rotation epoch duration in seconds (default: 86400 = 24 hours)
    pub epoch_duration_secs: u64,
    /// Percentage of chunks to rotate per epoch (0-100, default: 10).
    /// Values above 100 are clamped to 100.
    pub rotation_percentage: u8,
    /// Whether to cache retrieved chunks locally (Freenet-style)
    pub enable_caching: bool,
    /// Maximum number of cached chunks to hold (0 = unlimited, default: 100)
    pub max_cached_chunks: usize,
    /// Minimum lease remaining before rotating (seconds, default: 3600 = 1 hour)
    pub min_lease_remaining_secs: u64,
}

impl Default for RotationConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            epoch_duration_secs: 86400,
            rotation_percentage: 10,
            enable_caching: true,
            max_cached_chunks: 100,
            min_lease_remaining_secs: 3600,
        }
    }
}

/// Maximum rotation-history entries retained (H14 bound, FIFO eviction).
pub const MAX_ROTATION_HISTORY: usize = 10_000;

/// State tracking for chunk rotation
#[derive(Debug, Clone, Default)]
pub struct RotationState {    /// Chunks that have been rotated and when (chunk_id -> unix timestamp)
    pub rotation_history: HashMap<ChunkId, u64>,
    /// Cached chunks (chunk_id -> when cached, unix timestamp)
    pub cached_chunks: HashMap<ChunkId, u64>,
    /// Last epoch timestamp
    pub last_epoch: u64,
    /// Total rotations performed
    pub total_rotations: u64,
    /// Total chunks cached
    pub total_cached: u64,
}

impl RotationState {
    /// Create new rotation state
    pub fn new() -> Self {
        Self::default()
    }

    /// Check if it's time for a rotation epoch
    pub fn should_rotate(&self, config: &RotationConfig, current_time: u64) -> bool {
        if !config.enabled {
            return false;
        }
        current_time.saturating_sub(self.last_epoch) >= config.epoch_duration_secs
    }

    /// Record a rotation (H14: bounded history).
    pub fn record_rotation(&mut self, chunk_id: ChunkId, current_time: u64) {
        if self.rotation_history.len() >= MAX_ROTATION_HISTORY {
            if let Some(k) = self.rotation_history.keys().next().copied() {
                self.rotation_history.remove(&k);
            }
        }
        self.rotation_history.insert(chunk_id, current_time);
        self.total_rotations += 1;
    }

    /// Record a cached chunk
    pub fn record_cache(&mut self, chunk_id: ChunkId, current_time: u64) {
        self.cached_chunks.insert(chunk_id, current_time);
        self.total_cached += 1;
    }

    /// Remove a cached chunk
    pub fn remove_cache(&mut self, chunk_id: &ChunkId) {
        self.cached_chunks.remove(chunk_id);
    }

    /// Check if a chunk was recently rotated (within the current epoch)
    pub fn was_recently_rotated(
        &self,
        chunk_id: &ChunkId,
        current_time: u64,
        epoch_duration: u64,
    ) -> bool {
        if let Some(&rotation_time) = self.rotation_history.get(chunk_id) {
            current_time.saturating_sub(rotation_time) < epoch_duration
        } else {
            false
        }
    }

    /// Get chunks to rotate this epoch (selects a percentage of eligible chunks)
    ///
    /// Excludes recently-rotated chunks so rotation spreads across epochs.
    /// The percentage is clamped to 100.
    pub fn select_chunks_for_rotation(
        &self,
        all_chunks: &[ChunkId],
        config: &RotationConfig,
        current_time: u64,
    ) -> Vec<ChunkId> {
        let mut eligible: Vec<ChunkId> = all_chunks
            .iter()
            .filter(|chunk_id| {
                // Skip recently rotated chunks
                !self.was_recently_rotated(chunk_id, current_time, config.epoch_duration_secs)
            })
            .cloned()
            .collect();

        // Shuffle for random selection
        use rand::seq::SliceRandom;
        eligible.shuffle(&mut rand::thread_rng());

        // Select the percentage (clamped to 100)
        let pct = config.rotation_percentage.min(100) as usize;
        let count = (eligible.len() * pct) / 100;
        eligible.into_iter().take(count).collect()
    }

    /// Get the least recently used cached chunk (for eviction)
    pub fn lru_cached_chunk(&self) -> Option<ChunkId> {
        self.cached_chunks
            .iter()
            .min_by_key(|(_, &time)| time)
            .map(|(id, _)| *id)
    }

    /// Get rotation statistics
    pub fn stats(&self) -> RotationStats {
        RotationStats {
            total_rotations: self.total_rotations,
            total_cached: self.total_cached,
            active_cached: self.cached_chunks.len(),
            rotation_history_size: self.rotation_history.len(),
        }
    }
}

/// Rotation statistics
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RotationStats {
    /// Total rotations performed
    pub total_rotations: u64,
    /// Total chunks cached (all time)
    pub total_cached: u64,
    /// Currently cached chunks
    pub active_cached: usize,
    /// Size of rotation history
    pub rotation_history_size: usize,
}

/// Errors that can occur during rotation
#[derive(Debug, thiserror::Error)]
pub enum RotationError {
    /// No eligible chunks to rotate
    #[error("no eligible chunks to rotate")]
    NoEligibleChunks,
    /// No peers available for rotation
    #[error("no peers available for rotation")]
    NoPeersAvailable,
    /// Storage capacity exceeded
    #[error("storage capacity exceeded")]
    CapacityExceeded,
    /// Lease too short to rotate
    #[error("lease too short to rotate")]
    LeaseTooShort,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn chunk_id(byte: u8) -> ChunkId {
        [byte; 32]
    }

    #[test]
    fn test_rotation_config_default() {
        let config = RotationConfig::default();
        assert!(config.enabled);
        assert_eq!(config.epoch_duration_secs, 86400);
        assert_eq!(config.rotation_percentage, 10);
        assert!(config.enable_caching);
        assert_eq!(config.max_cached_chunks, 100);
        assert_eq!(config.min_lease_remaining_secs, 3600);
    }

    #[test]
    fn test_should_rotate() {
        let config = RotationConfig::default();
        let mut state = RotationState::new();

        // last_epoch = 0, current far beyond epoch -> rotate
        assert!(state.should_rotate(&config, 100_000));

        // Just rotated -> no
        state.last_epoch = 100_000;
        assert!(!state.should_rotate(&config, 100_000 + 100));

        // Epoch passed -> yes
        assert!(state.should_rotate(&config, 100_000 + 86400));

        // Disabled -> never
        let off = RotationConfig { enabled: false, ..Default::default() };
        assert!(!off.enabled);
        assert!(!state.should_rotate(&off, u64::MAX));
    }

    #[test]
    fn test_record_rotation() {
        let mut state = RotationState::new();
        assert_eq!(state.total_rotations, 0);

        state.record_rotation(chunk_id(1), 1000);
        state.record_rotation(chunk_id(2), 2000);

        assert_eq!(state.total_rotations, 2);
        assert_eq!(state.rotation_history.len(), 2);
        assert_eq!(state.rotation_history[&chunk_id(1)], 1000);
    }

    #[test]
    fn test_was_recently_rotated() {
        let mut state = RotationState::new();
        let id = chunk_id(7);

        // Never rotated -> false
        assert!(!state.was_recently_rotated(&id, 10_000, 86400));

        state.record_rotation(id, 10_000);
        // Within epoch -> true
        assert!(state.was_recently_rotated(&id, 10_000 + 100, 86400));
        // Past epoch -> false
        assert!(!state.was_recently_rotated(&id, 10_000 + 86400, 86400));
    }

    #[test]
    fn test_select_chunks_for_rotation() {
        let mut state = RotationState::new();
        let all: Vec<ChunkId> = (0..20u8).map(chunk_id).collect();
        let config = RotationConfig::default(); // 10% of 20 = 2

        let selected = state.select_chunks_for_rotation(&all, &config, 50_000);
        assert_eq!(selected.len(), 2);

        // Recently rotated chunks are excluded: rotate 18 of 20 this epoch,
        // leaving only 2 eligible -> 10% of 2 = 0.
        for id in all.iter().take(18) {
            state.record_rotation(*id, 50_000);
        }
        let selected = state.select_chunks_for_rotation(&all, &config, 50_001);
        assert_eq!(selected.len(), 0);

        // Percentage above 100 clamps to 100: all 20 eligible next epoch.
        let aggressive = RotationConfig { rotation_percentage: 250, ..Default::default() };
        let selected = state.select_chunks_for_rotation(&all, &aggressive, 50_000 + 86401);
        assert_eq!(selected.len(), 20);
    }

    #[test]
    fn test_lru_cached_chunk() {
        let mut state = RotationState::new();
        assert!(state.lru_cached_chunk().is_none());

        state.record_cache(chunk_id(1), 3000);
        state.record_cache(chunk_id(2), 1000);
        state.record_cache(chunk_id(3), 2000);

        assert_eq!(state.lru_cached_chunk(), Some(chunk_id(2)));
    }

    #[test]
    fn test_caching_and_eviction() {
        let mut state = RotationState::new();
        let config = RotationConfig { max_cached_chunks: 2, ..Default::default() };

        state.record_cache(chunk_id(1), 1000);
        state.record_cache(chunk_id(2), 2000);
        assert_eq!(state.cached_chunks.len(), 2);

        // Over limit: evict LRU (chunk 1), cache chunk 3.
        while state.cached_chunks.len() >= config.max_cached_chunks {
            if let Some(lru) = state.lru_cached_chunk() {
                state.remove_cache(&lru);
            } else {
                break;
            }
        }
        state.record_cache(chunk_id(3), 3000);

        assert!(!state.cached_chunks.contains_key(&chunk_id(1)));
        assert!(state.cached_chunks.contains_key(&chunk_id(2)));
        assert!(state.cached_chunks.contains_key(&chunk_id(3)));
        // total_cached counts every cache event, evictions don't decrement it.
        assert_eq!(state.total_cached, 3);
    }

    #[test]
    fn test_rotation_stats() {
        let mut state = RotationState::new();
        state.record_rotation(chunk_id(1), 1000);
        state.record_cache(chunk_id(2), 2000);
        state.record_cache(chunk_id(3), 3000);

        let stats = state.stats();
        assert_eq!(stats.total_rotations, 1);
        assert_eq!(stats.total_cached, 2);
        assert_eq!(stats.active_cached, 2);
        assert_eq!(stats.rotation_history_size, 1);
    }
}
