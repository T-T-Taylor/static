//! Lease and heartbeat protocol for owner control
//!
//! Implements:
//! - Content leases with expiration times
//! - Encrypted heartbeat packets for lease renewal
//! - Owner-controlled content revocation (stop heartbeat = content expires)
//! - Seed node redundancy (multiple nodes can send heartbeats)
//! - Repopulation when nodes go offline (chunks redistributed)
//!
//! The heartbeat is a Sphinx packet indistinguishable from cover traffic.
//! No one can tell that a lease renewal happened. When the owner stops
//! sending heartbeats, the chunks expire and are overwritten via the
//! swap mechanism.

use crate::{
    ChunkId, NodeId, ChunkLease, StorageError,
    create_lease, is_lease_valid,
};
use static_crypto::SymmetricKey;
use rand::rngs::OsRng;
use rand::RngCore;
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

/// Ed25519 signing/verification for owner-authorized heartbeats.
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};

/// Default heartbeat interval (30 minutes)
pub const DEFAULT_HEARTBEAT_INTERVAL_SECS: u64 = 1800;

/// Default lease duration (24 hours - must be > heartbeat interval)
pub const DEFAULT_LEASE_DURATION_SECS: u64 = 86400;

/// Lease renewal grace period (2 hours after expiry before repopulation)
pub const GRACE_PERIOD_SECS: u64 = 7200;

/// Heartbeat message type (Sphinx body dispatch, Phase 1)
pub const MSG_HEARTBEAT: u8 = 0x0A;

/// Get current unix timestamp
fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock went backwards")
        .as_secs()
}

/// A heartbeat packet sent by the content owner
#[derive(Debug, Clone)]
pub struct Heartbeat {
    /// The content ID this heartbeat covers
    pub content_id: [u8; 32],
    /// The renewal token proving ownership
    pub renewal_token: [u8; 32],
    /// The new expiration time
    pub new_expires_at: u64,
    /// The list of chunk IDs to renew
    pub chunk_ids: Vec<ChunkId>,
    /// Nonce to prevent replay
    pub nonce: [u8; 32],
    /// Ed25519 signature from the content owner
    ///
    /// Signs [`Heartbeat::signing_bytes`]
    /// (`content_id || chunk_ids || new_expires_at || nonce`), 64 bytes
    /// when signed. Empty (`vec![]`) means unsigned — processing rejects
    /// it with [`HeartbeatError::InvalidSignature`].
    pub signature: Vec<u8>,
    /// Content owner's Ed25519 public key (for verification by holders)
    ///
    /// `blake3(content_pub_key) == content_id` is enforced, binding the
    /// key to the content identity. Holders additionally compare this
    /// against the key stored in the lease (from the swap proposal).
    pub content_pub_key: [u8; 32],
}

impl Heartbeat {
    /// Create a new (unsigned) heartbeat for a content
    ///
    /// Call [`Heartbeat::sign`] before sending or processing; the
    /// renewal path rejects unsigned heartbeats.
    pub fn new(
        content_id: [u8; 32],
        renewal_token: [u8; 32],
        chunk_ids: Vec<ChunkId>,
        new_duration_secs: u64,
    ) -> Self {
        let mut nonce = [0u8; 32];
        OsRng.fill_bytes(&mut nonce);

        Self {
            content_id,
            renewal_token,
            new_expires_at: current_timestamp() + new_duration_secs,
            chunk_ids,
            nonce,
            signature: Vec::new(),
            content_pub_key: [0u8; 32],
        }
    }

    /// Bytes covered by the owner signature.
    ///
    /// `content_id (32) || chunk_ids (32 each) || new_expires_at (8 BE)
    /// || nonce (32)`. Binds the renewal to the content identity, the
    /// exact chunk set, the expiration and the replay nonce.
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(32 + 32 * self.chunk_ids.len() + 8 + 32);
        buf.extend_from_slice(&self.content_id);
        for chunk_id in &self.chunk_ids {
            buf.extend_from_slice(chunk_id);
        }
        buf.extend_from_slice(&self.new_expires_at.to_be_bytes());
        buf.extend_from_slice(&self.nonce);
        buf
    }

    /// Sign this heartbeat with the content owner's key.
    ///
    /// Sets `content_pub_key` from the key and `signature` to the
    /// Ed25519 signature over [`Heartbeat::signing_bytes`].
    pub fn sign(&mut self, signing_key: &SigningKey) {
        self.content_pub_key = signing_key.verifying_key().to_bytes();
        let sig = signing_key.sign(&self.signing_bytes());
        self.signature = sig.to_bytes().to_vec();
    }

    /// Verify the owner signature and content binding.
    ///
    /// Returns `Ok(())` when `blake3(content_pub_key) == content_id`,
    /// the signature is 64 bytes, and the Ed25519 signature over
    /// [`Heartbeat::signing_bytes`] verifies. Otherwise returns
    /// [`HeartbeatError::InvalidSignature`].
    pub fn verify_signature(&self) -> Result<(), HeartbeatError> {
        // Binding: content_id must be blake3(content_pub_key) so the
        // signing key is pinned to this content identity.
        let expected = *blake3::hash(&self.content_pub_key).as_bytes();
        if expected != self.content_id {
            return Err(HeartbeatError::InvalidSignature);
        }
        if self.signature.len() != 64 {
            return Err(HeartbeatError::InvalidSignature);
        }
        let Ok(public) = VerifyingKey::from_bytes(&self.content_pub_key) else {
            return Err(HeartbeatError::InvalidSignature);
        };
        let mut arr = [0u8; 64];
        arr.copy_from_slice(&self.signature);
        let sig = Signature::from_bytes(&arr);
        public
            .verify(&self.signing_bytes(), &sig)
            .map_err(|_| HeartbeatError::InvalidSignature)
    }

    /// Serialize the heartbeat for transmission
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&self.content_id);
        buf.extend_from_slice(&self.renewal_token);
        buf.extend_from_slice(&self.new_expires_at.to_be_bytes());
        buf.extend_from_slice(&(self.chunk_ids.len() as u32).to_be_bytes());
        for chunk_id in &self.chunk_ids {
            buf.extend_from_slice(chunk_id);
        }
        buf.extend_from_slice(&self.nonce);
        buf.extend_from_slice(&self.content_pub_key);
        buf.extend_from_slice(&(self.signature.len() as u32).to_be_bytes());
        buf.extend_from_slice(&self.signature);
        buf
    }

    /// Deserialize a heartbeat
    pub fn deserialize(data: &[u8]) -> Result<Self, StorageError> {
        if data.len() < 32 + 32 + 8 + 4 + 32 + 32 + 4 {
            return Err(StorageError::InvalidChunkSize {
                expected: 144,
                actual: data.len(),
            });
        }

        let mut offset = 0;
        let mut content_id = [0u8; 32];
        content_id.copy_from_slice(&data[offset..offset + 32]);
        offset += 32;

        let mut renewal_token = [0u8; 32];
        renewal_token.copy_from_slice(&data[offset..offset + 32]);
        offset += 32;

        let new_expires_at = u64::from_be_bytes([
            data[offset], data[offset + 1], data[offset + 2], data[offset + 3],
            data[offset + 4], data[offset + 5], data[offset + 6], data[offset + 7],
        ]);
        offset += 8;

        let chunk_count = u32::from_be_bytes([
            data[offset], data[offset + 1], data[offset + 2], data[offset + 3],
        ]) as usize;
        offset += 4;

        let mut chunk_ids = Vec::with_capacity(chunk_count);
        for _ in 0..chunk_count {
            if offset + 32 > data.len() {
                return Err(StorageError::InvalidChunkSize {
                    expected: offset + 32,
                    actual: data.len(),
                });
            }
            let mut chunk_id = [0u8; 32];
            chunk_id.copy_from_slice(&data[offset..offset + 32]);
            chunk_ids.push(chunk_id);
            offset += 32;
        }

        if offset + 32 + 32 + 4 > data.len() {
            return Err(StorageError::InvalidChunkSize {
                expected: offset + 32 + 32 + 4,
                actual: data.len(),
            });
        }
        let mut nonce = [0u8; 32];
        nonce.copy_from_slice(&data[offset..offset + 32]);
        offset += 32;

        let mut content_pub_key = [0u8; 32];
        content_pub_key.copy_from_slice(&data[offset..offset + 32]);
        offset += 32;

        let sig_len = u32::from_be_bytes([
            data[offset], data[offset + 1], data[offset + 2], data[offset + 3],
        ]) as usize;
        offset += 4;

        // Bound the signature length before allocating (DoS guard); the
        // renewal path only ever accepts exactly 64 bytes.
        if sig_len > 64 || offset + sig_len > data.len() {
            return Err(StorageError::InvalidChunkSize {
                expected: offset + sig_len,
                actual: data.len(),
            });
        }
        let signature = data[offset..offset + sig_len].to_vec();

        Ok(Self {
            content_id,
            renewal_token,
            new_expires_at,
            chunk_ids,
            nonce,
            signature,
            content_pub_key,
        })
    }

    /// Serialize as a Sphinx body payload (type byte + heartbeat fields)
    pub fn wire_serialize(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(1 + self.serialize().len());
        buf.push(MSG_HEARTBEAT);
        buf.extend_from_slice(&self.serialize());
        buf
    }

    /// Deserialize a Sphinx body payload (type byte + heartbeat fields)
    pub fn wire_deserialize(data: &[u8]) -> Result<Self, StorageError> {
        if data.is_empty() || data[0] != MSG_HEARTBEAT {
            return Err(StorageError::InvalidChunkSize {
                expected: MSG_HEARTBEAT as usize,
                actual: data.first().copied().unwrap_or(0) as usize,
            });
        }
        Self::deserialize(&data[1..])
    }
}

/// Lease manager for tracking active leases
#[derive(Clone)]
pub struct LeaseManager {
    /// Active leases (chunk_id -> lease)
    pub leases: HashMap<ChunkId, ChunkLease>,
    /// Content to chunks mapping (content_id -> chunk_ids)
    pub content_chunks: HashMap<[u8; 32], Vec<ChunkId>>,
    /// Seen heartbeat nonces (for replay prevention)
    pub seen_nonces: HashMap<[u8; 32], u64>,
    /// Master keys for content we own (content_id -> master_key)
    pub owned_content: HashMap<[u8; 32], SymmetricKey>,
}

impl LeaseManager {
    /// Create a new lease manager
    pub fn new() -> Self {
        Self {
            leases: HashMap::new(),
            content_chunks: HashMap::new(),
            seen_nonces: HashMap::new(),
            owned_content: HashMap::new(),
        }
    }

    /// Register content we own
    pub fn register_owned_content(
        &mut self,
        content_id: [u8; 32],
        master_key: SymmetricKey,
        chunk_ids: Vec<ChunkId>,
    ) {
        self.owned_content.insert(content_id, master_key);
        self.content_chunks.insert(content_id, chunk_ids);
    }

    /// Add a lease for a chunk we're storing for someone else
    pub fn add_lease(&mut self, chunk_id: ChunkId, lease: ChunkLease) {
        self.leases.insert(chunk_id, lease);
    }

    /// Remove a lease
    pub fn remove_lease(&mut self, chunk_id: &ChunkId) -> Option<ChunkLease> {
        self.leases.remove(chunk_id)
    }

    /// Check if a lease is valid
    pub fn is_valid(&self, chunk_id: &ChunkId, current_time: u64) -> bool {
        if let Some(lease) = self.leases.get(chunk_id) {
            return is_lease_valid(lease, current_time);
        }
        false
    }

    /// Get expired chunks (lease expired + grace period)
    pub fn get_expired_chunks(&self, current_time: u64) -> Vec<ChunkId> {
        let threshold = current_time.saturating_sub(GRACE_PERIOD_SECS);
        self.leases
            .iter()
            .filter(|(_, lease)| lease.expires_at < threshold)
            .map(|(chunk_id, _)| *chunk_id)
            .collect()
    }

    /// Process a heartbeat
    ///
    /// Verifies the owner signature, checks for replay, and renews
    /// leases. The heartbeat's `content_pub_key` must match the key
    /// stored in each lease (legacy all-zero keys adopt the heartbeat's
    /// verified key once).
    pub fn process_heartbeat(
        &mut self,
        heartbeat: &Heartbeat,
        current_time: u64,
    ) -> Result<Vec<ChunkId>, HeartbeatError> {
        // Owner authorization first: unsigned or forged heartbeats are
        // rejected before consuming the nonce or touching any lease.
        heartbeat.verify_signature()?;

        // Check for replay
        if let Some(&seen_time) = self.seen_nonces.get(&heartbeat.nonce) {
            return Err(HeartbeatError::ReplayDetected(seen_time));
        }

        // Record the nonce
        self.seen_nonces.insert(heartbeat.nonce, current_time);

        // Verify the renewal token for each chunk
        // In a real implementation, we'd need the master key to verify
        // For now, we trust the token and renew the leases
        let mut renewed = Vec::new();

        for chunk_id in &heartbeat.chunk_ids {
            if let Some(mut lease) = self.leases.get(chunk_id).cloned() {
                // Verify the token matches
                if lease.renewal_token != heartbeat.renewal_token {
                    return Err(HeartbeatError::InvalidToken);
                }

                // The signer must be the content owner on record.
                match_lease_content_key(&mut lease, heartbeat)?;

                // Renew the lease
                lease.expires_at = heartbeat.new_expires_at;
                self.leases.insert(*chunk_id, lease);
                renewed.push(*chunk_id);
            }
        }

        Ok(renewed)
    }

    /// Process a heartbeat with upsert semantics (Phase 1)
    ///
    /// Signature-verified, token-checked refresh for existing leases;
    /// for chunks without a lease, creates one capped at `current_time +
    /// DEFAULT_LEASE_DURATION_SECS`. Callers must gate on chunks the node
    /// actually holds (pass them via `held_chunks`) so heartbeats cannot
    /// conjure leases for absent data.
    ///
    /// The content owner's Ed25519 signature over
    /// `content_id || chunk_ids || new_expires_at || nonce` is mandatory:
    /// only the owner (whose key derives the content_id) can extend a
    /// lease. Existing leases must match the stored `content_pub_key`
    /// (all-zero legacy keys adopt the verified key once); upsert-created
    /// leases record the owner key.
    pub fn process_heartbeat_upsert(
        &mut self,
        heartbeat: &Heartbeat,
        current_time: u64,
        held_chunks: &std::collections::HashSet<ChunkId>,
    ) -> Result<Vec<ChunkId>, HeartbeatError> {
        // Owner authorization first: unsigned or forged heartbeats are
        // rejected before consuming the nonce or touching any lease.
        heartbeat.verify_signature()?;

        // Check for replay (shared with process_heartbeat)
        if let Some(&seen_time) = self.seen_nonces.get(&heartbeat.nonce) {
            return Err(HeartbeatError::ReplayDetected(seen_time));
        }
        self.seen_nonces.insert(heartbeat.nonce, current_time);

        // Expiry sanity: never accept absurd expirations.
        let max_expires = current_time.saturating_add(DEFAULT_LEASE_DURATION_SECS);
        let expires_at = heartbeat.new_expires_at.min(max_expires);

        let mut renewed = Vec::new();
        for chunk_id in &heartbeat.chunk_ids {
            // Only formalize holdings: no lease for data we don't have.
            if !held_chunks.contains(chunk_id) {
                continue;
            }
            match self.leases.get_mut(chunk_id) {
                Some(lease) => {
                    // Existing lease: token-checked refresh (same as
                    // process_heartbeat).
                    if lease.renewal_token != heartbeat.renewal_token {
                        return Err(HeartbeatError::InvalidToken);
                    }
                    // The signer must be the content owner on record.
                    match_lease_content_key(lease, heartbeat)?;
                    lease.expires_at = expires_at;
                }
                None => {
                    // Upsert: first heartbeat for a chunk received via
                    // swap barter (no lease existed yet). Records the
                    // verified owner key for future heartbeats.
                    self.leases.insert(
                        *chunk_id,
                        ChunkLease {
                            chunk_id: *chunk_id,
                            expires_at,
                            renewal_token: heartbeat.renewal_token,
                            content_pub_key: heartbeat.content_pub_key,
                        },
                    );
                }
            }
            renewed.push(*chunk_id);
        }

        Ok(renewed)
    }

    /// Create a heartbeat for owned content, signed by the owner
    ///
    /// `signing_key` must be the content's Ed25519 key
    /// (`blake3(pub) == content_id`) — the same keypair the content_id
    /// is derived from. The signature covers
    /// [`Heartbeat::signing_bytes`].
    pub fn create_heartbeat(
        &self,
        content_id: &[u8; 32],
        new_duration_secs: u64,
        signing_key: &SigningKey,
    ) -> Result<Heartbeat, HeartbeatError> {
        let master_key = self
            .owned_content
            .get(content_id)
            .ok_or(HeartbeatError::ContentNotOwned)?;

        let chunk_ids = self
            .content_chunks
            .get(content_id)
            .cloned()
            .unwrap_or_default();

        if chunk_ids.is_empty() {
            return Err(HeartbeatError::NoChunks);
        }

        // Derive renewal token from the first chunk's lease
        // In a real implementation, all chunks share the same token
        let first_chunk = &chunk_ids[0];
        let lease = create_lease(
            first_chunk,
            master_key,
            DEFAULT_LEASE_DURATION_SECS,
            current_timestamp(),
        );

        let mut heartbeat = Heartbeat::new(
            *content_id,
            lease.renewal_token,
            chunk_ids,
            new_duration_secs,
        );
        heartbeat.sign(signing_key);
        Ok(heartbeat)
    }

    /// Clean up expired nonces (older than 24 hours)
    pub fn cleanup_nonces(&mut self, current_time: u64) {
        let threshold = current_time.saturating_sub(DEFAULT_LEASE_DURATION_SECS);
        self.seen_nonces.retain(|_, time| *time > threshold);
    }

    /// Get statistics
    pub fn stats(&self) -> LeaseStats {
        LeaseStats {
            active_leases: self.leases.len(),
            owned_content: self.owned_content.len(),
            seen_nonces: self.seen_nonces.len(),
        }
    }
}

impl Default for LeaseManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Lease statistics
#[derive(Debug, Clone)]
pub struct LeaseStats {
    /// Number of active leases
    pub active_leases: usize,
    /// Number of owned content items
    pub owned_content: usize,
    /// Number of seen nonces
    pub seen_nonces: usize,
}

/// Errors that can occur during heartbeat operations
#[derive(Debug, thiserror::Error)]
pub enum HeartbeatError {
    /// Replay detected
    #[error("replay detected (nonce seen at {0})")]
    ReplayDetected(u64),
    /// Invalid renewal token
    #[error("invalid renewal token")]
    InvalidToken,
    /// Content not owned by this node
    #[error("content not owned")]
    ContentNotOwned,
    /// No chunks associated with content
    #[error("no chunks for content")]
    NoChunks,
    /// Missing, malformed, or forged owner signature
    ///
    /// Covers: unsigned heartbeats, signatures not exactly 64 bytes,
    /// unparseable owner public keys, `blake3(content_pub_key) !=
    /// content_id`, failed verification over the signing bytes, and a
    /// signer key that does not match the lease's recorded owner key.
    #[error("invalid heartbeat signature")]
    InvalidSignature,
}

/// Match a heartbeat's verified owner key against a lease.
///
/// A lease carrying a non-zero `content_pub_key` (recorded from the
/// swap proposal at commit time, or from a previous signed heartbeat)
/// must match the heartbeat's key exactly — a different owner cannot
/// renew someone else's lease. An all-zero legacy key adopts the
/// (already signature-verified) heartbeat key once so pre-existing
/// leases transition to signed renewals; the renewal-token check
/// remains the primary guard in that case.
fn match_lease_content_key(
    lease: &mut ChunkLease,
    heartbeat: &Heartbeat,
) -> Result<(), HeartbeatError> {
    if lease.content_pub_key == [0u8; 32] {
        lease.content_pub_key = heartbeat.content_pub_key;
        return Ok(());
    }
    if lease.content_pub_key != heartbeat.content_pub_key {
        return Err(HeartbeatError::InvalidSignature);
    }
    Ok(())
}

/// Seed node configuration
#[derive(Debug, Clone)]
pub struct SeedNodeConfig {
    /// The seed node's ID
    pub node_id: NodeId,
    /// The seed node's address
    pub address: String,
    /// Whether this seed is active
    pub active: bool,
}

/// Seed node manager for redundancy
#[derive(Debug, Clone)]
pub struct SeedManager {
    /// Seed nodes for each content
    pub seeds: HashMap<[u8; 32], Vec<SeedNodeConfig>>,
}

impl SeedManager {
    /// Create a new seed manager
    pub fn new() -> Self {
        Self {
            seeds: HashMap::new(),
        }
    }

    /// Add a seed node for content
    pub fn add_seed(&mut self, content_id: [u8; 32], seed: SeedNodeConfig) {
        self.seeds
            .entry(content_id)
            .or_insert_with(Vec::new)
            .push(seed);
    }

    /// Get active seeds for content
    pub fn get_active_seeds(&self, content_id: &[u8; 32]) -> Vec<&SeedNodeConfig> {
        self.seeds
            .get(content_id)
            .map(|seeds| seeds.iter().filter(|s| s.active).collect())
            .unwrap_or_default()
    }

    /// Mark a seed as inactive (went offline)
    pub fn mark_inactive(&mut self, content_id: &[u8; 32], node_id: &NodeId) {
        if let Some(seeds) = self.seeds.get_mut(content_id) {
            for seed in seeds.iter_mut() {
                if seed.node_id == *node_id {
                    seed.active = false;
                }
            }
        }
    }

    /// Check if content has any active seeds
    pub fn has_active_seeds(&self, content_id: &[u8; 32]) -> bool {
        !self.get_active_seeds(content_id).is_empty()
    }

    /// Get content with no active seeds (needs repopulation)
    pub fn get_orphaned_content(&self) -> Vec<[u8; 32]> {
        self.seeds
            .iter()
            .filter(|(content_id, _)| !self.has_active_seeds(content_id))
            .map(|(content_id, _)| *content_id)
            .collect()
    }
}

impl Default for SeedManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use static_crypto::SymmetricKey;

    fn random_content_id() -> [u8; 32] {
        let mut id = [0u8; 32];
        OsRng.fill_bytes(&mut id);
        id
    }

    fn random_chunk_id() -> ChunkId {
        let mut id = [0u8; 32];
        OsRng.fill_bytes(&mut id);
        id
    }

    fn random_node_id() -> NodeId {
        let mut id = [0u8; 16];
        OsRng.fill_bytes(&mut id);
        id
    }

    /// A content owner keypair plus the content_id it derives
    /// (`blake3(pub) == content_id`, matching the C1 binding).
    fn test_owner() -> (SigningKey, [u8; 32]) {
        let mut sk_bytes = [0u8; 32];
        OsRng.fill_bytes(&mut sk_bytes);
        let sk = SigningKey::from_bytes(&sk_bytes);
        let content_id = *blake3::hash(&sk.verifying_key().to_bytes()).as_bytes();
        (sk, content_id)
    }

    /// Build a signed heartbeat from an owner key.
    fn signed_heartbeat(
        content_id: [u8; 32],
        token: [u8; 32],
        chunk_ids: Vec<ChunkId>,
        duration: u64,
        key: &SigningKey,
    ) -> Heartbeat {
        let mut hb = Heartbeat::new(content_id, token, chunk_ids, duration);
        hb.sign(key);
        hb
    }

    #[test]
    fn test_heartbeat_creation() {
        let (signing_key, content_id) = test_owner();
        let master = SymmetricKey::random();
        let chunk_ids = vec![random_chunk_id(), random_chunk_id()];

        let mut manager = LeaseManager::new();
        manager.register_owned_content(content_id, master, chunk_ids.clone());

        let heartbeat = manager
            .create_heartbeat(&content_id, 3600, &signing_key)
            .unwrap();

        assert_eq!(heartbeat.content_id, content_id);
        assert_eq!(heartbeat.chunk_ids, chunk_ids);
        assert!(heartbeat.new_expires_at > current_timestamp());
        // Owner-signed: key binding + signature verify.
        assert_eq!(heartbeat.content_pub_key, signing_key.verifying_key().to_bytes());
        assert!(heartbeat.verify_signature().is_ok());
    }

    #[test]
    fn test_heartbeat_not_owned() {
        let manager = LeaseManager::new();
        let (_signing_key, content_id) = test_owner();

        let result = manager.create_heartbeat(&content_id, 3600, &test_owner().0);
        assert!(matches!(result, Err(HeartbeatError::ContentNotOwned)));
    }

    #[test]
    fn test_heartbeat_no_chunks() {
        let (signing_key, content_id) = test_owner();
        let master = SymmetricKey::random();

        let mut manager = LeaseManager::new();
        manager.register_owned_content(content_id, master, vec![]);

        let result = manager.create_heartbeat(&content_id, 3600, &signing_key);
        assert!(matches!(result, Err(HeartbeatError::NoChunks)));
    }

    #[test]
    fn test_heartbeat_serialization_roundtrip() {
        let (signing_key, content_id) = test_owner();
        let token = [0x42u8; 32];
        let chunk_ids = vec![random_chunk_id(), random_chunk_id(), random_chunk_id()];

        let mut heartbeat = Heartbeat::new(content_id, token, chunk_ids.clone(), 3600);
        heartbeat.sign(&signing_key);

        let serialized = heartbeat.serialize();
        let deserialized = Heartbeat::deserialize(&serialized).unwrap();

        assert_eq!(deserialized.content_id, content_id);
        assert_eq!(deserialized.renewal_token, token);
        assert_eq!(deserialized.chunk_ids, chunk_ids);
        assert_eq!(deserialized.new_expires_at, heartbeat.new_expires_at);
        assert_eq!(deserialized.nonce, heartbeat.nonce);
        assert_eq!(deserialized.content_pub_key, heartbeat.content_pub_key);
        assert_eq!(deserialized.signature, heartbeat.signature);
        assert!(deserialized.verify_signature().is_ok());
    }

    #[test]
    fn test_heartbeat_deserialize_too_short() {
        let result = Heartbeat::deserialize(&[0u8; 10]);
        assert!(result.is_err());
    }

    #[test]
    fn test_heartbeat_wire_roundtrip() {
        let (signing_key, content_id) = test_owner();
        let token = [0x7eu8; 32];
        let chunk_ids = vec![random_chunk_id(), random_chunk_id()];

        let mut heartbeat = Heartbeat::new(content_id, token, chunk_ids.clone(), 3600);
        heartbeat.sign(&signing_key);
        let wire = heartbeat.wire_serialize();

        assert_eq!(wire[0], MSG_HEARTBEAT);
        let deserialized = Heartbeat::wire_deserialize(&wire).unwrap();
        assert_eq!(deserialized.content_id, content_id);
        assert_eq!(deserialized.renewal_token, token);
        assert_eq!(deserialized.chunk_ids, chunk_ids);
        assert_eq!(deserialized.new_expires_at, heartbeat.new_expires_at);
        assert!(deserialized.verify_signature().is_ok());
    }

    #[test]
    fn test_heartbeat_wire_wrong_type() {
        assert!(Heartbeat::wire_deserialize(&[0x09u8; 40]).is_err());
        assert!(Heartbeat::wire_deserialize(&[]).is_err());
    }

    #[test]
    fn test_heartbeat_upsert_creates_lease_for_held_chunk() {
        let mut manager = LeaseManager::new();
        let (signing_key, content_id) = test_owner();
        let chunk_id = random_chunk_id();
        let token = [0x11u8; 32];

        let heartbeat = signed_heartbeat(content_id, token, vec![chunk_id], 3600, &signing_key);

        // Chunk held, no lease yet: upsert creates one.
        let mut held = std::collections::HashSet::new();
        held.insert(chunk_id);
        let renewed = manager
            .process_heartbeat_upsert(&heartbeat, current_timestamp(), &held)
            .unwrap();
        assert_eq!(renewed, vec![chunk_id]);

        let lease = manager.leases.get(&chunk_id).unwrap();
        assert_eq!(lease.renewal_token, token);
        // The owner key is recorded for future heartbeat verification.
        assert_eq!(lease.content_pub_key, signing_key.verifying_key().to_bytes());
        assert!(lease.expires_at <= current_timestamp() + DEFAULT_LEASE_DURATION_SECS);
    }

    #[test]
    fn test_heartbeat_upsert_ignores_unheld_chunks() {
        let mut manager = LeaseManager::new();
        let (signing_key, content_id) = test_owner();
        let chunk_id = random_chunk_id();

        let heartbeat = signed_heartbeat(
            content_id,
            [0x22u8; 32],
            vec![chunk_id],
            3600,
            &signing_key,
        );

        // Chunk NOT held: no lease may be conjured.
        let renewed = manager
            .process_heartbeat_upsert(&heartbeat, current_timestamp(), &std::collections::HashSet::new())
            .unwrap();
        assert!(renewed.is_empty());
        assert!(manager.leases.get(&chunk_id).is_none());
    }

    #[test]
    fn test_heartbeat_upsert_caps_expiration() {
        let mut manager = LeaseManager::new();
        let (signing_key, content_id) = test_owner();
        let chunk_id = random_chunk_id();

        // Absurd expiry (100 years out) must be capped at now + duration.
        let mut heartbeat = Heartbeat::new(content_id, [0x33u8; 32], vec![chunk_id], 3600);
        heartbeat.new_expires_at = current_timestamp() + 100 * 365 * 86400;
        heartbeat.sign(&signing_key);

        let mut held = std::collections::HashSet::new();
        held.insert(chunk_id);
        manager
            .process_heartbeat_upsert(&heartbeat, current_timestamp(), &held)
            .unwrap();

        let lease = manager.leases.get(&chunk_id).unwrap();
        assert!(lease.expires_at <= current_timestamp() + DEFAULT_LEASE_DURATION_SECS);
    }

    #[test]
    fn test_heartbeat_upsert_rejects_wrong_token_on_existing_lease() {
        let mut manager = LeaseManager::new();
        let (signing_key, content_id) = test_owner();
        let chunk_id = random_chunk_id();
        let master = SymmetricKey::random();

        let lease = create_lease(&chunk_id, &master, 3600, current_timestamp());
        manager.add_lease(chunk_id, lease);

        // Tampered token on an existing lease must be rejected.
        let mut heartbeat = Heartbeat::new(content_id, [0x44u8; 32], vec![chunk_id], 3600);
        heartbeat.renewal_token[0] ^= 0xff;
        heartbeat.sign(&signing_key);

        let mut held = std::collections::HashSet::new();
        held.insert(chunk_id);
        let result = manager.process_heartbeat_upsert(&heartbeat, current_timestamp(), &held);
        assert!(matches!(result, Err(HeartbeatError::InvalidToken)));
    }

    #[test]
    fn test_lease_manager_add_remove() {
        let mut manager = LeaseManager::new();
        let chunk_id = random_chunk_id();
        let master = SymmetricKey::random();

        let lease = create_lease(&chunk_id, &master, 3600, current_timestamp());
        manager.add_lease(chunk_id, lease.clone());

        assert!(manager.is_valid(&chunk_id, current_timestamp()));

        manager.remove_lease(&chunk_id);
        assert!(!manager.is_valid(&chunk_id, current_timestamp()));
    }

    #[test]
    fn test_lease_expiry() {
        let mut manager = LeaseManager::new();
        let chunk_id = random_chunk_id();
        let master = SymmetricKey::random();

        let lease = create_lease(&chunk_id, &master, 100, 1000); // expires at 1100
        manager.add_lease(chunk_id, lease);

        // Valid at 1050
        assert!(manager.is_valid(&chunk_id, 1050));

        // Expired at 1200
        assert!(!manager.is_valid(&chunk_id, 1200));

        // Still in grace period at 1100 + 7200 - 1
        let expired = manager.get_expired_chunks(1100 + GRACE_PERIOD_SECS - 1);
        assert!(expired.is_empty());

        // Past grace period
        let expired = manager.get_expired_chunks(1100 + GRACE_PERIOD_SECS + 1);
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0], chunk_id);
    }

    #[test]
    fn test_heartbeat_processing() {
        let mut manager = LeaseManager::new();
        let (signing_key, content_id) = test_owner();
        let chunk_id = random_chunk_id();
        let master = SymmetricKey::random();

        // Add a lease
        let lease = create_lease(&chunk_id, &master, 3600, current_timestamp());
        manager.add_lease(chunk_id, lease.clone());

        // Create a signed heartbeat
        let heartbeat = signed_heartbeat(
            content_id,
            lease.renewal_token,
            vec![chunk_id],
            7200,
            &signing_key,
        );

        // Process the heartbeat
        let renewed = manager.process_heartbeat(&heartbeat, current_timestamp()).unwrap();
        assert_eq!(renewed.len(), 1);
        assert_eq!(renewed[0], chunk_id);

        // Check the lease was renewed
        let new_lease = manager.leases.get(&chunk_id).unwrap();
        assert!(new_lease.expires_at > lease.expires_at);
    }

    #[test]
    fn test_heartbeat_replay_detection() {
        let mut manager = LeaseManager::new();
        let (signing_key, content_id) = test_owner();
        let chunk_id = random_chunk_id();
        let master = SymmetricKey::random();

        let lease = create_lease(&chunk_id, &master, 3600, current_timestamp());
        manager.add_lease(chunk_id, lease.clone());

        let heartbeat = signed_heartbeat(
            content_id,
            lease.renewal_token,
            vec![chunk_id],
            7200,
            &signing_key,
        );

        // First processing should succeed
        let result1 = manager.process_heartbeat(&heartbeat, current_timestamp());
        assert!(result1.is_ok());

        // Second processing (same nonce) should fail
        let result2 = manager.process_heartbeat(&heartbeat, current_timestamp());
        assert!(matches!(result2, Err(HeartbeatError::ReplayDetected(_))));
    }

    #[test]
    fn test_heartbeat_invalid_token() {
        let mut manager = LeaseManager::new();
        let (signing_key, content_id) = test_owner();
        let chunk_id = random_chunk_id();
        let master = SymmetricKey::random();

        let lease = create_lease(&chunk_id, &master, 3600, current_timestamp());
        manager.add_lease(chunk_id, lease.clone());

        // Create heartbeat with wrong token
        let mut heartbeat = Heartbeat::new(
            content_id,
            lease.renewal_token,
            vec![chunk_id],
            7200,
        );
        heartbeat.renewal_token[0] ^= 0xff; // Tamper
        heartbeat.sign(&signing_key);

        let result = manager.process_heartbeat(&heartbeat, current_timestamp());
        assert!(matches!(result, Err(HeartbeatError::InvalidToken)));
    }

    #[test]
    fn test_heartbeat_signature_valid() {
        // A correctly signed heartbeat passes verification and renews.
        let mut manager = LeaseManager::new();
        let (signing_key, content_id) = test_owner();
        let chunk_id = random_chunk_id();
        let master = SymmetricKey::random();

        let lease = create_lease(&chunk_id, &master, 3600, current_timestamp());
        manager.add_lease(chunk_id, lease.clone());

        let heartbeat = signed_heartbeat(
            content_id,
            lease.renewal_token,
            vec![chunk_id],
            7200,
            &signing_key,
        );
        assert!(heartbeat.verify_signature().is_ok());
        assert!(manager
            .process_heartbeat(&heartbeat, current_timestamp())
            .is_ok());
    }

    #[test]
    fn test_heartbeat_signature_invalid() {
        // A signature from the wrong key (valid for a different
        // content identity) must be rejected.
        let mut manager = LeaseManager::new();
        let (_owner_key, content_id) = test_owner();
        let attacker_key = test_owner().0;
        let chunk_id = random_chunk_id();
        let master = SymmetricKey::random();

        let lease = create_lease(&chunk_id, &master, 3600, current_timestamp());
        manager.add_lease(chunk_id, lease.clone());

        let heartbeat = signed_heartbeat(
            content_id,
            lease.renewal_token,
            vec![chunk_id],
            7200,
            &attacker_key,
        );
        // blake3(attacker_pub) != content_id, so the binding fails.
        assert!(matches!(
            heartbeat.verify_signature(),
            Err(HeartbeatError::InvalidSignature)
        ));
        let result = manager.process_heartbeat(&heartbeat, current_timestamp());
        assert!(matches!(result, Err(HeartbeatError::InvalidSignature)));
    }

    #[test]
    fn test_heartbeat_signature_missing() {
        // An unsigned heartbeat must be rejected outright.
        let mut manager = LeaseManager::new();
        let (_owner_key, content_id) = test_owner();
        let chunk_id = random_chunk_id();
        let master = SymmetricKey::random();

        let lease = create_lease(&chunk_id, &master, 3600, current_timestamp());
        manager.add_lease(chunk_id, lease.clone());

        let heartbeat = Heartbeat::new(content_id, lease.renewal_token, vec![chunk_id], 7200);
        assert!(heartbeat.signature.is_empty());
        assert!(matches!(
            heartbeat.verify_signature(),
            Err(HeartbeatError::InvalidSignature)
        ));
        let result = manager.process_heartbeat(&heartbeat, current_timestamp());
        assert!(matches!(result, Err(HeartbeatError::InvalidSignature)));
    }

    #[test]
    fn test_heartbeat_upsert_requires_valid_sig() {
        // The upsert path must also reject unsigned heartbeats.
        let mut manager = LeaseManager::new();
        let (_owner_key, content_id) = test_owner();
        let chunk_id = random_chunk_id();

        let heartbeat = Heartbeat::new(content_id, [0x55u8; 32], vec![chunk_id], 3600);

        let mut held = std::collections::HashSet::new();
        held.insert(chunk_id);
        let result = manager.process_heartbeat_upsert(&heartbeat, current_timestamp(), &held);
        assert!(matches!(result, Err(HeartbeatError::InvalidSignature)));
        assert!(manager.leases.get(&chunk_id).is_none());
    }

    #[test]
    fn test_heartbeat_wrong_owner_key_rejected_on_leased_chunk() {
        // An existing lease records its owner (from the swap proposal);
        // a validly-signed heartbeat from a DIFFERENT key must not renew.
        let mut manager = LeaseManager::new();
        let (owner_key, content_id) = test_owner();
        let other_key = test_owner().0;
        let chunk_id = random_chunk_id();
        let master = SymmetricKey::random();

        let mut lease = create_lease(&chunk_id, &master, 3600, current_timestamp());
        lease.content_pub_key = owner_key.verifying_key().to_bytes();
        manager.add_lease(chunk_id, lease);

        let heartbeat = signed_heartbeat(
            content_id,
            [0x66u8; 32],
            vec![chunk_id],
            7200,
            &other_key,
        );
        let mut held = std::collections::HashSet::new();
        held.insert(chunk_id);
        let result = manager.process_heartbeat_upsert(&heartbeat, current_timestamp(), &held);
        assert!(matches!(result, Err(HeartbeatError::InvalidSignature)));
    }

    #[test]
    fn test_heartbeat_legacy_lease_adopts_owner_key() {
        // A pre-signed-heartbeat lease (all-zero owner key) adopts the
        // verified key on the first signed heartbeat, and later
        // heartbeats from a different key are rejected.
        let mut manager = LeaseManager::new();
        let (owner_key, content_id) = test_owner();
        let chunk_id = random_chunk_id();
        let master = SymmetricKey::random();

        let lease = create_lease(&chunk_id, &master, 3600, current_timestamp());
        assert_eq!(lease.content_pub_key, [0u8; 32]);
        manager.add_lease(chunk_id, lease);

        let first = signed_heartbeat(
            content_id,
            {
                let l = manager.leases.get(&chunk_id).unwrap();
                l.renewal_token
            },
            vec![chunk_id],
            3600,
            &owner_key,
        );
        let mut held = std::collections::HashSet::new();
        held.insert(chunk_id);
        manager
            .process_heartbeat_upsert(&first, current_timestamp(), &held)
            .unwrap();
        assert_eq!(
            manager.leases.get(&chunk_id).unwrap().content_pub_key,
            owner_key.verifying_key().to_bytes()
        );

        // A different (validly bound) key can no longer renew.
        let impostor = test_owner().0;
        let second = signed_heartbeat(
            content_id,
            {
                let l = manager.leases.get(&chunk_id).unwrap();
                l.renewal_token
            },
            vec![chunk_id],
            3600,
            &impostor,
        );
        let result = manager.process_heartbeat_upsert(&second, current_timestamp(), &held);
        assert!(matches!(result, Err(HeartbeatError::InvalidSignature)));
    }

    #[test]
    fn test_seed_manager() {
        let mut seed_manager = SeedManager::new();
        let content_id = random_content_id();
        let seed1 = SeedNodeConfig {
            node_id: random_node_id(),
            address: "127.0.0.1:9001".to_string(),
            active: true,
        };
        let seed2 = SeedNodeConfig {
            node_id: random_node_id(),
            address: "127.0.0.1:9002".to_string(),
            active: true,
        };

        seed_manager.add_seed(content_id, seed1.clone());
        seed_manager.add_seed(content_id, seed2.clone());

        assert_eq!(seed_manager.get_active_seeds(&content_id).len(), 2);
        assert!(seed_manager.has_active_seeds(&content_id));

        // Mark one as inactive
        seed_manager.mark_inactive(&content_id, &seed1.node_id);
        assert_eq!(seed_manager.get_active_seeds(&content_id).len(), 1);

        // Mark all as inactive
        seed_manager.mark_inactive(&content_id, &seed2.node_id);
        assert!(!seed_manager.has_active_seeds(&content_id));

        // Should be orphaned
        let orphaned = seed_manager.get_orphaned_content();
        assert_eq!(orphaned.len(), 1);
        assert_eq!(orphaned[0], content_id);
    }

    #[test]
    fn test_lease_stats() {
        let mut manager = LeaseManager::new();
        let content_id = random_content_id();
        let master = SymmetricKey::random();
        let chunk_ids = vec![random_chunk_id()];

        manager.register_owned_content(content_id, master, chunk_ids);

        let stats = manager.stats();
        assert_eq!(stats.owned_content, 1);
        assert_eq!(stats.active_leases, 0);
    }

    #[test]
    fn test_nonce_cleanup() {
        let mut manager = LeaseManager::new();
        let (signing_key, content_id) = test_owner();
        let chunk_id = random_chunk_id();
        let master = SymmetricKey::random();

        let lease = create_lease(&chunk_id, &master, 3600, 1000);
        manager.add_lease(chunk_id, lease.clone());

        let heartbeat = signed_heartbeat(
            content_id,
            lease.renewal_token,
            vec![chunk_id],
            3600,
            &signing_key,
        );
        manager.process_heartbeat(&heartbeat, 1000).unwrap();

        assert_eq!(manager.seen_nonces.len(), 1);

        // Cleanup nonces older than 24 hours
        manager.cleanup_nonces(1000 + DEFAULT_LEASE_DURATION_SECS + 1);
        assert_eq!(manager.seen_nonces.len(), 0);
    }
}
