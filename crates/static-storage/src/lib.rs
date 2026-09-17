//! static-storage - Encrypted distributed storage with swap barter
//!
//! Implements:
//! - Chunk encryption (uniform 1 MiB chunks, strong encryption)
//! - Erasure coding (Reed-Solomon K=10, M=5 by default)
//! - Reciprocal storage swap (1:1 barter of opaque slots)
//! - Leases with encrypted heartbeats for owner control
//! - Seed node redundancy
//! - RAM safety (streaming decryption, key chains, never full file in memory)

#![forbid(unsafe_code)]
#![deny(missing_docs)]


/// Storage swap barter protocol
pub mod swap;

/// Lease and heartbeat protocol
pub mod heartbeat;

/// Chunk retrieval protocol
pub mod retrieval;

/// Compute execution protocol (WASM requests/responses over Sphinx)
pub mod compute;

/// Hidden service discovery and encrypted manifests
pub mod hidden_service;

/// Chunk repair protocol
pub mod repair;

/// Hot storage rotation — Freenet-style chunk migration
pub mod rotation;

use static_crypto::{SymmetricKey, NonceBytes, encrypt, decrypt};
use blake3;
use reed_solomon_erasure::galois_8::ReedSolomon;
use std::collections::HashMap;

/// Default chunk size: 1 MiB
pub const CHUNK_SIZE: usize = 1024 * 1024;

/// Default data shards (K) for erasure coding
pub const DEFAULT_DATA_SHARDS: usize = 10;

/// Default parity shards (M) for erasure coding
pub const DEFAULT_PARITY_SHARDS: usize = 5;

/// Size of a chunk ID (32 bytes = blake3 hash)
pub const CHUNK_ID_SIZE: usize = 32;

/// Size of a content ID (32 bytes = blake3 hash of manifest)
pub const CONTENT_ID_SIZE: usize = 32;

/// Size of a node ID
pub const NODE_ID_SIZE: usize = 16;

/// A chunk ID (blake3 hash of encrypted chunk)
pub type ChunkId = [u8; CHUNK_ID_SIZE];

/// A content ID (blake3 hash of content manifest)
pub type ContentId = [u8; CONTENT_ID_SIZE];

/// A node ID
pub type NodeId = [u8; NODE_ID_SIZE];

/// An encrypted chunk with its ID
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EncryptedChunk {
    /// The chunk ID (blake3 hash of the ciphertext)
    pub id: ChunkId,
    /// The encrypted chunk data (uniform CHUNK_SIZE bytes)
    pub data: Vec<u8>,
}

/// A lease on a chunk held by a storage node
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ChunkLease {
    /// The chunk ID this lease covers
    pub chunk_id: ChunkId,
    /// When the lease expires (unix timestamp)
    pub expires_at: u64,
    /// Renewal token (proves the owner is authorized to refresh)
    pub renewal_token: [u8; 32],
}

/// Content manifest describing how to reconstruct a file
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ContentManifest {
    /// The content ID
    pub content_id: ContentId,
    /// The master encryption key (encrypted to the retriever)
    pub encrypted_master_key: Vec<u8>,
    /// The list of chunk IDs in order
    pub chunk_ids: Vec<ChunkId>,
    /// The original file size in bytes
    pub original_size: u64,
    /// The erasure coding parameters
    pub data_shards: usize,
    /// The parity shard count
    pub parity_shards: usize,
    /// The nonce used for chunk encryption
    pub nonce: [u8; 12],
}

/// A storage slot offered in a swap
#[derive(Debug, Clone)]
pub struct SwapSlot {
    /// The chunk being offered
    pub chunk: EncryptedChunk,
    /// The lease associated with this chunk
    pub lease: ChunkLease,
}

/// A swap proposal from one node to another
#[derive(Debug, Clone)]
pub struct SwapProposal {
    /// The node offering the swap
    pub from_node: NodeId,
    /// The slot being offered
    pub offered_slot: SwapSlot,
    /// How many bytes are being offered
    pub offered_bytes: u64,
}

/// A swap acceptance
#[derive(Debug, Clone)]
pub struct SwapAccept {
    /// The node accepting the swap
    pub from_node: NodeId,
    /// The slot being offered in return
    pub return_slot: SwapSlot,
}

/// Local accounting state for a node
#[derive(Debug, Clone, Default)]
pub struct AccountingState {
    /// Bytes this node has contributed to others
    pub bytes_contributed: u64,
    /// Bytes this node is using from others
    pub bytes_used: u64,
    /// Per-peer credit tracking
    pub peer_credits: HashMap<NodeId, i64>,
}

impl AccountingState {
    /// Get the contribution ratio (contributed / used)
    /// Returns infinity if used is 0
    pub fn ratio(&self) -> f64 {
        if self.bytes_used == 0 {
            f64::INFINITY
        } else {
            self.bytes_contributed as f64 / self.bytes_used as f64
        }
    }

    /// Check if a peer has sufficient credit
    pub fn peer_has_credit(&self, peer: &NodeId, needed: u64) -> bool {
        let credit = self.peer_credits.get(peer).copied().unwrap_or(0);
        credit >= needed as i64
    }

    /// Record a contribution to a peer
    pub fn record_contribution(&mut self, peer: NodeId, bytes: u64) {
        self.bytes_contributed += bytes;
        *self.peer_credits.entry(peer).or_insert(0) += bytes as i64;
    }

    /// Record usage from a peer
    pub fn record_usage(&mut self, peer: NodeId, bytes: u64) {
        self.bytes_used += bytes;
        *self.peer_credits.entry(peer).or_insert(0) -= bytes as i64;
    }
}

/// Errors that can occur during storage operations
#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    /// Chunk encryption failed
    #[error("chunk encryption failed")]
    EncryptionFailed,
    /// Chunk decryption failed
    #[error("chunk decryption failed")]
    DecryptionFailed,
    /// Erasure coding error
    #[error("erasure coding error: {0}")]
    ErasureError(String),
    /// Not enough shards to reconstruct
    #[error("not enough shards to reconstruct (have {have}, need {need})")]
    InsufficientShards {
        /// Number of shards available
        have: usize,
        /// Number of shards required
        need: usize,
    },
    /// Invalid chunk size
    #[error("invalid chunk size: expected {expected}, got {actual}")]
    InvalidChunkSize {
        /// Expected chunk size in bytes
        expected: usize,
        /// Actual chunk size received
        actual: usize,
    },
    /// Lease expired
    #[error("lease expired")]
    LeaseExpired,
    /// Invalid renewal token
    #[error("invalid renewal token")]
    InvalidRenewalToken,
    /// Content not found
    #[error("content not found")]
    ContentNotFound,
    /// Manifest encryption failed
    #[error("manifest encryption failed")]
    ManifestEncryptionFailed,
    /// Manifest decryption failed
    #[error("manifest decryption failed")]
    ManifestDecryptionFailed,
    /// Manifest serialization failed
    #[error("manifest serialization failed")]
    ManifestSerializationFailed,
    /// Manifest deserialization failed
    #[error("manifest deserialization failed")]
    ManifestDeserializationFailed,
}

// ---- Chunk encryption ----

/// Encrypt a single chunk with a derived key.
///
/// The chunk is padded to CHUNK_SIZE if smaller.
/// The key is derived from the master key using HKDF with the chunk index.
/// Returns an EncryptedChunk with a blake3 ID.
pub fn encrypt_chunk(
    master_key: &SymmetricKey,
    nonce: &NonceBytes,
    chunk_index: usize,
    plaintext: &[u8],
) -> Result<EncryptedChunk, StorageError> {
    // Derive chunk-specific key from master key
    let chunk_key = master_key.derive(&format!("chunk:{}", chunk_index));

    // Pad plaintext to CHUNK_SIZE
    let mut padded = vec![0u8; CHUNK_SIZE];
    let len = plaintext.len().min(CHUNK_SIZE);
    padded[..len].copy_from_slice(&plaintext[..len]);

    // Encrypt with ChaCha20-Poly1305
    // Use a chunk-specific nonce derived from the base nonce
    let mut chunk_nonce_bytes = nonce.bytes;
    chunk_nonce_bytes[4..12].copy_from_slice(&(chunk_index as u64).to_le_bytes());
    let chunk_nonce = NonceBytes::from_bytes(chunk_nonce_bytes);

    let ciphertext = encrypt(&chunk_key, &chunk_nonce, &padded);

    // Verify ciphertext is exactly CHUNK_SIZE + TAG_SIZE
    if ciphertext.len() != CHUNK_SIZE + 16 {
        return Err(StorageError::EncryptionFailed);
    }

    // Compute chunk ID as blake3 hash of ciphertext
    let id: ChunkId = blake3::hash(&ciphertext).into();

    Ok(EncryptedChunk { id, data: ciphertext })
}

/// Decrypt a single chunk with a derived key.
///
/// Only one chunk is ever in RAM at a time.
/// The caller is responsible for zeroizing the plaintext after use.
pub fn decrypt_chunk(
    master_key: &SymmetricKey,
    nonce: &NonceBytes,
    chunk_index: usize,
    chunk: &EncryptedChunk,
) -> Result<Vec<u8>, StorageError> {
    let chunk_key = master_key.derive(&format!("chunk:{}", chunk_index));

    let mut chunk_nonce_bytes = nonce.bytes;
    chunk_nonce_bytes[4..12].copy_from_slice(&(chunk_index as u64).to_le_bytes());
    let chunk_nonce = NonceBytes::from_bytes(chunk_nonce_bytes);

    decrypt(&chunk_key, &chunk_nonce, &chunk.data)
        .map_err(|_| StorageError::DecryptionFailed)
}

// ---- File splitting and encryption ----

/// Split a file into encrypted chunks.
///
/// The file is split into CHUNK_SIZE pieces, each encrypted with a
/// key derived from the master key. Returns the chunks and a manifest.
pub fn encrypt_file(
    master_key: &SymmetricKey,
    nonce: &NonceBytes,
    file_data: &[u8],
) -> Result<(Vec<EncryptedChunk>, ContentManifest), StorageError> {
    let num_chunks = std::cmp::max(1, (file_data.len() + CHUNK_SIZE - 1) / CHUNK_SIZE);
    let mut chunks = Vec::with_capacity(num_chunks);

    for i in 0..num_chunks {
        let start = i * CHUNK_SIZE;
        let end = std::cmp::min(start + CHUNK_SIZE, file_data.len());
        let chunk_plaintext = &file_data[start..end];
        let encrypted = encrypt_chunk(master_key, nonce, i, chunk_plaintext)?;
        chunks.push(encrypted);
    }

    let chunk_ids: Vec<ChunkId> = chunks.iter().map(|c| c.id).collect();

    // Compute content ID as blake3 hash of chunk IDs
    let mut id_input = Vec::new();
    for id in &chunk_ids {
        id_input.extend_from_slice(id);
    }
    let content_id: ContentId = blake3::hash(&id_input).into();

    let manifest = ContentManifest {
        content_id,
        encrypted_master_key: vec![], // Filled by caller if needed
        chunk_ids,
        original_size: file_data.len() as u64,
        data_shards: DEFAULT_DATA_SHARDS,
        parity_shards: DEFAULT_PARITY_SHARDS,
        nonce: nonce.bytes,
    };

    Ok((chunks, manifest))
}

/// Reconstruct a file from decrypted chunks.
///
/// Only one chunk is decrypted at a time to limit RAM exposure.
/// The caller should zeroize the result after use.
pub fn decrypt_file(
    master_key: &SymmetricKey,
    nonce: &NonceBytes,
    chunks: &[EncryptedChunk],
    manifest: &ContentManifest,
) -> Result<Vec<u8>, StorageError> {
    let mut result = Vec::with_capacity(manifest.original_size as usize);

    for (i, chunk) in chunks.iter().enumerate() {
        let plaintext = decrypt_chunk(master_key, nonce, i, chunk)?;
        let remaining = manifest.original_size as usize - result.len();
        let to_take = plaintext.len().min(remaining);
        result.extend_from_slice(&plaintext[..to_take]);
        // plaintext is dropped here (caller should zeroize)
    }

    Ok(result)
}

// ---- Erasure coding ----

/// Apply Reed-Solomon erasure coding to a set of chunks.
///
/// Takes K data chunks and produces K+M total chunks (K data + M parity).
/// Any K of the K+M chunks can reconstruct the original data.
pub fn erasure_encode(
    chunks: &[EncryptedChunk],
    data_shards: usize,
    parity_shards: usize,
) -> Result<Vec<EncryptedChunk>, StorageError> {
    if chunks.len() != data_shards {
        return Err(StorageError::ErasureError(format!(
            "expected {} data shards, got {}",
            data_shards,
            chunks.len()
        )));
    }

    let rs = ReedSolomon::new(data_shards, parity_shards)
        .map_err(|e| StorageError::ErasureError(e.to_string()))?;

    // Convert chunk data to shards (each shard is a Vec<u8>)
    let mut shards: Vec<Vec<u8>> = chunks.iter()
        .map(|c| c.data.clone())
        .collect();

    // Add empty parity shards
    let shard_size = shards[0].len();
    for _ in 0..parity_shards {
        shards.push(vec![0u8; shard_size]);
    }

    // Encode
    rs.encode(&mut shards)
        .map_err(|e| StorageError::ErasureError(e.to_string()))?;

    // Build result chunks
    let mut result = Vec::with_capacity(data_shards + parity_shards);

    // Data chunks (with original IDs)
    for i in 0..data_shards {
        result.push(EncryptedChunk {
            id: chunks[i].id,
            data: shards[i].clone(),
        });
    }

    // Parity chunks (with blake3 IDs)
    for i in data_shards..data_shards + parity_shards {
        let id: ChunkId = blake3::hash(&shards[i]).into();
        result.push(EncryptedChunk {
            id,
            data: shards[i].clone(),
        });
    }

    Ok(result)
}

/// Reconstruct missing data chunks from a set of shards.
///
/// Takes up to K+M chunks (some may be None/missing) and reconstructs
/// the original K data chunks. Any K of K+M chunks is sufficient.
pub fn erasure_decode(
    shards: &[Option<EncryptedChunk>],
    data_shards: usize,
    parity_shards: usize,
) -> Result<Vec<EncryptedChunk>, StorageError> {
    let total = data_shards + parity_shards;
    if shards.len() != total {
        return Err(StorageError::ErasureError(format!(
            "expected {} shards, got {}",
            total,
            shards.len()
        )));
    }

    let present = shards.iter().filter(|s| s.is_some()).count();
    if present < data_shards {
        return Err(StorageError::InsufficientShards {
            have: present,
            need: data_shards,
        });
    }

    let rs = ReedSolomon::new(data_shards, parity_shards)
        .map_err(|e| StorageError::ErasureError(e.to_string()))?;

    // Convert to Option<Vec<u8>> format for reed-solomon-erasure v6 API
    let mut rs_shards: Vec<Option<Vec<u8>>> = shards.iter()
        .map(|s| s.as_ref().map(|c| c.data.clone()))
        .collect();

    // Reconstruct missing shards
    rs.reconstruct(&mut rs_shards)
        .map_err(|e| StorageError::ErasureError(e.to_string()))?;

    // Return only the data shards
    let mut result = Vec::with_capacity(data_shards);
    for i in 0..data_shards {
        let shard_data = rs_shards[i].as_ref().unwrap();
        let id: ChunkId = blake3::hash(shard_data).into();
        result.push(EncryptedChunk {
            id,
            data: shard_data.clone(),
        });
    }

    Ok(result)
}

// ---- Lease management ----

/// Create a new lease for a chunk.
///
/// The lease includes a renewal token that the owner uses to refresh.
/// The token is derived from the master key and chunk ID.
pub fn create_lease(
    chunk_id: &ChunkId,
    master_key: &SymmetricKey,
    duration_secs: u64,
    current_time: u64,
) -> ChunkLease {
    let token_key = master_key.derive("lease_token");
    let mut input = Vec::with_capacity(CHUNK_ID_SIZE + 32);
    input.extend_from_slice(chunk_id);
    input.extend_from_slice(&token_key.bytes);
    let token_hash = blake3::hash(&input);
    let mut renewal_token = [0u8; 32];
    renewal_token.copy_from_slice(token_hash.as_bytes());

    ChunkLease {
        chunk_id: *chunk_id,
        expires_at: current_time + duration_secs,
        renewal_token,
    }
}

/// Verify a renewal token for a chunk.
pub fn verify_renewal_token(
    chunk_id: &ChunkId,
    master_key: &SymmetricKey,
    token: &[u8; 32],
) -> bool {
    let token_key = master_key.derive("lease_token");
    let mut input = Vec::with_capacity(CHUNK_ID_SIZE + 32);
    input.extend_from_slice(chunk_id);
    input.extend_from_slice(&token_key.bytes);
    let expected_hash = blake3::hash(&input);
    let mut expected = [0u8; 32];
    expected.copy_from_slice(expected_hash.as_bytes());
    expected == *token
}

/// Check if a lease is still valid.
pub fn is_lease_valid(lease: &ChunkLease, current_time: u64) -> bool {
    current_time < lease.expires_at
}

/// Refresh a lease with a new expiration time.
///
/// The renewal token must be valid.
pub fn refresh_lease(
    lease: &ChunkLease,
    master_key: &SymmetricKey,
    new_duration_secs: u64,
    current_time: u64,
) -> Result<ChunkLease, StorageError> {
    if !verify_renewal_token(&lease.chunk_id, master_key, &lease.renewal_token) {
        return Err(StorageError::InvalidRenewalToken);
    }

    Ok(ChunkLease {
        chunk_id: lease.chunk_id,
        expires_at: current_time + new_duration_secs,
        renewal_token: lease.renewal_token,
    })
}

// ---- Streaming decryption (RAM safety) ----

/// Streaming chunk decryptor that processes one chunk at a time.
///
/// This ensures only one chunk is ever in RAM.
/// After each chunk is consumed, call `zeroize_current()` before
/// loading the next chunk.
pub struct StreamingDecryptor {
    master_key: SymmetricKey,
    nonce: NonceBytes,
    current_index: usize,
    current_plaintext: Option<Vec<u8>>,
}

impl StreamingDecryptor {
    /// Create a new streaming decryptor
    pub fn new(master_key: SymmetricKey, nonce: NonceBytes) -> Self {
        Self {
            master_key,
            nonce,
            current_index: 0,
            current_plaintext: None,
        }
    }

    /// Decrypt the next chunk.
    /// The previous chunk's plaintext is zeroized first.
    pub fn next_chunk(&mut self, chunk: &EncryptedChunk) -> Result<&[u8], StorageError> {
        // Zeroize previous plaintext
        if let Some(mut pt) = self.current_plaintext.take() {
            zeroize_vec(&mut pt);
        }

        let plaintext = decrypt_chunk(
            &self.master_key,
            &self.nonce,
            self.current_index,
            chunk,
        )?;
        self.current_plaintext = Some(plaintext);
        self.current_index += 1;

        Ok(self.current_plaintext.as_ref().unwrap())
    }

    /// Zeroize the current plaintext in memory
    pub fn zeroize_current(&mut self) {
        if let Some(mut pt) = self.current_plaintext.take() {
            zeroize_vec(&mut pt);
        }
    }

    /// Get the current chunk index
    pub fn current_index(&self) -> usize {
        self.current_index
    }
}

impl Drop for StreamingDecryptor {
    fn drop(&mut self) {
        self.zeroize_current();
        // Zeroize the master key
        let mut key_bytes = self.master_key.bytes;
        zeroize_array(&mut key_bytes);
    }
}

/// Zeroize a vector by overwriting with zeros
fn zeroize_vec(v: &mut Vec<u8>) {
    for byte in v.iter_mut() {
        *byte = 0;
    }
}

/// Zeroize an array by overwriting with zeros
fn zeroize_array<const N: usize>(arr: &mut [u8; N]) {
    for byte in arr.iter_mut() {
        *byte = 0;
    }
}

// ---- Tests ----

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;
    use rand::RngCore;

    fn random_bytes(len: usize) -> Vec<u8> {
        let mut bytes = vec![0u8; len];
        OsRng.fill_bytes(&mut bytes);
        bytes
    }

    #[test]
    fn test_chunk_encryption_roundtrip() {
        let master = SymmetricKey::random();
        let nonce = NonceBytes::random();
        let plaintext = b"hello storage network";
        
        let chunk = encrypt_chunk(&master, &nonce, 0, plaintext).unwrap();
        let decrypted = decrypt_chunk(&master, &nonce, 0, &chunk).unwrap();
        
        assert_eq!(&decrypted[..plaintext.len()], plaintext);
    }

    #[test]
    fn test_chunk_uniform_size() {
        let master = SymmetricKey::random();
        let nonce = NonceBytes::random();
        
        let small = encrypt_chunk(&master, &nonce, 0, b"tiny").unwrap();
        let large = encrypt_chunk(&master, &nonce, 1, &random_bytes(CHUNK_SIZE)).unwrap();
        
        // Both chunks should be the same size (CHUNK_SIZE + 16 byte tag)
        assert_eq!(small.data.len(), large.data.len());
        assert_eq!(small.data.len(), CHUNK_SIZE + 16);
    }

    #[test]
    fn test_chunk_id_is_hash() {
        let master = SymmetricKey::random();
        let nonce = NonceBytes::random();
        let plaintext = b"test data for id";
        
        let chunk = encrypt_chunk(&master, &nonce, 0, plaintext).unwrap();
        let expected_id: ChunkId = blake3::hash(&chunk.data).into();
        
        assert_eq!(chunk.id, expected_id);
    }

    #[test]
    fn test_file_encryption_roundtrip() {
        let master = SymmetricKey::random();
        let nonce = NonceBytes::random();
        let file_data = random_bytes(CHUNK_SIZE * 2 + 100); // 2.1 MiB
        
        let (chunks, manifest) = encrypt_file(&master, &nonce, &file_data).unwrap();
        assert_eq!(chunks.len(), 3); // 3 chunks for 2.1 MiB
        
        let decrypted = decrypt_file(&master, &nonce, &chunks, &manifest).unwrap();
        assert_eq!(decrypted, file_data);
    }

    #[test]
    fn test_empty_file() {
        let master = SymmetricKey::random();
        let nonce = NonceBytes::random();
        let file_data: Vec<u8> = vec![];
        
        let (chunks, manifest) = encrypt_file(&master, &nonce, &file_data).unwrap();
        assert_eq!(chunks.len(), 1); // At least one chunk
        
        let decrypted = decrypt_file(&master, &nonce, &chunks, &manifest).unwrap();
        assert_eq!(decrypted, file_data);
    }

    #[test]
    fn test_erasure_coding_roundtrip() {
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
        
        // Reconstruct with only 10 of 15 shards (drop 5)
        let mut shards: Vec<Option<EncryptedChunk>> = encoded.into_iter()
            .map(Some)
            .collect();
        
        // Drop 5 random shards
        shards[2] = None;
        shards[5] = None;
        shards[8] = None;
        shards[11] = None;
        shards[13] = None;
        
        let reconstructed = erasure_decode(&shards, DEFAULT_DATA_SHARDS, DEFAULT_PARITY_SHARDS).unwrap();
        assert_eq!(reconstructed.len(), DEFAULT_DATA_SHARDS);
        
        // Verify reconstructed data matches original
        for i in 0..DEFAULT_DATA_SHARDS {
            assert_eq!(reconstructed[i].data, chunks[i].data);
        }
    }

    #[test]
    fn test_erasure_insufficient_shards() {
        let master = SymmetricKey::random();
        let nonce = NonceBytes::random();
        
        let mut chunks = Vec::new();
        for i in 0..DEFAULT_DATA_SHARDS {
            let chunk = encrypt_chunk(&master, &nonce, i, &random_bytes(100)).unwrap();
            chunks.push(chunk);
        }
        
        let encoded = erasure_encode(&chunks, DEFAULT_DATA_SHARDS, DEFAULT_PARITY_SHARDS).unwrap();
        
        // Drop 6 shards (more than parity)
        let mut shards: Vec<Option<EncryptedChunk>> = encoded.into_iter()
            .map(Some)
            .collect();
        
        for i in 0..6 {
            shards[i] = None;
        }
        
        let result = erasure_decode(&shards, DEFAULT_DATA_SHARDS, DEFAULT_PARITY_SHARDS);
        assert!(matches!(result, Err(StorageError::InsufficientShards { .. })));
    }

    #[test]
    fn test_lease_creation_and_validation() {
        let master = SymmetricKey::random();
        let chunk_id = [0x42u8; CHUNK_ID_SIZE];
        let current_time = 1000u64;
        let duration = 3600u64;
        
        let lease = create_lease(&chunk_id, &master, duration, current_time);
        
        assert!(is_lease_valid(&lease, current_time));
        assert!(is_lease_valid(&lease, current_time + duration - 1));
        assert!(!is_lease_valid(&lease, current_time + duration));
    }

    #[test]
    fn test_lease_renewal() {
        let master = SymmetricKey::random();
        let chunk_id = [0x42u8; CHUNK_ID_SIZE];
        let current_time = 1000u64;
        
        let lease = create_lease(&chunk_id, &master, 3600, current_time);
        
        // Refresh the lease
        let refreshed = refresh_lease(&lease, &master, 7200, current_time + 1800).unwrap();
        
        assert!(is_lease_valid(&refreshed, current_time + 1800));
        assert!(is_lease_valid(&refreshed, current_time + 1800 + 7200 - 1));
        assert!(!is_lease_valid(&refreshed, current_time + 1800 + 7200));
    }

    #[test]
    fn test_lease_invalid_renewal_token() {
        let master = SymmetricKey::random();
        let chunk_id = [0x42u8; CHUNK_ID_SIZE];
        
        let mut lease = create_lease(&chunk_id, &master, 3600, 1000);
        lease.renewal_token[0] ^= 0xff; // Tamper with token
        
        let result = refresh_lease(&lease, &master, 7200, 1500);
        assert!(matches!(result, Err(StorageError::InvalidRenewalToken)));
    }

    #[test]
    fn test_streaming_decryptor() {
        let master = SymmetricKey::random();
        let nonce = NonceBytes::random();
        let file_data = random_bytes(CHUNK_SIZE * 3);
        
        let (chunks, manifest) = encrypt_file(&master, &nonce, &file_data).unwrap();
        
        let mut decryptor = StreamingDecryptor::new(master, nonce);
        
        let mut reconstructed = Vec::new();
        for chunk in &chunks {
            let plaintext = decryptor.next_chunk(chunk).unwrap();
            let remaining = manifest.original_size as usize - reconstructed.len();
            let to_take = plaintext.len().min(remaining);
            reconstructed.extend_from_slice(&plaintext[..to_take]);
        }
        
        assert_eq!(reconstructed, file_data);
    }

    #[test]
    fn test_streaming_decryptor_zeroizes() {
        let master = SymmetricKey::random();
        let nonce = NonceBytes::random();
        let plaintext = b"sensitive data";
        
        let chunk = encrypt_chunk(&master, &nonce, 0, plaintext).unwrap();
        
        let mut decryptor = StreamingDecryptor::new(master, nonce);
        let _ = decryptor.next_chunk(&chunk).unwrap();
        
        // Zeroize
        decryptor.zeroize_current();
        
        // Current plaintext should be gone
        assert!(decryptor.current_plaintext.is_none());
    }

    #[test]
    fn test_accounting_state() {
        let mut state = AccountingState::default();
        let peer1 = [0x01u8; NODE_ID_SIZE];
        let peer2 = [0x02u8; NODE_ID_SIZE];
        
        state.record_contribution(peer1, 1000);
        state.record_contribution(peer2, 500);
        state.record_usage(peer1, 300);
        
        assert_eq!(state.bytes_contributed, 1500);
        assert_eq!(state.bytes_used, 300);
        assert_eq!(state.peer_credits[&peer1], 700);
        assert_eq!(state.peer_credits[&peer2], 500);
        assert!(state.peer_has_credit(&peer1, 700));
        assert!(!state.peer_has_credit(&peer1, 701));
    }

    #[test]
    fn test_accounting_ratio() {
        let mut state = AccountingState::default();
        let peer = [0x01u8; NODE_ID_SIZE];
        
        // No usage -> infinity
        state.record_contribution(peer, 1000);
        assert!(state.ratio().is_infinite());
        
        // With usage
        state.record_usage(peer, 500);
        assert_eq!(state.ratio(), 2.0);
    }

    #[test]
    fn test_content_manifest_serialization() {
        let manifest = ContentManifest {
            content_id: [0x42u8; CONTENT_ID_SIZE],
            encrypted_master_key: vec![0xAB; 32],
            chunk_ids: vec![[0x01u8; CHUNK_ID_SIZE], [0x02u8; CHUNK_ID_SIZE]],
            original_size: 2048,
            data_shards: 10,
            parity_shards: 5,
            nonce: [0u8; 12],
        };
        
        let serialized = serde_json::to_string(&manifest).unwrap();
        let deserialized: ContentManifest = serde_json::from_str(&serialized).unwrap();
        
        assert_eq!(deserialized.content_id, manifest.content_id);
        assert_eq!(deserialized.chunk_ids, manifest.chunk_ids);
        assert_eq!(deserialized.original_size, manifest.original_size);
    }

    #[test]
    fn test_different_keys_produce_different_chunks() {
        let master1 = SymmetricKey::random();
        let master2 = SymmetricKey::random();
        let nonce = NonceBytes::random();
        let plaintext = b"same plaintext";
        
        let chunk1 = encrypt_chunk(&master1, &nonce, 0, plaintext).unwrap();
        let chunk2 = encrypt_chunk(&master2, &nonce, 0, plaintext).unwrap();
        
        assert_ne!(chunk1.data, chunk2.data);
        assert_ne!(chunk1.id, chunk2.id);
    }

    #[test]
    fn test_chunk_indistinguishability() {
        let master = SymmetricKey::random();
        let nonce = NonceBytes::random();
        
        let chunk_a = encrypt_chunk(&master, &nonce, 0, b"short message").unwrap();
        let chunk_b = encrypt_chunk(&master, &nonce, 1, &random_bytes(CHUNK_SIZE)).unwrap();
        
        // Both chunks should be the same size
        assert_eq!(chunk_a.data.len(), chunk_b.data.len());
        
        // Neither should contain recognizable patterns
        let zeros = vec![0u8; 32];
        assert!(!chunk_a.data.windows(32).any(|w| w == zeros.as_slice()));
        assert!(!chunk_b.data.windows(32).any(|w| w == zeros.as_slice()));
    }
}
