//! Chunk retrieval protocol over Sphinx
//!
//! Implements:
//! - ChunkRequest messages (requester -> holding node)
//! - ChunkResponse messages (holding node -> requester)
//! - Reply blocks for anonymous responses (Sphinx reply mechanism)
//! - Content assembly from retrieved chunks
//!
//! All requests and responses are Sphinx packet bodies, making them
//! indistinguishable from cover traffic. The holding node does not
//! know who requested the chunk, and the requester does not know
//! which node provided it (beyond the mixnet's properties).

use crate::{
    EncryptedChunk, ChunkId, ContentId, ContentManifest,
    StorageError, decrypt_file,
};
use static_crypto::SymmetricKey;
use static_sphinx::{Route, NodeId};
use std::collections::HashMap;

/// Chunk request message type
pub const MSG_CHUNK_REQUEST: u8 = 0x01;

/// Chunk response message type
pub const MSG_CHUNK_RESPONSE: u8 = 0x02;

/// Maximum return-route hops accepted during deserialization (DoS bound).
///
/// Legit return routes are 1 hop; cap prevents `u32::MAX` pre-alloc.
pub const MAX_RETRIEVAL_ROUTE_HOPS: usize = 32;

/// Maximum serialized SURB bytes accepted in a chunk request (DoS bound).
///
/// A hybrid SURB is ~5.9 KiB; the cap allows hybrid SURBs plus slack
/// while rejecting absurd allocations.
pub const MAX_SERIALIZED_SURB_SIZE: usize = 16 * 1024;

/// A chunk request sent through the mixnet
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ChunkRequest {
    /// The chunk ID being requested
    pub chunk_id: ChunkId,
    /// A return route for the response (Sphinx reply block)
    /// This is a pre-built route back to the requester
    pub return_route: ReturnRoute,
    /// Serialized SURB for session-based responses (optional)
    ///
    /// When present, responses travel as a reply-session: the first
    /// fragment wrapped with the full SURB (establishing the cached
    /// session at every hop), subsequent fragments as lightweight
    /// session replies. The SURB is opaque to the holder beyond the
    /// first hop.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub surb: Option<Vec<u8>>,
}

/// A chunk response sent through the mixnet
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ChunkResponse {
    /// The chunk ID being responded to
    pub chunk_id: ChunkId,
    /// The encrypted chunk data
    pub chunk_data: Vec<u8>,
    /// Whether the chunk was found
    pub found: bool,
}

/// A return route for anonymous responses
///
/// This contains the information needed to send a Sphinx packet
/// back to the requester without knowing their identity.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ReturnRoute {
    /// The route hops (in order from requester to first mix)
    pub hops: Vec<RouteHopInfo>,
    /// The destination node ID (the requester)
    pub destination: NodeId,
}

/// Route hop information for serialization
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RouteHopInfo {
    /// The mix node's public key
    pub public_key: [u8; 32],
    /// The mix node's ID
    pub node_id: NodeId,
}

impl ReturnRoute {
    /// Convert to a Sphinx Route
    pub fn to_sphinx_route(&self) -> Route {
        Route {
            hops: self.hops.iter()
                .map(|h| static_sphinx::RouteHop {
                    public_key: h.public_key,
                    node_id: h.node_id,
                })
                .collect(),
            destination: self.destination,
        }
    }

    /// Create from a Sphinx Route
    pub fn from_sphinx_route(route: &Route) -> Self {
        Self {
            hops: route.hops.iter()
                .map(|h| RouteHopInfo {
                    public_key: h.public_key,
                    node_id: h.node_id,
                })
                .collect(),
            destination: route.destination,
        }
    }
}

/// Serialize a chunk request
pub fn serialize_request(req: &ChunkRequest) -> Vec<u8> {
    let mut buf = Vec::new();

    // Message type
    buf.push(MSG_CHUNK_REQUEST);

    // Chunk ID (32 bytes)
    buf.extend_from_slice(&req.chunk_id);

    // Return route
    buf.extend_from_slice(&(req.return_route.hops.len() as u32).to_be_bytes());
    for hop in &req.return_route.hops {
        buf.extend_from_slice(&hop.public_key);
        buf.extend_from_slice(&hop.node_id);
    }
    buf.extend_from_slice(&req.return_route.destination);

    // Optional serialized SURB ([1 present][4 len][bytes]); older
    // requests end at the destination and parse without it.
    if let Some(surb) = &req.surb {
        buf.push(1);
        buf.extend_from_slice(&(surb.len() as u32).to_be_bytes());
        buf.extend_from_slice(surb);
    }

    buf
}

/// Deserialize a chunk request
pub fn deserialize_request(data: &[u8]) -> Result<ChunkRequest, StorageError> {
    if data.is_empty() {
        return Err(StorageError::InvalidChunkSize {
            expected: 1,
            actual: 0,
        });
    }

    if data[0] != MSG_CHUNK_REQUEST {
        return Err(StorageError::InvalidChunkSize {
            expected: MSG_CHUNK_REQUEST as usize,
            actual: data[0] as usize,
        });
    }

    let mut offset = 1;

    if offset + 32 > data.len() {
        return Err(StorageError::InvalidChunkSize {
            expected: offset + 32,
            actual: data.len(),
        });
    }
    let mut chunk_id = [0u8; 32];
    chunk_id.copy_from_slice(&data[offset..offset + 32]);
    offset += 32;

    if offset + 4 > data.len() {
        return Err(StorageError::InvalidChunkSize {
            expected: offset + 4,
            actual: data.len(),
        });
    }
    let hop_count = u32::from_be_bytes([
        data[offset], data[offset + 1], data[offset + 2], data[offset + 3],
    ]) as usize;
    offset += 4;

    if hop_count > MAX_RETRIEVAL_ROUTE_HOPS {
        return Err(StorageError::InvalidChunkSize {
            expected: MAX_RETRIEVAL_ROUTE_HOPS,
            actual: hop_count,
        });
    }
    let mut hops = Vec::with_capacity(hop_count);
    for _ in 0..hop_count {
        if offset + 48 > data.len() {
            return Err(StorageError::InvalidChunkSize {
                expected: offset + 48,
                actual: data.len(),
            });
        }
        let mut public_key = [0u8; 32];
        public_key.copy_from_slice(&data[offset..offset + 32]);
        offset += 32;

        let mut node_id = [0u8; 16];
        node_id.copy_from_slice(&data[offset..offset + 16]);
        offset += 16;

        hops.push(RouteHopInfo { public_key, node_id });
    }

    if offset + 16 > data.len() {
        return Err(StorageError::InvalidChunkSize {
            expected: offset + 16,
            actual: data.len(),
        });
    }
    let mut destination = [0u8; 16];
    destination.copy_from_slice(&data[offset..offset + 16]);
    offset += 16;

    // Optional serialized SURB suffix (session-based requests). Sphinx
    // bodies are zero-padded to BODY_SIZE; a genuine suffix always has
    // non-zero bytes (its present marker is 1), so all-zero tails are
    // padding.
    let has_surb = data.len() > offset && data[offset..].iter().any(|&b| b != 0);
    let surb = if has_surb {
        if offset + 5 > data.len() || data[offset] != 1 {
            return Err(StorageError::InvalidChunkSize {
                expected: offset + 5,
                actual: data.len(),
            });
        }
        let surb_len = u32::from_be_bytes([
            data[offset + 1], data[offset + 2], data[offset + 3], data[offset + 4],
        ]) as usize;
        if surb_len > MAX_SERIALIZED_SURB_SIZE || data.len() < offset + 5 + surb_len {
            return Err(StorageError::InvalidChunkSize {
                expected: MAX_SERIALIZED_SURB_SIZE,
                actual: surb_len,
            });
        }
        let surb = data[offset + 5..offset + 5 + surb_len].to_vec();
        Some(surb)
    } else {
        None
    };

    Ok(ChunkRequest {
        chunk_id,
        return_route: ReturnRoute { hops, destination },
        surb,
    })
}

/// Serialize a chunk response
pub fn serialize_response(resp: &ChunkResponse) -> Vec<u8> {
    let mut buf = Vec::new();

    // Message type
    buf.push(MSG_CHUNK_RESPONSE);

    // Chunk ID (32 bytes)
    buf.extend_from_slice(&resp.chunk_id);

    // Found flag (1 byte)
    buf.push(if resp.found { 1 } else { 0 });

    // Chunk data length (4 bytes) + data
    buf.extend_from_slice(&(resp.chunk_data.len() as u32).to_be_bytes());
    buf.extend_from_slice(&resp.chunk_data);

    buf
}

/// Deserialize a chunk response
pub fn deserialize_response(data: &[u8]) -> Result<ChunkResponse, StorageError> {
    if data.is_empty() {
        return Err(StorageError::InvalidChunkSize {
            expected: 1,
            actual: 0,
        });
    }

    if data[0] != MSG_CHUNK_RESPONSE {
        return Err(StorageError::InvalidChunkSize {
            expected: MSG_CHUNK_RESPONSE as usize,
            actual: data[0] as usize,
        });
    }

    let mut offset = 1;

    if offset + 32 > data.len() {
        return Err(StorageError::InvalidChunkSize {
            expected: offset + 32,
            actual: data.len(),
        });
    }
    let mut chunk_id = [0u8; 32];
    chunk_id.copy_from_slice(&data[offset..offset + 32]);
    offset += 32;

    if offset + 1 > data.len() {
        return Err(StorageError::InvalidChunkSize {
            expected: offset + 1,
            actual: data.len(),
        });
    }
    let found = data[offset] == 1;
    offset += 1;

    if offset + 4 > data.len() {
        return Err(StorageError::InvalidChunkSize {
            expected: offset + 4,
            actual: data.len(),
        });
    }
    let data_len = u32::from_be_bytes([
        data[offset], data[offset + 1], data[offset + 2], data[offset + 3],
    ]) as usize;
    offset += 4;

    if offset + data_len > data.len() {
        return Err(StorageError::InvalidChunkSize {
            expected: offset + data_len,
            actual: data.len(),
        });
    }
    let chunk_data = data[offset..offset + data_len].to_vec();

    Ok(ChunkResponse {
        chunk_id,
        chunk_data,
        found,
    })
}

/// Content retriever
///
/// Manages the retrieval of content from the network.
/// Tracks which chunks have been received and assembles them.
pub struct ContentRetriever {
    /// Pending chunk requests (chunk_id -> expected)
    pub pending: HashMap<ChunkId, bool>,
    /// Received chunks (chunk_id -> chunk)
    pub received: HashMap<ChunkId, EncryptedChunk>,
    /// The manifest for the content being retrieved
    pub manifest: Option<ContentManifest>,
    /// The master key for decryption
    pub master_key: Option<SymmetricKey>,
    /// The nonce for decryption
    pub nonce: Option<[u8; 12]>,
}

impl ContentRetriever {
    /// Create a new retriever
    pub fn new() -> Self {
        Self {
            pending: HashMap::new(),
            received: HashMap::new(),
            manifest: None,
            master_key: None,
            nonce: None,
        }
    }

    /// Start retrieving content
    pub fn start_retrieval(
        &mut self,
        manifest: ContentManifest,
        master_key: SymmetricKey,
    ) {
        self.manifest = Some(manifest.clone());
        self.master_key = Some(master_key);
        self.nonce = Some(manifest.nonce);

        for chunk_id in &manifest.chunk_ids {
            self.pending.insert(*chunk_id, true);
        }
    }

    /// Record a received chunk
    pub fn record_chunk(&mut self, chunk: EncryptedChunk) -> Result<bool, StorageError> {
        if !self.pending.contains_key(&chunk.id) {
            return Ok(false); // Not expecting this chunk
        }

        self.pending.remove(&chunk.id);
        self.received.insert(chunk.id, chunk);

        Ok(true)
    }

    /// Check if all chunks have been received
    pub fn is_complete(&self) -> bool {
        if self.pending.is_empty() && self.manifest.is_some() {
            if let Some(manifest) = &self.manifest {
                return self.received.len() == manifest.chunk_ids.len();
            }
        }
        false
    }

    /// Assemble the decrypted content
    ///
    /// Only one chunk is decrypted at a time (RAM safety).
    /// The caller should zeroize the result after use.
    pub fn assemble(&self) -> Result<Vec<u8>, StorageError> {
        let manifest = self.manifest.as_ref()
            .ok_or(StorageError::ContentNotFound)?;
        let master_key = self.master_key.as_ref()
            .ok_or(StorageError::ContentNotFound)?;
        let nonce_bytes = self.nonce.as_ref()
            .ok_or(StorageError::ContentNotFound)?;

        // Collect chunks in order
        let mut chunks = Vec::with_capacity(manifest.chunk_ids.len());
        for chunk_id in &manifest.chunk_ids {
            let chunk = self.received.get(chunk_id)
                .ok_or(StorageError::ContentNotFound)?;
            chunks.push(chunk.clone());
        }

        let nonce = static_crypto::NonceBytes::from_bytes(*nonce_bytes);
        decrypt_file(master_key, &nonce, &chunks, manifest)
    }

    /// Get the number of pending chunks
    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }

    /// Get the number of received chunks
    pub fn received_count(&self) -> usize {
        self.received.len()
    }

    /// Get progress (0.0 to 1.0)
    pub fn progress(&self) -> f64 {
        if let Some(manifest) = &self.manifest {
            if manifest.chunk_ids.is_empty() {
                return 1.0;
            }
            return self.received.len() as f64 / manifest.chunk_ids.len() as f64;
        }
        0.0
    }
}

impl Default for ContentRetriever {
    fn default() -> Self {
        Self::new()
    }
}

/// Chunk holder
///
/// Tracks which chunks this node is holding and serves requests.
pub struct ChunkHolder {
    /// Chunks we're storing (chunk_id -> chunk data)
    pub chunks: HashMap<ChunkId, Vec<u8>>,
    /// Chunk to content mapping (chunk_id -> content_id)
    pub chunk_to_content: HashMap<ChunkId, ContentId>,
}

impl ChunkHolder {
    /// Create a new chunk holder
    pub fn new() -> Self {
        Self {
            chunks: HashMap::new(),
            chunk_to_content: HashMap::new(),
        }
    }

    /// Add a chunk
    pub fn add_chunk(&mut self, chunk_id: ChunkId, data: Vec<u8>, content_id: ContentId) {
        self.chunks.insert(chunk_id, data);
        self.chunk_to_content.insert(chunk_id, content_id);
    }

    /// Remove a chunk
    pub fn remove_chunk(&mut self, chunk_id: &ChunkId) {
        self.chunks.remove(chunk_id);
        self.chunk_to_content.remove(chunk_id);
    }

    /// Check if we have a chunk
    pub fn has_chunk(&self, chunk_id: &ChunkId) -> bool {
        self.chunks.contains_key(chunk_id)
    }

    /// Get chunk data
    pub fn get_chunk(&self, chunk_id: &ChunkId) -> Option<&Vec<u8>> {
        self.chunks.get(chunk_id)
    }

    /// Handle a chunk request
    ///
    /// Returns a ChunkResponse if we have the chunk, None otherwise.
    pub fn handle_request(&self, request: &ChunkRequest) -> Option<ChunkResponse> {
        if let Some(data) = self.chunks.get(&request.chunk_id) {
            return Some(ChunkResponse {
                chunk_id: request.chunk_id,
                chunk_data: data.clone(),
                found: true,
            });
        }
        Some(ChunkResponse {
            chunk_id: request.chunk_id,
            chunk_data: vec![],
            found: false,
        })
    }

    /// Get the number of chunks held
    pub fn chunk_count(&self) -> usize {
        self.chunks.len()
    }

    /// Get total bytes stored
    pub fn total_bytes(&self) -> u64 {
        self.chunks.values().map(|d| d.len() as u64).sum()
    }
}

impl Default for ChunkHolder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{encrypt_file, CHUNK_SIZE};
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

    fn random_node_id() -> NodeId {
        let mut id = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut id);
        id
    }

    fn random_route_hop() -> RouteHopInfo {
        let mut pub_key = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut pub_key);
        RouteHopInfo {
            public_key: pub_key,
            node_id: random_node_id(),
        }
    }

    #[test]
    fn test_chunk_request_serialization() {
        let req = ChunkRequest {
            chunk_id: random_chunk_id(),
            return_route: ReturnRoute {
                hops: vec![random_route_hop(), random_route_hop()],
                destination: random_node_id(),
            },
            surb: None, };

        let serialized = serialize_request(&req);
        let deserialized = deserialize_request(&serialized).unwrap();

        assert_eq!(deserialized.chunk_id, req.chunk_id);
        assert_eq!(deserialized.return_route.hops.len(), 2);
        assert_eq!(deserialized.return_route.destination, req.return_route.destination);
    }

    #[test]
    fn test_chunk_request_empty_route() {
        let req = ChunkRequest {
            chunk_id: random_chunk_id(),
            return_route: ReturnRoute {
                hops: vec![],
                destination: random_node_id(),
            },
            surb: None, };

        let serialized = serialize_request(&req);
        let deserialized = deserialize_request(&serialized).unwrap();

        assert_eq!(deserialized.return_route.hops.len(), 0);
    }

    #[test]
    fn test_chunk_response_serialization() {
        let resp = ChunkResponse {
            chunk_id: random_chunk_id(),
            chunk_data: vec![0xABu8; 1024],
            found: true,
        };

        let serialized = serialize_response(&resp);
        let deserialized = deserialize_response(&serialized).unwrap();

        assert_eq!(deserialized.chunk_id, resp.chunk_id);
        assert_eq!(deserialized.chunk_data, resp.chunk_data);
        assert!(deserialized.found);
    }

    #[test]
    fn test_chunk_response_not_found() {
        let resp = ChunkResponse {
            chunk_id: random_chunk_id(),
            chunk_data: vec![],
            found: false,
        };

        let serialized = serialize_response(&resp);
        let deserialized = deserialize_response(&serialized).unwrap();

        assert!(!deserialized.found);
        assert!(deserialized.chunk_data.is_empty());
    }

    #[test]
    fn test_chunk_holder_add_remove() {
        let mut holder = ChunkHolder::new();
        let chunk_id = random_chunk_id();
        let content_id = random_content_id();
        let data = vec![0xABu8; 1024];

        holder.add_chunk(chunk_id, data.clone(), content_id);
        assert!(holder.has_chunk(&chunk_id));
        assert_eq!(holder.get_chunk(&chunk_id).unwrap(), &data);

        holder.remove_chunk(&chunk_id);
        assert!(!holder.has_chunk(&chunk_id));
    }

    #[test]
    fn test_chunk_holder_handle_request() {
        let mut holder = ChunkHolder::new();
        let chunk_id = random_chunk_id();
        let content_id = random_content_id();
        let data = vec![0xABu8; 1024];

        holder.add_chunk(chunk_id, data.clone(), content_id);

        let req = ChunkRequest {
            chunk_id,
            return_route: ReturnRoute {
                hops: vec![],
                destination: random_node_id(),
            },
            surb: None, };

        let resp = holder.handle_request(&req).unwrap();
        assert!(resp.found);
        assert_eq!(resp.chunk_data, data);
    }

    #[test]
    fn test_chunk_holder_handle_request_not_found() {
        let holder = ChunkHolder::new();

        let req = ChunkRequest {
            chunk_id: random_chunk_id(),
            return_route: ReturnRoute {
                hops: vec![],
                destination: random_node_id(),
            },
            surb: None, };

        let resp = holder.handle_request(&req).unwrap();
        assert!(!resp.found);
        assert!(resp.chunk_data.is_empty());
    }

    #[test]
    fn test_content_retriever_basic() {
        let retriever = ContentRetriever::new();
        assert_eq!(retriever.progress(), 0.0);
        assert!(!retriever.is_complete());
    }

    #[test]
    fn test_content_retriever_progress() {
        let master = SymmetricKey::random();
        let nonce = NonceBytes::random();
        let file_data = vec![0x42u8; CHUNK_SIZE * 3];

        let (chunks, manifest) = encrypt_file(&master, &nonce, &file_data).unwrap();

        let mut retriever = ContentRetriever::new();
        retriever.start_retrieval(manifest, master);

        assert_eq!(retriever.pending_count(), 3);
        assert_eq!(retriever.received_count(), 0);
        assert!((retriever.progress() - 0.0).abs() < 0.01);

        // Receive first chunk
        retriever.record_chunk(chunks[0].clone()).unwrap();
        assert_eq!(retriever.pending_count(), 2);
        assert!((retriever.progress() - 0.333).abs() < 0.01);

        // Receive second chunk
        retriever.record_chunk(chunks[1].clone()).unwrap();
        assert_eq!(retriever.pending_count(), 1);
        assert!((retriever.progress() - 0.666).abs() < 0.01);

        // Receive third chunk
        retriever.record_chunk(chunks[2].clone()).unwrap();
        assert_eq!(retriever.pending_count(), 0);
        assert!(retriever.is_complete());
        assert!((retriever.progress() - 1.0).abs() < 0.01);
    }

    #[test]
    fn test_content_retriever_assemble() {
        let master = SymmetricKey::random();
        let nonce = NonceBytes::random();
        let file_data = vec![0x42u8; CHUNK_SIZE * 2 + 100];

        let (chunks, manifest) = encrypt_file(&master, &nonce, &file_data).unwrap();

        let mut retriever = ContentRetriever::new();
        retriever.start_retrieval(manifest, master);

        for chunk in &chunks {
            retriever.record_chunk(chunk.clone()).unwrap();
        }

        assert!(retriever.is_complete());
        let assembled = retriever.assemble().unwrap();
        assert_eq!(assembled, file_data);
    }

    #[test]
    fn test_content_retriever_unexpected_chunk() {
        let mut retriever = ContentRetriever::new();

        let unexpected_chunk = EncryptedChunk {
            id: random_chunk_id(),
            data: vec![0u8; 1024],
        };

        let accepted = retriever.record_chunk(unexpected_chunk).unwrap();
        assert!(!accepted);
    }

    #[test]
    fn test_content_retriever_assemble_incomplete() {
        let master = SymmetricKey::random();
        let nonce = NonceBytes::random();
        let file_data = vec![0x42u8; CHUNK_SIZE * 3];

        let (chunks, manifest) = encrypt_file(&master, &nonce, &file_data).unwrap();

        let mut retriever = ContentRetriever::new();
        retriever.start_retrieval(manifest, master);

        // Only receive 2 of 3 chunks
        retriever.record_chunk(chunks[0].clone()).unwrap();
        retriever.record_chunk(chunks[1].clone()).unwrap();

        assert!(!retriever.is_complete());
        assert!(retriever.assemble().is_err());
    }

    #[test]
    fn test_return_route_conversion() {
        let route = Route {
            hops: vec![
                static_sphinx::RouteHop {
                    public_key: [0x01u8; 32],
                    node_id: [0x01u8; 16],
                },
                static_sphinx::RouteHop {
                    public_key: [0x02u8; 32],
                    node_id: [0x02u8; 16],
                },
            ],
            destination: [0xFFu8; 16],
        };

        let return_route = ReturnRoute::from_sphinx_route(&route);
        assert_eq!(return_route.hops.len(), 2);
        assert_eq!(return_route.destination, [0xFFu8; 16]);

        let converted_back = return_route.to_sphinx_route();
        assert_eq!(converted_back.hops.len(), 2);
        assert_eq!(converted_back.destination, [0xFFu8; 16]);
        assert_eq!(converted_back.hops[0].node_id, [0x01u8; 16]);
    }

    #[test]
    fn test_chunk_holder_stats() {
        let mut holder = ChunkHolder::new();

        holder.add_chunk(random_chunk_id(), vec![0u8; 1024], random_content_id());
        holder.add_chunk(random_chunk_id(), vec![0u8; 2048], random_content_id());

        assert_eq!(holder.chunk_count(), 2);
        assert_eq!(holder.total_bytes(), 3072);
    }

    #[test]
    fn test_deserialize_request_invalid_type() {
        let data = vec![0xFFu8; 40];
        let result = deserialize_request(&data);
        assert!(result.is_err());
    }

    #[test]
    fn test_deserialize_response_invalid_type() {
        let data = vec![0xFFu8; 40];
        let result = deserialize_response(&data);
        assert!(result.is_err());
    }
}
