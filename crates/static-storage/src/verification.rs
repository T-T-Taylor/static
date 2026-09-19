//! Chunk integrity verification via segment challenges (TODO item 14)
//!
//! Extends the Proof of Space-Time system with real possession checks:
//! a node that claims to store a chunk must be able to return any
//! 4 KiB segment of it on demand. The 1:1 storage barter is no longer
//! gameable by claiming space while storing nothing.
//!
//! Mechanism:
//! - At publish time the publisher computes `blake3(segment[i])` for
//!   every [`crate::SEGMENT_SIZE`] slice of every encrypted chunk and
//!   stores the hashes in [`crate::ContentManifest::segment_hashes`].
//!   They ride inside the encrypted manifest: only nodes holding the
//!   content public key can challenge.
//! - Any manifest holder can challenge any claimed holder (Sphinx body
//!   type `0x07`): "return segment N of chunk X". Challenges are
//!   indistinguishable from cover traffic.
//! - The challenged node answers with the raw segment (`0x08`, ~4 KiB,
//!   fragmented like chunk/compute responses) or `found: false`.
//! - The challenger compares `blake3(segment_data)` against the
//!   manifest hash and records the result in accounting; repeated
//!   failures deprioritize the peer via
//!   [`static_accounting::AccountingState::should_serve`].
//!
//! Wire format (all integers big-endian):
//!
//! ```text
//! VerificationChallenge: [0x07][chunk_id 32][segment_index 4]
//!                        [nonce 32][return_route]
//!
//! VerificationResponse:  [0x08][chunk_id 32][segment_index 4]
//!                        [nonce 32][found 1][data_len 4][data..]
//!
//! return_route:          [hop_count 4][{public_key 32, node_id 16}..][destination 16]
//! ```
//!
//! Encrypted chunks are `CHUNK_SIZE + 16` bytes (AEAD tag), so full
//! chunks slice into 257 segments with a 16-byte tail; hashes are
//! stored for whatever slices exist and the last response may be
//! shorter than [`SEGMENT_SIZE`]. Hash comparison is length-agnostic.
//!
//! `ReturnRoute` is re-declared (same shape as `crate::retrieval` and
//! `crate::compute`) so this module has no dependency on either.

use crate::{ChunkId, SEGMENT_SIZE, StorageError};
use static_sphinx::NodeId;

/// Challenge message type (challenger -> holder)
pub const MSG_VERIFICATION_CHALLENGE: u8 = 0x07;

/// Response message type (holder -> challenger)
pub const MSG_VERIFICATION_RESPONSE: u8 = 0x08;

/// Maximum segment data carried by a [`VerificationResponse`] (bytes)
pub const MAX_SEGMENT_DATA_SIZE: usize = SEGMENT_SIZE;

/// A challenge asking a node to prove it holds a chunk
///
/// The challenger names one segment of one chunk. The nonce lets the
/// challenger match the (anonymous) response to this challenge and
/// prevents replaying an old response.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct VerificationChallenge {
    /// The chunk being challenged
    pub chunk_id: ChunkId,
    /// Which segment to return (index into the chunk's `SEGMENT_SIZE`
    /// slices; bounded by the manifest's per-chunk hash count)
    pub segment_index: u32,
    /// Random nonce to prevent replay and match responses
    pub nonce: [u8; 32],
    /// Return route for the response (Sphinx reply route)
    pub return_route: ReturnRoute,
}

/// A response to a [`VerificationChallenge`]
///
/// Carries the raw segment bytes (never decrypted — challenges prove
/// possession of the stored ciphertext). `found: false` with empty
/// data means the chunk or segment is not held.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct VerificationResponse {
    /// The chunk being verified
    pub chunk_id: ChunkId,
    /// The segment index requested
    pub segment_index: u32,
    /// The segment data (up to `SEGMENT_SIZE` bytes; empty when not found)
    pub segment_data: Vec<u8>,
    /// The nonce from the challenge (for matching)
    pub nonce: [u8; 32],
    /// Whether the chunk/segment was found
    pub found: bool,
}

/// A return route for anonymous verification responses
///
/// Same shape as `crate::retrieval::ReturnRoute` and
/// `crate::compute::ReturnRoute`; re-declared so this module depends
/// on neither.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct ReturnRoute {
    /// The route hops (in order from challenger to first mix)
    pub hops: Vec<RouteHopInfo>,
    /// The destination node ID (the challenger)
    pub destination: NodeId,
}

/// Route hop information for serialization
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct RouteHopInfo {
    /// The mix node's public key
    pub public_key: [u8; 32],
    /// The mix node's ID
    pub node_id: NodeId,
}

impl ReturnRoute {
    /// Convert to a Sphinx route for response packet creation
    pub fn to_sphinx_route(&self) -> static_sphinx::Route {
        static_sphinx::Route {
            hops: self
                .hops
                .iter()
                .map(|h| static_sphinx::RouteHop {
                    public_key: h.public_key,
                    node_id: h.node_id,
                })
                .collect(),
            destination: self.destination,
        }
    }

    /// Create from a Sphinx route (the challenger's own return path)
    pub fn from_sphinx_route(route: &static_sphinx::Route) -> Self {
        Self {
            hops: route
                .hops
                .iter()
                .map(|h| RouteHopInfo {
                    public_key: h.public_key,
                    node_id: h.node_id,
                })
                .collect(),
            destination: route.destination,
        }
    }
}

/// Compute segment hashes for a set of chunks
///
/// `result[chunk][segment] = blake3(segment)` where segments are
/// `SEGMENT_SIZE`-byte slices of the encrypted chunk data (the last
/// slice may be shorter). Order matches the input chunk order and the
/// manifest's `chunk_ids` order.
pub fn compute_segment_hashes(chunks: &[crate::EncryptedChunk]) -> Vec<Vec<[u8; 32]>> {
    chunks
        .iter()
        .map(|chunk| {
            chunk
                .data
                .chunks(SEGMENT_SIZE)
                .map(|segment| {
                    let mut hash = [0u8; 32];
                    hash.copy_from_slice(blake3::hash(segment).as_bytes());
                    hash
                })
                .collect()
        })
        .collect()
}

/// Verify a response against the expected segment hash
///
/// A response passes only when it claims `found` and the blake3 hash
/// of the returned data matches the manifest's hash for that segment.
/// Length is not checked separately: it is implied by the hash.
pub fn verify_segment_response(
    response: &VerificationResponse,
    expected_hash: &[u8; 32],
) -> bool {
    if !response.found {
        return false;
    }
    let mut actual = [0u8; 32];
    actual.copy_from_slice(blake3::hash(&response.segment_data).as_bytes());
    &actual == expected_hash
}

/// Serialize a verification challenge into a Sphinx body payload
pub fn serialize_challenge(challenge: &VerificationChallenge) -> Result<Vec<u8>, StorageError> {
    let mut buf = Vec::with_capacity(73 + 4 + challenge.return_route.hops.len() * 48 + 16);

    // Message type
    buf.push(MSG_VERIFICATION_CHALLENGE);

    // Chunk ID (32 bytes)
    buf.extend_from_slice(&challenge.chunk_id);

    // Segment index (4 bytes)
    buf.extend_from_slice(&challenge.segment_index.to_be_bytes());

    // Nonce (32 bytes)
    buf.extend_from_slice(&challenge.nonce);

    // Return route
    append_return_route(&mut buf, &challenge.return_route);

    Ok(buf)
}

/// Deserialize a verification challenge
pub fn deserialize_challenge(data: &[u8]) -> Result<VerificationChallenge, StorageError> {
    if data.is_empty() {
        return Err(StorageError::InvalidChunkSize {
            expected: 1,
            actual: 0,
        });
    }
    if data[0] != MSG_VERIFICATION_CHALLENGE {
        return Err(StorageError::InvalidChunkSize {
            expected: MSG_VERIFICATION_CHALLENGE as usize,
            actual: data[0] as usize,
        });
    }

    let mut offset = 1;

    let chunk_id = take_array::<32>(data, &mut offset)?;
    let index_bytes = take_array::<4>(data, &mut offset)?;
    let segment_index = u32::from_be_bytes(index_bytes);
    let nonce = take_array::<32>(data, &mut offset)?;
    let return_route = take_return_route(data, &mut offset)?;

    Ok(VerificationChallenge {
        chunk_id,
        segment_index,
        nonce,
        return_route,
    })
}

/// Serialize a verification response into a Sphinx body payload
pub fn serialize_response(resp: &VerificationResponse) -> Result<Vec<u8>, StorageError> {
    if resp.segment_data.len() > MAX_SEGMENT_DATA_SIZE {
        return Err(StorageError::InvalidChunkSize {
            expected: MAX_SEGMENT_DATA_SIZE,
            actual: resp.segment_data.len(),
        });
    }

    let mut buf = Vec::with_capacity(74 + resp.segment_data.len());

    // Message type
    buf.push(MSG_VERIFICATION_RESPONSE);

    // Chunk ID (32 bytes)
    buf.extend_from_slice(&resp.chunk_id);

    // Segment index (4 bytes)
    buf.extend_from_slice(&resp.segment_index.to_be_bytes());

    // Nonce (32 bytes)
    buf.extend_from_slice(&resp.nonce);

    // Found flag (1 byte)
    buf.push(if resp.found { 1 } else { 0 });

    // Segment data length (4 bytes) + data
    buf.extend_from_slice(&(resp.segment_data.len() as u32).to_be_bytes());
    buf.extend_from_slice(&resp.segment_data);

    Ok(buf)
}

/// Deserialize a verification response
pub fn deserialize_response(data: &[u8]) -> Result<VerificationResponse, StorageError> {
    if data.is_empty() {
        return Err(StorageError::InvalidChunkSize {
            expected: 1,
            actual: 0,
        });
    }
    if data[0] != MSG_VERIFICATION_RESPONSE {
        return Err(StorageError::InvalidChunkSize {
            expected: MSG_VERIFICATION_RESPONSE as usize,
            actual: data[0] as usize,
        });
    }

    let mut offset = 1;

    let chunk_id = take_array::<32>(data, &mut offset)?;
    let index_bytes = take_array::<4>(data, &mut offset)?;
    let segment_index = u32::from_be_bytes(index_bytes);
    let nonce = take_array::<32>(data, &mut offset)?;

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
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ]) as usize;
    offset += 4;

    if data_len > MAX_SEGMENT_DATA_SIZE {
        return Err(StorageError::InvalidChunkSize {
            expected: MAX_SEGMENT_DATA_SIZE,
            actual: data_len,
        });
    }
    if offset + data_len > data.len() {
        return Err(StorageError::InvalidChunkSize {
            expected: offset + data_len,
            actual: data.len(),
        });
    }
    let segment_data = data[offset..offset + data_len].to_vec();

    Ok(VerificationResponse {
        chunk_id,
        segment_index,
        nonce,
        segment_data,
        found,
    })
}

/// Append the return route encoding: `[hop_count 4][hops 48 each][destination 16]`
fn append_return_route(buf: &mut Vec<u8>, route: &ReturnRoute) {
    buf.extend_from_slice(&(route.hops.len() as u32).to_be_bytes());
    for hop in &route.hops {
        buf.extend_from_slice(&hop.public_key);
        buf.extend_from_slice(&hop.node_id);
    }
    buf.extend_from_slice(&route.destination);
}

/// Read `N` bytes as a fixed array, advancing `offset`
fn take_array<const N: usize>(
    data: &[u8],
    offset: &mut usize,
) -> Result<[u8; N], StorageError> {
    if *offset + N > data.len() {
        return Err(StorageError::InvalidChunkSize {
            expected: *offset + N,
            actual: data.len(),
        });
    }
    let mut out = [0u8; N];
    out.copy_from_slice(&data[*offset..*offset + N]);
    *offset += N;
    Ok(out)
}

/// Read the return route encoding starting at `offset`
fn take_return_route(data: &[u8], offset: &mut usize) -> Result<ReturnRoute, StorageError> {
    let count_bytes = take_array::<4>(data, offset)?;
    let hop_count = u32::from_be_bytes(count_bytes) as usize;

    // DoS bound (H6): cap before allocating. Legit routes are 1 hop.
    if hop_count > 32 {
        return Err(StorageError::InvalidChunkSize {
            expected: 32,
            actual: hop_count,
        });
    }
    let mut hops = Vec::with_capacity(hop_count);
    for _ in 0..hop_count {
        let public_key = take_array::<32>(data, offset)?;
        let node_id = take_array::<16>(data, offset)?;
        hops.push(RouteHopInfo { public_key, node_id });
    }
    let destination = take_array::<16>(data, offset)?;

    Ok(ReturnRoute {
        hops,
        destination,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{SEGMENT_SIZE, CHUNK_ID_SIZE, EncryptedChunk};
    use rand::RngCore;

    fn random_chunk_id() -> ChunkId {
        let mut id = [0u8; CHUNK_ID_SIZE];
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

    fn random_return_route() -> ReturnRoute {
        ReturnRoute {
            hops: vec![random_route_hop(), random_route_hop()],
            destination: random_node_id(),
        }
    }

    /// A fake encrypted chunk of `2 * SEGMENT_SIZE + 100` bytes: three
    /// slices (4 KiB, 4 KiB, 100 bytes).
    fn test_chunk() -> EncryptedChunk {
        let mut data = vec![0u8; 2 * SEGMENT_SIZE + 100];
        rand::rngs::OsRng.fill_bytes(&mut data);
        EncryptedChunk {
            id: random_chunk_id(),
            data,
        }
    }

    #[test]
    fn test_compute_segment_hashes() {
        let chunk = test_chunk();
        let hashes = compute_segment_hashes(&[chunk.clone()]);

        // One chunk, three segments (2 full + 100-byte tail)
        assert_eq!(hashes.len(), 1);
        assert_eq!(hashes[0].len(), 3);

        // Hash values match blake3 of the actual slices
        let expected_0 = blake3::hash(&chunk.data[0..SEGMENT_SIZE]);
        let expected_2 = blake3::hash(&chunk.data[2 * SEGMENT_SIZE..]);
        assert_eq!(hashes[0][0], *expected_0.as_bytes());
        assert_eq!(hashes[0][2], *expected_2.as_bytes());

        // Nominal SEGMENTS_PER_CHUNK stays 256; real counts come from
        // the stored hashes.
        assert_eq!(crate::SEGMENTS_PER_CHUNK, 256);
    }

    #[test]
    fn test_segment_hash_verification() {
        let chunk = test_chunk();
        let hashes = compute_segment_hashes(&[chunk.clone()]);

        // Valid segment passes
        let response = VerificationResponse {
            chunk_id: chunk.id,
            segment_index: 1,
            segment_data: chunk.data[SEGMENT_SIZE..2 * SEGMENT_SIZE].to_vec(),
            nonce: [0x11u8; 32],
            found: true,
        };
        assert!(verify_segment_response(&response, &hashes[0][1]));

        // Tampered segment (same length, different bytes) fails
        let mut tampered = response.clone();
        tampered.segment_data[0] ^= 0xFF;
        assert!(!verify_segment_response(&tampered, &hashes[0][1]));

        // Swapped segment (valid data, wrong index expectation) fails
        let mut swapped = response.clone();
        swapped.segment_data = chunk.data[0..SEGMENT_SIZE].to_vec();
        assert!(!verify_segment_response(&swapped, &hashes[0][1]));

        // Not-found never passes
        let mut missing = response;
        missing.found = false;
        assert!(!verify_segment_response(&missing, &hashes[0][1]));
    }

    #[test]
    fn test_verification_challenge_serialization() {
        let challenge = VerificationChallenge {
            chunk_id: random_chunk_id(),
            segment_index: 257,
            nonce: [0x22u8; 32],
            return_route: random_return_route(),
        };

        let serialized = serialize_challenge(&challenge).unwrap();
        assert_eq!(serialized[0], MSG_VERIFICATION_CHALLENGE);

        // Layout: 1 + 32 + 4 + 32 + (4 + 2*48 + 16) = 185 bytes
        assert_eq!(serialized.len(), 185);

        let deserialized = deserialize_challenge(&serialized).unwrap();
        assert_eq!(deserialized, challenge);
    }

    #[test]
    fn test_verification_response_serialization() {
        let mut segment = vec![0u8; SEGMENT_SIZE];
        rand::rngs::OsRng.fill_bytes(&mut segment);

        let response = VerificationResponse {
            chunk_id: random_chunk_id(),
            segment_index: 42,
            segment_data: segment,
            nonce: [0x33u8; 32],
            found: true,
        };

        let serialized = serialize_response(&response).unwrap();
        assert_eq!(serialized[0], MSG_VERIFICATION_RESPONSE);

        // Layout: 1 + 32 + 4 + 32 + 1 + 4 + 4096 = 4170 bytes
        assert_eq!(serialized.len(), 4170);

        let deserialized = deserialize_response(&serialized).unwrap();
        assert_eq!(deserialized, response);
    }

    #[test]
    fn test_verification_response_not_found() {
        let response = VerificationResponse {
            chunk_id: random_chunk_id(),
            segment_index: 0,
            segment_data: vec![],
            nonce: [0x44u8; 32],
            found: false,
        };

        let serialized = serialize_response(&response).unwrap();
        let deserialized = deserialize_response(&serialized).unwrap();

        assert!(!deserialized.found);
        assert!(deserialized.segment_data.is_empty());
        assert_eq!(deserialized.nonce, response.nonce);

        // Oversized segment data is rejected
        let oversized = VerificationResponse {
            segment_data: vec![0u8; MAX_SEGMENT_DATA_SIZE + 1],
            found: true,
            ..response.clone()
        };
        assert!(serialize_response(&oversized).is_err());
        let mut bad = serialize_response(&response).unwrap();
        // Corrupt the data_len field to exceed the cap: offset 73..77
        let len_pos = 1 + 32 + 4 + 32 + 1;
        bad[len_pos..len_pos + 4].copy_from_slice(&(MAX_SEGMENT_DATA_SIZE as u32 + 1).to_be_bytes());
        assert!(deserialize_response(&bad).is_err());

        // Wrong type byte is rejected
        let wrong_type = vec![0xFFu8; 40];
        assert!(deserialize_challenge(&wrong_type).is_err());
        assert!(deserialize_response(&wrong_type).is_err());
    }
}
