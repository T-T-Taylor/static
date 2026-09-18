//! Missing-chunk gossip protocol (Phase 1, active reseed)
//!
//! When a node detects that a chunk is missing from the network (a peer
//! answered `found: false`, or the repair loop could not gather enough
//! shards), it reports the miss to the content's hidden service address.
//! The host — whichever peer still holds the chunk in its HostBuffer —
//! reseeds it locally and sends it back through the reporter's return
//! route.
//!
//! The message is a Sphinx packet body (type byte `0x09`): it is always
//! fragmented and hybrid-Sphinx-wrapped, never clear JSON, so it is
//! indistinguishable from cover traffic (Phase 0, C6).

use crate::{ChunkId, ContentId, StorageError, retrieval::ReturnRoute};

/// Missing-chunk gossip message type (Sphinx body dispatch)
pub const MSG_MISSING_CHUNK_GOSSIP: u8 = 0x09;

/// A report that a chunk is missing from the network
///
/// Sent by a node that failed to retrieve a chunk; the node that still
/// holds the chunk in its HostBuffer reseeds it and returns it via
/// `return_route`.
#[derive(Debug, Clone)]
pub struct MissingChunkGossip {
    /// The content ID that has a missing chunk
    pub content_id: ContentId,
    /// The chunk ID that was not found
    pub chunk_id: ChunkId,
    /// When the missing chunk was detected (unix secs)
    pub timestamp: u64,
    /// Return route for the host to send the reseeded chunk back
    pub return_route: ReturnRoute,
}

/// Serialize a missing-chunk gossip message (type byte + binary fields)
pub fn serialize_gossip(gossip: &MissingChunkGossip) -> Vec<u8> {
    let mut buf = Vec::new();

    // Message type
    buf.push(MSG_MISSING_CHUNK_GOSSIP);

    // Content ID (32 bytes)
    buf.extend_from_slice(&gossip.content_id);

    // Chunk ID (32 bytes)
    buf.extend_from_slice(&gossip.chunk_id);

    // Timestamp (8 bytes)
    buf.extend_from_slice(&gossip.timestamp.to_be_bytes());

    // Return route (same layout as ChunkRequest)
    buf.extend_from_slice(&(gossip.return_route.hops.len() as u32).to_be_bytes());
    for hop in &gossip.return_route.hops {
        buf.extend_from_slice(&hop.public_key);
        buf.extend_from_slice(&hop.node_id);
    }
    buf.extend_from_slice(&gossip.return_route.destination);

    buf
}

/// Deserialize a missing-chunk gossip message
pub fn deserialize_gossip(data: &[u8]) -> Result<MissingChunkGossip, StorageError> {
    if data.is_empty() {
        return Err(StorageError::InvalidChunkSize {
            expected: 1,
            actual: 0,
        });
    }

    if data[0] != MSG_MISSING_CHUNK_GOSSIP {
        return Err(StorageError::InvalidChunkSize {
            expected: MSG_MISSING_CHUNK_GOSSIP as usize,
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
    let mut content_id = [0u8; 32];
    content_id.copy_from_slice(&data[offset..offset + 32]);
    offset += 32;

    if offset + 32 > data.len() {
        return Err(StorageError::InvalidChunkSize {
            expected: offset + 32,
            actual: data.len(),
        });
    }
    let mut chunk_id = [0u8; 32];
    chunk_id.copy_from_slice(&data[offset..offset + 32]);
    offset += 32;

    if offset + 8 > data.len() {
        return Err(StorageError::InvalidChunkSize {
            expected: offset + 8,
            actual: data.len(),
        });
    }
    let timestamp = u64::from_be_bytes([
        data[offset], data[offset + 1], data[offset + 2], data[offset + 3],
        data[offset + 4], data[offset + 5], data[offset + 6], data[offset + 7],
    ]);
    offset += 8;

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

        hops.push(crate::retrieval::RouteHopInfo { public_key, node_id });
    }

    if offset + 16 > data.len() {
        return Err(StorageError::InvalidChunkSize {
            expected: offset + 16,
            actual: data.len(),
        });
    }
    let mut destination = [0u8; 16];
    destination.copy_from_slice(&data[offset..offset + 16]);

    Ok(MissingChunkGossip {
        content_id,
        chunk_id,
        timestamp,
        return_route: ReturnRoute { hops, destination },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::RngCore;
    use static_sphinx::NodeId;

    fn random_content_id() -> ContentId {
        let mut id = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut id);
        id
    }

    fn random_chunk_id() -> ChunkId {
        let mut id = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut id);
        id
    }

    fn random_node_id() -> NodeId {
        let mut id = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut id);
        id
    }

    #[test]
    fn test_gossip_serialization_roundtrip() {
        let gossip = MissingChunkGossip {
            content_id: random_content_id(),
            chunk_id: random_chunk_id(),
            timestamp: 1_700_000_000,
            return_route: ReturnRoute {
                hops: vec![crate::retrieval::RouteHopInfo {
                    public_key: random_content_id(),
                    node_id: random_node_id(),
                }],
                destination: random_node_id(),
            },
        };

        let serialized = serialize_gossip(&gossip);
        assert_eq!(serialized[0], MSG_MISSING_CHUNK_GOSSIP);

        let deserialized = deserialize_gossip(&serialized).unwrap();
        assert_eq!(deserialized.content_id, gossip.content_id);
        assert_eq!(deserialized.chunk_id, gossip.chunk_id);
        assert_eq!(deserialized.timestamp, gossip.timestamp);
        assert_eq!(deserialized.return_route.hops.len(), 1);
        assert_eq!(
            deserialized.return_route.hops[0].node_id,
            gossip.return_route.hops[0].node_id
        );
        assert_eq!(deserialized.return_route.destination, gossip.return_route.destination);
    }

    #[test]
    fn test_gossip_deserialize_wrong_type() {
        let mut data = vec![0x01u8]; // ChunkRequest type byte
        data.extend_from_slice(&[0u8; 73]);
        assert!(deserialize_gossip(&data).is_err());
    }

    #[test]
    fn test_gossip_deserialize_too_short() {
        assert!(deserialize_gossip(&[0x09u8; 10]).is_err());
        assert!(deserialize_gossip(&[]).is_err());
    }
}
