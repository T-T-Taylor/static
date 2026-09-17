//! Content integrity verification using Merkle trees
//!
//! Allows nodes to verify that a chunk is a valid shard of some content
//! without decrypting it or learning what the content is. The publisher
//! builds a binary Merkle tree over the encrypted chunks (data + parity
//! shards) and stores a proof per chunk; swap proposals carry the root
//! and the offered chunk's proof, and receivers verify before accepting.
//!
//! Tree conventions:
//! - Leaf hash: `blake3(chunk.data)`
//! - Internal node hash: `blake3(left || right)`
//! - Odd trailing nodes at any level are paired with a duplicate of
//!   themselves (Bitcoin-style)
//! - An empty chunk set yields [`EMPTY_ROOT`]; a single chunk's root is
//!   its leaf hash with an empty sibling list in its proof
//!
//! Note: leaf and node hashes are not domain-separated (an attacker could
//! in principle craft chunk data equal to a 64-byte internal node
//! encoding). Hardening with a domain tag byte (0x00 leaf / 0x01 node) is
//! planned future work; not blocking for MVP.

use crate::EncryptedChunk;
use serde::{Deserialize, Serialize};

/// The root of a Merkle tree built over encrypted chunks
pub type MerkleRoot = [u8; 32];

/// Root returned for an empty chunk set
pub const EMPTY_ROOT: MerkleRoot = [0u8; 32];

/// A Merkle proof for a single chunk
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MerkleProof {
    /// The index of the leaf in the tree (0-based, left to right)
    pub leaf_index: usize,
    /// The sibling hashes from leaf to root
    pub siblings: Vec<[u8; 32]>,
}

/// Hash of a single leaf: blake3(chunk data)
fn leaf_hash(data: &[u8]) -> [u8; 32] {
    *blake3::hash(data).as_bytes()
}

/// Hash of an internal node: blake3(left || right)
fn node_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut input = [0u8; 64];
    input[..32].copy_from_slice(left);
    input[32..].copy_from_slice(right);
    *blake3::hash(&input).as_bytes()
}

/// Compute the Merkle root for a set of chunks
///
/// Leaf order is the input slice order. An empty set yields
/// [`EMPTY_ROOT`].
pub fn compute_root(chunks: &[EncryptedChunk]) -> MerkleRoot {
    if chunks.is_empty() {
        return EMPTY_ROOT;
    }

    let mut level: Vec<[u8; 32]> = chunks.iter().map(|c| leaf_hash(&c.data)).collect();
    while level.len() > 1 {
        if level.len() % 2 == 1 {
            let last = *level.last().expect("non-empty level");
            level.push(last);
        }
        level = level
            .chunks(2)
            .map(|pair| node_hash(&pair[0], &pair[1]))
            .collect();
    }
    level[0]
}

/// Generate Merkle proofs for all chunks
///
/// Returns the tree root and one proof per chunk, in input order.
pub fn generate_proofs(chunks: &[EncryptedChunk]) -> (MerkleRoot, Vec<MerkleProof>) {
    if chunks.is_empty() {
        return (EMPTY_ROOT, Vec::new());
    }

    // Build all levels leaf -> root (padding odd trailing nodes with a
    // duplicate before hashing each level).
    let mut levels: Vec<Vec<[u8; 32]>> = Vec::new();
    let mut level: Vec<[u8; 32]> = chunks.iter().map(|c| leaf_hash(&c.data)).collect();
    while level.len() > 1 {
        if level.len() % 2 == 1 {
            let last = *level.last().expect("non-empty level");
            level.push(last);
        }
        levels.push(level.clone());
        level = level
            .chunks(2)
            .map(|pair| node_hash(&pair[0], &pair[1]))
            .collect();
    }
    let root = level[0];

    // Extract each leaf's sibling path (one sibling per level).
    let mut proofs = Vec::with_capacity(chunks.len());
    for leaf_index in 0..chunks.len() {
        let mut siblings = Vec::with_capacity(levels.len());
        let mut idx = leaf_index;
        for tree_level in &levels {
            siblings.push(tree_level[idx ^ 1]);
            idx /= 2;
        }
        proofs.push(MerkleProof {
            leaf_index,
            siblings,
        });
    }

    (root, proofs)
}

/// Verify a chunk against a Merkle proof and root
///
/// Returns `true` only when re-hashing the chunk data and walking the
/// proof's siblings reproduces `root`.
pub fn verify_chunk(chunk: &EncryptedChunk, proof: &MerkleProof, root: &MerkleRoot) -> bool {
    let mut current = leaf_hash(&chunk.data);
    let mut idx = proof.leaf_index;
    for sibling in &proof.siblings {
        current = if idx % 2 == 0 {
            node_hash(&current, sibling)
        } else {
            node_hash(sibling, &current)
        };
        idx /= 2;
    }
    current == *root
}

#[cfg(test)]
mod tests {
    use super::*;

    fn chunk(id_byte: u8, len: usize) -> EncryptedChunk {
        EncryptedChunk {
            id: [id_byte; 32],
            data: vec![id_byte; len],
        }
    }

    #[test]
    fn test_merkle_tree_small() {
        // Edge cases first: empty set -> sentinel root; single chunk ->
        // leaf hash with an empty-sibling proof.
        assert_eq!(compute_root(&[]), EMPTY_ROOT);
        let (root, proofs) = generate_proofs(&[chunk(0x01, 100)]);
        assert_eq!(proofs.len(), 1);
        assert!(proofs[0].siblings.is_empty());
        assert!(verify_chunk(&chunk(0x01, 100), &proofs[0], &root));

        // Two chunks: one level, one sibling per proof.
        let chunks = vec![chunk(0x02, 128), chunk(0x03, 128)];
        let root = compute_root(&chunks);
        let (root2, proofs) = generate_proofs(&chunks);
        assert_eq!(root, root2);
        assert_eq!(proofs.len(), 2);
        for (expected_index, proof) in proofs.iter().enumerate() {
            assert_eq!(proof.leaf_index, expected_index);
            assert_eq!(proof.siblings.len(), 1);
            assert!(verify_chunk(&chunks[expected_index], proof, &root));
        }
        // The two proofs' siblings hash together to the root.
        assert_eq!(
            node_hash(&leaf_hash(&chunks[0].data), &leaf_hash(&chunks[1].data)),
            root
        );
    }

    #[test]
    fn test_merkle_tree_odd() {
        // Three leaves: the trailing node is duplicated at the leaf level.
        let chunks = vec![chunk(0x04, 64), chunk(0x05, 64), chunk(0x06, 64)];
        let root = compute_root(&chunks);
        let (root2, proofs) = generate_proofs(&chunks);
        assert_eq!(root, root2);
        assert_eq!(proofs.len(), 3);
        for (expected_index, proof) in proofs.iter().enumerate() {
            assert_eq!(proof.leaf_index, expected_index);
            // Two levels: leaf level and internal level.
            assert_eq!(proof.siblings.len(), 2);
            assert!(verify_chunk(&chunks[expected_index], proof, &root));
        }
    }

    #[test]
    fn test_verify_valid_chunk() {
        let chunks: Vec<EncryptedChunk> = (0x10u8..0x18u8).map(|b| chunk(b, 256)).collect();
        let (root, proofs) = generate_proofs(&chunks);
        for (i, proof) in proofs.iter().enumerate() {
            assert!(verify_chunk(&chunks[i], proof, &root), "chunk {} must verify", i);
        }
    }

    #[test]
    fn test_verify_tampered_chunk() {
        let chunks = vec![chunk(0x20, 128), chunk(0x21, 128), chunk(0x22, 128)];
        let (root, proofs) = generate_proofs(&chunks);

        let mut tampered = chunks[1].clone();
        tampered.data[7] ^= 0xFF;
        assert!(!verify_chunk(&tampered, &proofs[1], &root));
    }

    #[test]
    fn test_verify_tampered_proof() {
        let chunks = vec![chunk(0x30, 128), chunk(0x31, 128), chunk(0x32, 128)];
        let (root, proofs) = generate_proofs(&chunks);

        let mut forged = proofs[0].clone();
        forged.siblings[0][0] ^= 0xFF;
        assert!(!verify_chunk(&chunks[0], &forged, &root));
    }

    #[test]
    fn test_verify_wrong_root() {
        let chunks = vec![chunk(0x40, 128), chunk(0x41, 128)];
        let other = vec![chunk(0x42, 128), chunk(0x43, 128)];
        let (_, proofs) = generate_proofs(&chunks);
        let other_root = compute_root(&other);

        assert_ne!(other_root, compute_root(&chunks));
        assert!(!verify_chunk(&chunks[0], &proofs[0], &other_root));
        assert!(!verify_chunk(&chunks[0], &proofs[0], &EMPTY_ROOT));
    }
}
