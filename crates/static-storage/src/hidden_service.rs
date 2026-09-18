//! Hidden service discovery and encrypted manifests
//!
//! Implements the content-addressed hidden service model:
//! 1. Publisher generates an X25519 keypair for the content.
//! 2. ContentId = blake3(public_key)
//! 3. The manifest is encrypted using a symmetric key derived from the public key.
//! 4. The encrypted manifest is stored as a chunk on the network.
//! 5. Hints narrow down which nodes hold the manifest chunk.

use crate::{ContentId, ContentManifest, ChunkId, NodeId, StorageError};
use static_crypto::{SymmetricKey, encrypt, decrypt, NonceBytes};
use serde::{Serialize, Deserialize};

/// A hint pointing to where the encrypted manifest might be stored
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Hint {
    /// The content ID this hint is for
    pub content_id: ContentId,
    /// The chunk ID of the encrypted manifest
    pub manifest_chunk_id: ChunkId,
    /// Hash ranges of node IDs that are storing copies
    /// (start, end) inclusive
    pub node_id_ranges: Vec<(NodeId, NodeId)>,
}

/// An encrypted manifest
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedManifest {
    /// The ciphertext of the serialized ContentManifest
    pub ciphertext: Vec<u8>,
    /// The nonce used for encryption
    pub nonce: NonceBytes,
}

/// Compute the content ID from a public key
pub fn content_id_from_public(public_key: &[u8; 32]) -> ContentId {
    let mut id = [0u8; 32];
    id.copy_from_slice(blake3::hash(public_key).as_bytes());
    id
}

/// Derive a symmetric key from a public key
fn derive_symmetric_key(public_key: &[u8; 32]) -> SymmetricKey {
    SymmetricKey::from_bytes(*public_key).derive("static-hidden-service-manifest")
}

/// Encrypt a manifest for hidden service discovery
pub fn encrypt_manifest(
    manifest: &ContentManifest,
    content_public_key: &[u8; 32],
) -> Result<(EncryptedManifest, ChunkId), StorageError> {
    let plaintext = serde_json::to_vec(manifest)
        .map_err(|_| StorageError::ManifestSerializationFailed)?;
    
    let symmetric_key = derive_symmetric_key(content_public_key);
    let nonce = NonceBytes::random();
    let ciphertext = encrypt(&symmetric_key, &nonce, &plaintext);
    
    let encrypted_manifest = EncryptedManifest {
        ciphertext,
        nonce,
    };
    
    let mut chunk_id = [0u8; 32];
    chunk_id.copy_from_slice(blake3::hash(&encrypted_manifest.ciphertext).as_bytes());
    
    Ok((encrypted_manifest, chunk_id))
}

/// Decrypt a manifest using the content's public key
pub fn decrypt_manifest(
    encrypted_manifest: &EncryptedManifest,
    content_public_key: &[u8; 32],
) -> Result<ContentManifest, StorageError> {
    let symmetric_key = derive_symmetric_key(content_public_key);
    let plaintext = decrypt(&symmetric_key, &encrypted_manifest.nonce, &encrypted_manifest.ciphertext)
        .map_err(|_| StorageError::ManifestDecryptionFailed)?;
    
    let manifest: ContentManifest = serde_json::from_slice(&plaintext)
        .map_err(|_| StorageError::ManifestDeserializationFailed)?;
    
    Ok(manifest)
}

/// Create a hint for a manifest
pub fn create_hint(
    content_id: ContentId,
    manifest_chunk_id: ChunkId,
    storing_node_ids: &[NodeId],
) -> Hint {
    let mut ranges = Vec::new();
    for node_id in storing_node_ids {
        ranges.push((*node_id, *node_id));
    }
    
    Hint {
        content_id,
        node_id_ranges: ranges,
        manifest_chunk_id,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ContentManifest;
    use rand::RngCore;

    #[test]
    fn test_content_id_from_public() {
        let mut pub_key = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut pub_key);
        
        let id1 = content_id_from_public(&pub_key);
        let id2 = content_id_from_public(&pub_key);
        
        assert_eq!(id1, id2);
        
        let mut pub_key2 = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut pub_key2);
        let id3 = content_id_from_public(&pub_key2);
        
        assert_ne!(id1, id3);
    }

    #[test]
    fn test_manifest_encryption_roundtrip() {
        let manifest = ContentManifest {
            content_id: [0x42u8; 32],
            encrypted_master_key: vec![0xAB; 32],
            chunk_ids: vec![[0x01u8; 32], [0x02u8; 32]],
            original_size: 1024,
            data_shards: 10,
            parity_shards: 5,
            nonce: [0u8; 12],
            segment_hashes: vec![],
        };
        
        let mut pub_key = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut pub_key);
        
        let (encrypted, _chunk_id) = encrypt_manifest(&manifest, &pub_key).unwrap();
        let decrypted = decrypt_manifest(&encrypted, &pub_key).unwrap();
        
        assert_eq!(decrypted.content_id, manifest.content_id);
        assert_eq!(decrypted.chunk_ids, manifest.chunk_ids);
        assert_eq!(decrypted.original_size, manifest.original_size);
        
        // Wrong key should fail
        let mut wrong_key = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut wrong_key);
        let result = decrypt_manifest(&encrypted, &wrong_key);
        assert!(result.is_err());
    }

    #[test]
    fn test_hint_creation() {
        let content_id = [0x42u8; 32];
        let chunk_id = [0x43u8; 32];
        let node1 = [0x01u8; 16];
        let node2 = [0x02u8; 16];
        
        let hint = create_hint(content_id, chunk_id, &[node1, node2]);
        
        assert_eq!(hint.content_id, content_id);
        assert_eq!(hint.manifest_chunk_id, chunk_id);
        assert_eq!(hint.node_id_ranges.len(), 2);
        assert_eq!(hint.node_id_ranges[0], (node1, node1));
        assert_eq!(hint.node_id_ranges[1], (node2, node2));
    }
}
