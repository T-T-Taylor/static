//! static-crypto - Shared cryptographic primitives for Static
//!
//! Provides key types, key derivation, encryption, and zeroization
//! utilities used across all Static crates. All keys and plaintext
//! material implement ZeroizeOnDrop to ensure memory is wiped.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Key as ChaChaKey, Nonce,
};
use hkdf::Hkdf;
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::ZeroizeOnDrop;

/// Size of a ChaCha20-Poly1305 key in bytes
pub const KEY_SIZE: usize = 32;

/// Size of a ChaCha20-Poly1305 nonce in bytes
pub const NONCE_SIZE: usize = 12;

/// Size of a ChaCha20-Poly1305 authentication tag in bytes
pub const TAG_SIZE: usize = 16;

/// A symmetric encryption key. Zeroized on drop.
#[derive(Clone, ZeroizeOnDrop)]
pub struct SymmetricKey {
    /// The raw key bytes
    pub bytes: [u8; KEY_SIZE],
}

impl SymmetricKey {
    /// Create a new key from raw bytes
    pub fn from_bytes(bytes: [u8; KEY_SIZE]) -> Self {
        Self { bytes }
    }

    /// Generate a random key using the OS CSPRNG
    pub fn random() -> Self {
        let mut bytes = [0u8; KEY_SIZE];
        OsRng.fill_bytes(&mut bytes);
        Self { bytes }
    }

    /// Derive a sub-key from this key using HKDF with a context string
    pub fn derive(&self, context: &str) -> Self {
        let hkdf = Hkdf::<Sha256>::new(None, &self.bytes);
        let mut out = [0u8; KEY_SIZE];
        hkdf.expand(context.as_bytes(), &mut out)
            .expect("HKDF expand failed");
        Self { bytes: out }
    }
}

/// An X25519 keypair for Diffie-Hellman key exchange. Secret is zeroized on drop.
#[derive(ZeroizeOnDrop)]
pub struct DhKeypair {
    /// The secret key
    pub secret: StaticSecret,
    /// The public key
    pub public: PublicKey,
}

impl DhKeypair {
    /// Generate a new random keypair using the OS CSPRNG
    pub fn random() -> Self {
        let mut secret_bytes = [0u8; 32];
        OsRng.fill_bytes(&mut secret_bytes);
        let secret = StaticSecret::from(secret_bytes);
        let public = PublicKey::from(&secret);
        Self { secret, public }
    }

    /// Perform Diffie-Hellman with another public key to derive a shared secret
    pub fn dh(&self, their_public: &PublicKey) -> SymmetricKey {
        let shared = self.secret.diffie_hellman(their_public);
        let mut bytes = [0u8; KEY_SIZE];
        bytes.copy_from_slice(shared.as_bytes());
        SymmetricKey { bytes }
    }
}

/// A nonce for ChaCha20-Poly1305 encryption
#[derive(Clone)]
pub struct NonceBytes {
    /// The raw nonce bytes
    pub bytes: [u8; NONCE_SIZE],
}

impl NonceBytes {
    /// Create a nonce from raw bytes
    pub fn from_bytes(bytes: [u8; NONCE_SIZE]) -> Self {
        Self { bytes }
    }

    /// Generate a random nonce using the OS CSPRNG
    pub fn random() -> Self {
        let mut bytes = [0u8; NONCE_SIZE];
        OsRng.fill_bytes(&mut bytes);
        Self { bytes }
    }

    /// Create a nonce from a counter (useful for streaming encryption)
    pub fn from_counter(counter: u64) -> Self {
        let mut bytes = [0u8; NONCE_SIZE];
        bytes[4..12].copy_from_slice(&counter.to_le_bytes());
        Self { bytes }
    }
}

/// Encrypt plaintext with a symmetric key and nonce.
/// Returns ciphertext with appended 16-byte Poly1305 tag.
pub fn encrypt(key: &SymmetricKey, nonce: &NonceBytes, plaintext: &[u8]) -> Vec<u8> {
    let cipher = ChaCha20Poly1305::new(ChaChaKey::from_slice(&key.bytes));
    let nonce = Nonce::from_slice(&nonce.bytes);
    cipher
        .encrypt(nonce, Payload { msg: plaintext, aad: &[] })
        .expect("encryption failed")
}

/// Decrypt ciphertext with a symmetric key and nonce.
/// Returns the plaintext if the tag verifies, otherwise an error.
pub fn decrypt(key: &SymmetricKey, nonce: &NonceBytes, ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let cipher = ChaCha20Poly1305::new(ChaChaKey::from_slice(&key.bytes));
    let nonce = Nonce::from_slice(&nonce.bytes);
    cipher
        .decrypt(nonce, Payload { msg: ciphertext, aad: &[] })
        .map_err(|_| CryptoError::DecryptionFailed)
}

/// Encrypt plaintext with associated data (AEAD).
/// Returns ciphertext with appended 16-byte tag.
pub fn encrypt_aad(key: &SymmetricKey, nonce: &NonceBytes, plaintext: &[u8], aad: &[u8]) -> Vec<u8> {
    let cipher = ChaCha20Poly1305::new(ChaChaKey::from_slice(&key.bytes));
    let nonce = Nonce::from_slice(&nonce.bytes);
    cipher
        .encrypt(nonce, Payload { msg: plaintext, aad })
        .expect("encryption failed")
}

/// Decrypt ciphertext with associated data (AEAD).
/// Returns the plaintext if the tag verifies, otherwise an error.
pub fn decrypt_aad(key: &SymmetricKey, nonce: &NonceBytes, ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let cipher = ChaCha20Poly1305::new(ChaChaKey::from_slice(&key.bytes));
    let nonce = Nonce::from_slice(&nonce.bytes);
    cipher
        .decrypt(nonce, Payload { msg: ciphertext, aad })
        .map_err(|_| CryptoError::DecryptionFailed)
}

/// Derive a chain of keys from a master key using HKDF.
/// Each key in the chain is derived from the previous one.
/// This is used for streaming chunk encryption where chunk N's
/// key depends on chunk N-1's key.
pub fn derive_key_chain(master: &SymmetricKey, count: usize, context: &str) -> Vec<SymmetricKey> {
    let mut keys = Vec::with_capacity(count);
    let mut current = master.derive(&format!("{}:0", context));
    keys.push(current.clone());
    
    for i in 1..count {
        current = current.derive(&format!("{}:{}", context, i));
        keys.push(current.clone());
    }
    
    keys
}

/// Errors that can occur during cryptographic operations
#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    /// Decryption failed (tag verification or other error)
    #[error("decryption failed")]
    DecryptionFailed,

    /// Invalid key size
    #[error("invalid key size")]
    InvalidKeySize,

    /// Invalid nonce size
    #[error("invalid nonce size")]
    InvalidNonceSize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let key = SymmetricKey::random();
        let nonce = NonceBytes::random();
        let plaintext = b"hello static network";
        
        let ciphertext = encrypt(&key, &nonce, plaintext);
        let decrypted = decrypt(&key, &nonce, &ciphertext).unwrap();
        
        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_aad_roundtrip() {
        let key = SymmetricKey::random();
        let nonce = NonceBytes::random();
        let plaintext = b"authenticated data test";
        let aad = b"associated metadata";
        
        let ciphertext = encrypt_aad(&key, &nonce, plaintext, aad);
        let decrypted = decrypt_aad(&key, &nonce, &ciphertext, aad).unwrap();
        
        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_aad_tamper_detected() {
        let key = SymmetricKey::random();
        let nonce = NonceBytes::random();
        let plaintext = b"authenticated data test";
        let aad = b"associated metadata";
        
        let ciphertext = encrypt_aad(&key, &nonce, plaintext, aad);
        
        // Wrong AAD should fail
        let result = decrypt_aad(&key, &nonce, &ciphertext, b"wrong aad");
        assert!(result.is_err());
    }

    #[test]
    fn test_key_derivation() {
        let master = SymmetricKey::random();
        let key1 = master.derive("context1");
        let key2 = master.derive("context2");
        
        // Different contexts produce different keys
        assert_ne!(key1.bytes, key2.bytes);
        
        // Same context produces same key
        let key1_again = master.derive("context1");
        assert_eq!(key1.bytes, key1_again.bytes);
    }

    #[test]
    fn test_key_chain() {
        let master = SymmetricKey::random();
        let chain = derive_key_chain(&master, 5, "file");
        
        assert_eq!(chain.len(), 5);
        
        // All keys should be different
        for i in 0..5 {
            for j in (i+1)..5 {
                assert_ne!(chain[i].bytes, chain[j].bytes, "keys {} and {} are the same", i, j);
            }
        }
    }

    #[test]
    fn test_dh_key_exchange() {
        let alice = DhKeypair::random();
        let bob = DhKeypair::random();
        
        let alice_shared = alice.dh(&bob.public);
        let bob_shared = bob.dh(&alice.public);
        
        // Both parties derive the same shared secret
        assert_eq!(alice_shared.bytes, bob_shared.bytes);
    }

    #[test]
    fn test_ciphertext_indistinguishable() {
        let key = SymmetricKey::random();
        let nonce = NonceBytes::random();
        let plaintext = b"this is a test message for indistinguishability";
        
        let ciphertext = encrypt(&key, &nonce, plaintext);
        
        // Ciphertext should be different from plaintext
        assert_ne!(plaintext.as_slice(), &ciphertext[..plaintext.len()]);
        
        // Ciphertext length = plaintext + 16 byte tag
        assert_eq!(ciphertext.len(), plaintext.len() + TAG_SIZE);
    }

    #[test]
    fn test_nonce_from_counter() {
        let n1 = NonceBytes::from_counter(1);
        let n2 = NonceBytes::from_counter(2);
        let n3 = NonceBytes::from_counter(1);
        
        assert_ne!(n1.bytes, n2.bytes);
        assert_eq!(n1.bytes, n3.bytes);
    }
}
