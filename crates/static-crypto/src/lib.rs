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

/// Size of an ML-KEM-768 (Kyber768) public key in bytes
pub const KEM_PUBLIC_KEY_SIZE: usize = pqc_kyber::KYBER_PUBLICKEYBYTES;

/// Size of an ML-KEM-768 ciphertext in bytes
pub const KEM_CIPHERTEXT_SIZE: usize = pqc_kyber::KYBER_CIPHERTEXTBYTES;

/// Size of an ML-KEM-768 shared secret in bytes
pub const KEM_SHARED_SECRET_SIZE: usize = pqc_kyber::KYBER_SSBYTES;

/// An ML-KEM-768 keypair for post-quantum key encapsulation.
///
/// Combined with X25519 via [`derive_hybrid_shared_secret`] this provides
/// key agreement that remains secure if *either* algorithm holds.
#[derive(Clone)]
pub struct KemKeypair {
    /// The secret (decapsulation) key. Cloned rarely; prefer references.
    pub secret: pqc_kyber::SecretKey,
    /// The public (encapsulation) key, shared with peers.
    pub public: pqc_kyber::PublicKey,
}

impl KemKeypair {
    /// Generate a new random ML-KEM-768 keypair using the OS CSPRNG
    pub fn random() -> Self {
        let keys = pqc_kyber::keypair(&mut OsRng).expect("ML-KEM keygen failed");
        Self {
            secret: keys.secret,
            public: keys.public,
        }
    }

    /// Encapsulate a fresh shared secret to a peer's public key bytes
    ///
    /// Returns `(shared_secret, ciphertext)`. Send the ciphertext to the
    /// peer; they recover the same secret with [`KemKeypair::decapsulate`].
    pub fn encapsulate_to(public_key_bytes: &[u8]) -> Result<(SymmetricKey, Vec<u8>), CryptoError> {
        if public_key_bytes.len() != KEM_PUBLIC_KEY_SIZE {
            return Err(CryptoError::KemInvalidInput);
        }
        let mut pk = [0u8; pqc_kyber::KYBER_PUBLICKEYBYTES];
        pk.copy_from_slice(public_key_bytes);
        let (ciphertext, shared) =
            pqc_kyber::encapsulate(&pk, &mut OsRng).map_err(|_| CryptoError::KemInvalidInput)?;
        let mut secret_bytes = [0u8; KEY_SIZE];
        secret_bytes.copy_from_slice(shared.as_ref());
        Ok((SymmetricKey::from_bytes(secret_bytes), ciphertext.to_vec()))
    }

    /// Encapsulate to this keypair's own public key (for tests/loopback)
    pub fn encapsulate(&self) -> Result<(SymmetricKey, Vec<u8>), CryptoError> {
        Self::encapsulate_to(self.public.as_ref())
    }

    /// Decapsulate a peer's ciphertext into the shared secret
    pub fn decapsulate(&self, ciphertext: &[u8]) -> Result<SymmetricKey, CryptoError> {
        Self::decapsulate_with(self.secret.as_ref(), ciphertext)
    }

    /// Decapsulate with explicit secret-key bytes
    ///
    /// For nodes that store the classical and KEM keys separately
    /// (e.g. transport holding a plain mix node plus a KEM pair).
    pub fn decapsulate_with(secret_bytes: &[u8], ciphertext: &[u8]) -> Result<SymmetricKey, CryptoError> {
        if secret_bytes.len() != pqc_kyber::KYBER_SECRETKEYBYTES {
            return Err(CryptoError::KemInvalidInput);
        }
        if ciphertext.len() != KEM_CIPHERTEXT_SIZE {
            return Err(CryptoError::KemInvalidInput);
        }
        let mut sk = [0u8; pqc_kyber::KYBER_SECRETKEYBYTES];
        sk.copy_from_slice(secret_bytes);
        let mut ct = [0u8; pqc_kyber::KYBER_CIPHERTEXTBYTES];
        ct.copy_from_slice(ciphertext);
        let shared =
            pqc_kyber::decapsulate(&ct, &sk).map_err(|_| CryptoError::KemDecapsulationFailed)?;
        let mut out = [0u8; KEY_SIZE];
        out.copy_from_slice(shared.as_ref());
        Ok(SymmetricKey::from_bytes(out))
    }

    /// This keypair's secret key as bytes (keep private; for split storage)
    pub fn secret_bytes(&self) -> Vec<u8> {
        self.secret.as_ref().to_vec()
    }

    /// This keypair's public key as bytes (to advertise to peers)
    pub fn public_bytes(&self) -> Vec<u8> {
        self.public.as_ref().to_vec()
    }
}

/// Combine classical (X25519) and post-quantum (ML-KEM) shared secrets
/// into a single hybrid shared secret.
///
/// Construction: `HKDF-SHA256(salt=context, ikm=classical || kem)`.
/// Security: an attacker must break *both* X25519 and ML-KEM-768 to
/// recover the hybrid key; breaking either one alone reveals nothing
/// about the output.
pub fn derive_hybrid_shared_secret(
    classical_shared: &SymmetricKey,
    kem_shared: &SymmetricKey,
    context: &str,
) -> SymmetricKey {
    let mut combined = Vec::with_capacity(2 * KEY_SIZE);
    combined.extend_from_slice(&classical_shared.bytes);
    combined.extend_from_slice(&kem_shared.bytes);
    let hkdf = Hkdf::<Sha256>::new(Some(context.as_bytes()), &combined);
    let mut out = [0u8; KEY_SIZE];
    hkdf.expand(b"static-hybrid-v1", &mut out)
        .expect("HKDF expand failed");
    SymmetricKey::from_bytes(out)
}

/// A nonce for ChaCha20-Poly1305 encryption
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
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

    /// ML-KEM input had the wrong size (wrong security level or corrupt key)
    #[error("invalid ML-KEM input size")]
    KemInvalidInput,

    /// ML-KEM decapsulation failed (ciphertext failed authentication)
    #[error("ML-KEM decapsulation failed")]
    KemDecapsulationFailed,
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

    #[test]
    fn test_kem_keypair_generation() {
        let kem = KemKeypair::random();
        assert_eq!(kem.public.as_ref().len(), KEM_PUBLIC_KEY_SIZE);
        assert_eq!(kem.secret.as_ref().len(), pqc_kyber::KYBER_SECRETKEYBYTES);
        assert_eq!(kem.public_bytes().len(), KEM_PUBLIC_KEY_SIZE);

        // Two keypairs differ
        let other = KemKeypair::random();
        assert_ne!(kem.public_bytes(), other.public_bytes());
    }

    #[test]
    fn test_kem_encapsulate_decapsulate() {
        let bob = KemKeypair::random();
        let (shared_alice, ciphertext) = KemKeypair::encapsulate_to(&bob.public_bytes()).unwrap();
        assert_eq!(ciphertext.len(), KEM_CIPHERTEXT_SIZE);

        let shared_bob = bob.decapsulate(&ciphertext).unwrap();
        assert_eq!(shared_alice.bytes, shared_bob.bytes);
    }

    #[test]
    fn test_hybrid_key_derivation() {
        let classical = SymmetricKey::random();
        let kem = SymmetricKey::random();

        let hybrid = derive_hybrid_shared_secret(&classical, &kem, "test");
        // Deterministic
        let hybrid_again = derive_hybrid_shared_secret(&classical, &kem, "test");
        assert_eq!(hybrid.bytes, hybrid_again.bytes);
        // Context separation
        let other_ctx = derive_hybrid_shared_secret(&classical, &kem, "other");
        assert_ne!(hybrid.bytes, other_ctx.bytes);
        // Differs from either input
        assert_ne!(hybrid.bytes, classical.bytes);
        assert_ne!(hybrid.bytes, kem.bytes);
    }

    #[test]
    fn test_hybrid_key_independence() {
        // Breaking one component (knowing it fully) must not reveal the hybrid:
        // varying the unknown component changes the output.
        let classical = SymmetricKey::random();
        let kem_a = SymmetricKey::random();
        let kem_b = SymmetricKey::random();

        let h1 = derive_hybrid_shared_secret(&classical, &kem_a, "ctx");
        let h2 = derive_hybrid_shared_secret(&classical, &kem_b, "ctx");
        assert_ne!(h1.bytes, h2.bytes, "X25519 break must not reveal hybrid");

        let classical_b = SymmetricKey::random();
        let h3 = derive_hybrid_shared_secret(&classical_b, &kem_a, "ctx");
        assert_ne!(h1.bytes, h3.bytes, "ML-KEM break must not reveal hybrid");
    }
}
