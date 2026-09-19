//! Wire protocol for Static network messages
//!
//! Defines the message format for communication between Static nodes.
//! All messages are length-prefixed and serialized as binary.
//!
//! Message format:
//!   [1 byte: message type] [4 bytes: payload length] [N bytes: payload]
//!
//! Message types:
//!   0x01 - Handshake (exchange node ID and public key)
//!   0x02 - Sphinx packet (real or cover, indistinguishable)

use static_sphinx::{
    SessionReply, SphinxPacket, SphinxHeader, NodeId,
    BODY_SIZE, WIRE_BODY_SIZE, KEM_BLOCK_SIZE, SESSION_ID_SIZE,
    ROUTING_INFO_SIZE, EPHEMERAL_KEY_SIZE, MAC_SIZE,
    SPHINX_VERSION_CLASSICAL, SPHINX_VERSION_HYBRID,
    SPHINX_VERSION_SESSION_REPLY, SESSION_REPLY_WIRE_SIZE,
    HYBRID_KEM_CIPHERTEXT_SIZE,
};
use bytes::{BufMut, BytesMut};

/// Handshake message type
pub const MSG_HANDSHAKE: u8 = 0x01;

/// Sphinx packet message type
pub const MSG_SPHINX: u8 = 0x02;

// NOTE (Phase 7, Task 1): the direct-wire maintenance messages
// (Gossip 0x03, SwapProposal 0x04, SwapAccept 0x05, SwapReject 0x06,
// Prepayment 0x07, Reconciliation 0x08, SwapCommit 0x0B, SwapAbort 0x0C)
// are removed. All maintenance travels Sphinx-wrapped inside encrypted
// bodies (type bytes below, a separate namespace from wire framing).

/// Sphinx-body type: peer gossip (inside encrypted Sphinx body)
pub const MSG_BODY_GOSSIP: u8 = 0x12;

/// Sphinx-body type: swap proposal
pub const MSG_BODY_SWAP_PROPOSAL: u8 = 0x13;

/// Sphinx-body type: swap accept
pub const MSG_BODY_SWAP_ACCEPT: u8 = 0x14;

/// Sphinx-body type: swap reject
pub const MSG_BODY_SWAP_REJECT: u8 = 0x15;

/// Sphinx-body type: prepayment
pub const MSG_BODY_PREPAYMENT: u8 = 0x16;

/// Sphinx-body type: accounting reconciliation
pub const MSG_BODY_RECONCILIATION: u8 = 0x17;

/// Sphinx-body type: swap commit
pub const MSG_BODY_SWAP_COMMIT: u8 = 0x18;

/// Sphinx-body type: swap abort
pub const MSG_BODY_SWAP_ABORT: u8 = 0x19;

/// Hello message type (Phase 7 encrypted handshake, client -> server)
///
/// Wire namespace only; Sphinx-body type bytes are a separate namespace.
pub const MSG_HELLO: u8 = 0x0D;

/// Welcome message type (Phase 7 encrypted handshake, server -> client)
pub const MSG_WELCOME: u8 = 0x0E;

/// Encrypted identity type (Phase 7 handshake auth, both directions)
pub const MSG_AUTH_IDENTITY: u8 = 0x0F;

/// HKDF context for the handshake hybrid shared secret
pub const HANDSHAKE_CONTEXT: &str = "static-handshake-v1";

/// HKDF context for the handshake identity-AEAD key
pub const HANDSHAKE_AUTH_CONTEXT: &str = "handshake/auth";

/// Maximum peer credit entries per reconciliation message (batching cap)
///
/// Keeps serialized reconciliation messages under `MAX_MESSAGE_SIZE`.
/// Nodes with more peers send multiple messages; `reconcile()` is
/// idempotent so batches converge to the same result.
pub const MAX_RECONCILIATION_ENTRIES: usize = 50;

/// Maximum message size (header + body + framing overhead)
///
/// Sized for a versioned classical Sphinx packet with the Phase 7 AEAD
/// wire body: outer framing plus version, ephemeral key, session id,
/// kem-length prefix, routing info, MAC, and [`WIRE_BODY_SIZE`] body.
pub const MAX_MESSAGE_SIZE: usize = 1 + 4 + 1 + 4 + EPHEMERAL_KEY_SIZE + SESSION_ID_SIZE + ROUTING_INFO_SIZE + MAC_SIZE + WIRE_BODY_SIZE;

/// Maximum hybrid message size
///
/// Hybrid v1 Sphinx packets carry the fixed [`KEM_BLOCK_SIZE`] block:
/// 1-byte version + 32-byte session id + u32 kem length + fixed block on
/// top of the classical layout (Phase 7, Task 4b: no per-hop size leak).
pub const HYBRID_MAX_MESSAGE_SIZE: usize = 1 + 4 + 1 + 4 + SESSION_ID_SIZE + KEM_BLOCK_SIZE + EPHEMERAL_KEY_SIZE + ROUTING_INFO_SIZE + MAC_SIZE + WIRE_BODY_SIZE;

/// Padded uniform wire size (Phase 0, C3).
///
/// After the hybrid-only mandate every outer message is padded to
/// `HYBRID_MAX_MESSAGE_SIZE` so gossip/swap/prepayment/reconciliation are
/// indistinguishable by size from Sphinx packets.
pub const PADDED_MESSAGE_SIZE: usize = HYBRID_MAX_MESSAGE_SIZE;

/// A handshake message exchanged when peers connect
///
/// Phase 0 unified format (one wire break): no bandwidth-tier field —
/// peers infer tier from observed cover rate. Carries an Ed25519
/// identity key plus nonce/signature proving possession of the identity
/// private key. `signing_bytes` covers node_id, mix public key, KEM key,
/// compute flags, identity key and nonce.
#[derive(Debug, Clone)]
pub struct Handshake {
    /// The sending node's ID
    pub node_id: NodeId,
    /// The sending node's public key (Montgomery point bytes, Sphinx)
    pub public_key: [u8; 32],
    /// The sending node's ML-KEM-768 public key (for hybrid Sphinx)
    ///
    /// `None` for legacy (classical-only) peers. Hybrid-only networks
    /// require `Some`.
    pub kem_public_key: Option<Vec<u8>>,
    /// Whether the sending node accepts compute requests
    pub compute_enabled: bool,
    /// Maximum concurrent compute executions on the sending node
    pub compute_capacity: u8,
    /// Ed25519 identity public key (authentication, not Sphinx encryption)
    pub identity_public_key: [u8; 32],
    /// Random nonce for challenge-response / replay protection
    pub nonce: [u8; 32],
    /// Ed25519 signature over [`Handshake::signing_bytes`]
    pub signature: Vec<u8>,
}

impl Handshake {
    /// Bytes covered by the handshake signature.
    pub fn signing_bytes(&self) -> Vec<u8> {
        let kem = self.kem_public_key.as_deref().unwrap_or(&[]);
        let mut buf = Vec::with_capacity(16 + 32 + 2 + kem.len() + 2 + 32 + 32);
        buf.extend_from_slice(&self.node_id);
        buf.extend_from_slice(&self.public_key);
        buf.extend_from_slice(&(kem.len() as u16).to_be_bytes());
        buf.extend_from_slice(kem);
        buf.push(u8::from(self.compute_enabled));
        buf.push(self.compute_capacity);
        buf.extend_from_slice(&self.identity_public_key);
        buf.extend_from_slice(&self.nonce);
        buf
    }

    /// Sign this handshake with the node's Ed25519 private key.
    pub fn sign(&mut self, signing_key: &ed25519_dalek::SigningKey) {
        use ed25519_dalek::Signer;
        self.identity_public_key = signing_key.verifying_key().to_bytes();
        let sig = signing_key.sign(&self.signing_bytes());
        self.signature = sig.to_bytes().to_vec();
    }

    /// Verify the handshake signature and basic field sanity.
    pub fn verify(&self) -> bool {
        use ed25519_dalek::{Signature, Verifier, VerifyingKey};
        if self.signature.len() != 64 {
            return false;
        }
        let Ok(pk) = VerifyingKey::from_bytes(&self.identity_public_key) else {
            return false;
        };
        let mut arr = [0u8; 64];
        arr.copy_from_slice(&self.signature);
        let sig = Signature::from_bytes(&arr);
        // Enforce KEM key size when present (ML-KEM-768 pubkey).
        if let Some(kem) = &self.kem_public_key {
            if kem.len() != static_sphinx::HYBRID_KEM_PUBLIC_KEY_SIZE {
                return false;
            }
        }
        pk.verify(&self.signing_bytes(), &sig).is_ok()
    }
}

/// Hello: Phase 7 handshake message 1 (client -> server).
///
/// Carries only ephemeral keys + nonce. No identity. Padded to
/// [`PADDED_MESSAGE_SIZE`] on the wire.
#[derive(Debug, Clone)]
pub struct Hello {
    /// Client's ephemeral X25519 public key (this handshake only)
    pub eph_pub_key: [u8; 32],
    /// Client's ephemeral ML-KEM-768 public key
    pub eph_kem_pub_key: Vec<u8>,
    /// Random anti-replay nonce
    pub nonce: [u8; 32],
}

/// Welcome: Phase 7 handshake message 2 (server -> client).
///
/// Carries the server's ephemeral keys + KEM ciphertext encapsulating to
/// the client's ephemeral KEM key. No identity. Padded to
/// [`PADDED_MESSAGE_SIZE`] on the wire.
#[derive(Debug, Clone)]
pub struct Welcome {
    /// Server's ephemeral X25519 public key
    pub eph_pub_key: [u8; 32],
    /// Server's ephemeral ML-KEM-768 public key
    pub eph_kem_pub_key: Vec<u8>,
    /// Server's anti-replay nonce
    pub nonce: [u8; 32],
    /// KEM ciphertext (server encapsulates to client's ephemeral KEM key)
    pub kem_ciphertext: Vec<u8>,
}

/// Encrypted identity: Phase 7 handshake messages 3-4 (both directions).
///
/// AEAD-encrypted [`Handshake`] (ChaCha20-Poly1305, key derived from the
/// handshake hybrid secret, AAD = hello_nonce || welcome_nonce). An
/// eavesdropper sees only encrypted bytes. Padded to
/// [`PADDED_MESSAGE_SIZE`] on the wire.
#[derive(Debug, Clone)]
pub struct EncryptedIdentity {
    /// Random AEAD nonce (12 bytes, ChaCha20-Poly1305)
    pub aead_nonce: [u8; 12],
    /// AEAD ciphertext (serialized [`Handshake`] + 16-byte tag)
    pub ciphertext: Vec<u8>,
}

/// Session binding for handshake identity AEAD (hello_nonce || welcome_nonce).
pub fn handshake_session_aad(hello_nonce: &[u8; 32], welcome_nonce: &[u8; 32]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(64);
    aad.extend_from_slice(hello_nonce);
    aad.extend_from_slice(welcome_nonce);
    aad
}

/// Derive the handshake hybrid secret from X25519 and KEM shares.
pub fn derive_handshake_secret(
    dh_shared: &static_crypto::SymmetricKey,
    kem_shared: &static_crypto::SymmetricKey,
) -> static_crypto::SymmetricKey {
    static_crypto::derive_hybrid_shared_secret(dh_shared, kem_shared, HANDSHAKE_CONTEXT)
}

/// Encrypt a [`Handshake`] into an [`EncryptedIdentity`].
pub fn encrypt_identity(
    handshake_secret: &static_crypto::SymmetricKey,
    handshake: &Handshake,
    aad: &[u8],
) -> EncryptedIdentity {
    use rand::RngCore;
    let aead_key = handshake_secret.derive(HANDSHAKE_AUTH_CONTEXT);
    let mut nonce_bytes = [0u8; 12];
    rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = static_crypto::NonceBytes::from_bytes(nonce_bytes);
    let plaintext = serialize_handshake(handshake);
    let ciphertext = static_crypto::encrypt_aad(&aead_key, &nonce, &plaintext, aad);
    EncryptedIdentity { aead_nonce: nonce_bytes, ciphertext }
}

/// Decrypt an [`EncryptedIdentity`] into a [`Handshake`].
pub fn decrypt_identity(
    handshake_secret: &static_crypto::SymmetricKey,
    enc: &EncryptedIdentity,
    aad: &[u8],
) -> Option<Handshake> {
    let aead_key = handshake_secret.derive(HANDSHAKE_AUTH_CONTEXT);
    let nonce = static_crypto::NonceBytes::from_bytes(enc.aead_nonce);
    let plaintext =
        static_crypto::decrypt_aad(&aead_key, &nonce, &enc.ciphertext, aad).ok()?;
    deserialize_handshake(&plaintext).ok()
}

/// A wire message (Phase 7: handshake + Sphinx only)
///
/// All maintenance (gossip, swap negotiation, prepayment,
/// reconciliation) travels Sphinx-wrapped inside encrypted bodies and
/// never appears as a direct wire message.
#[derive(Debug, Clone)]
pub enum WireMessage {
    /// Handshake message (legacy internal signaling + tests)
    ///
    /// Phase 7: no longer sent on the wire for peer handshakes (replaced
    /// by [`WireMessage::Hello`]/[`WireMessage::Welcome`]/
    /// [`WireMessage::AuthIdentity`]). Retained for reconnection signaling
    /// via `inbound_tx` and backward-compat tests.
    Handshake(Handshake),
    /// Hello (Phase 7 handshake message 1, client -> server)
    Hello(Hello),
    /// Welcome (Phase 7 handshake message 2, server -> client)
    Welcome(Welcome),
    /// Encrypted identity (Phase 7 messages 3-4, both directions)
    AuthIdentity(EncryptedIdentity),
    /// Sphinx packet (real, cover, or Sphinx-wrapped maintenance)
    Sphinx(SphinxPacket),
    /// Lightweight session reply (reply-session fragment)
    ///
    /// Serialized as a `MSG_SPHINX`-typed frame with a version-2 payload
    /// so an observer cannot distinguish session replies from Sphinx
    /// packets by wire type, framing or size.
    SessionReply(SessionReply),
}

/// Prepayment from a seed-only node to a sponsor
///
/// Sent as direct wire maintenance traffic (like gossip), not
/// Sphinx-wrapped. The sponsored chunks themselves are Sphinx-wrapped
/// for privacy; the prepayment record is accounting metadata.
/// Authenticated with Ed25519 over (from_node || bytes || content_id).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Prepayment {
    /// The sending node's ID
    pub from_node: NodeId,
    /// Amount of bytes being prepaid
    pub bytes: u64,
    /// Content ID this prepayment is for
    pub content_id: [u8; 32],
    /// Ed25519 identity public key of the seed node
    pub identity_public_key: [u8; 32],
    /// Signature proving the seed-only node authorized this payment
    pub signature: Vec<u8>,
}

impl Prepayment {
    /// Bytes covered by the prepayment signature.
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(16 + 8 + 32);
        buf.extend_from_slice(&self.from_node);
        buf.extend_from_slice(&self.bytes.to_be_bytes());
        buf.extend_from_slice(&self.content_id);
        buf
    }

    /// Create a signed prepayment.
    pub fn sign(
        from_node: NodeId,
        bytes: u64,
        content_id: [u8; 32],
        signing_key: &ed25519_dalek::SigningKey,
    ) -> Self {
        use ed25519_dalek::Signer;
        let identity_public_key = signing_key.verifying_key().to_bytes();
        let proto = Self {
            from_node,
            bytes,
            content_id,
            identity_public_key,
            signature: vec![],
        };
        let sig = signing_key.sign(&proto.signing_bytes());
        Self {
            signature: sig.to_bytes().to_vec(),
            ..proto
        }
    }

    /// Validate the prepayment fields with real Ed25519 verification.
    pub fn validate(&self) -> bool {
        use ed25519_dalek::{Signature, Verifier, VerifyingKey};
        if self.bytes == 0 || self.signature.len() != 64 {
            return false;
        }
        let Ok(pk) = VerifyingKey::from_bytes(&self.identity_public_key) else {
            return false;
        };
        let mut arr = [0u8; 64];
        arr.copy_from_slice(&self.signature);
        let sig = Signature::from_bytes(&arr);
        pk.verify(&self.signing_bytes(), &sig).is_ok()
    }
}

/// A single peer credit entry for reconciliation
///
/// Mirrors the fields of `static-accounting::PeerCredit` needed for
/// timestamp-based last-write-wins. Defined here (rather than in
/// `static-accounting`) so `static-mesh` does not gain a dependency
/// on `static-accounting`; `static-node` converts between the two.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ReconciliationEntry {
    /// The peer node ID this credit is for
    pub peer_id: NodeId,
    /// Bytes served to this peer
    pub bytes_served: u64,
    /// Bytes received from this peer
    pub bytes_received: u64,
    /// Net credit (served - received)
    pub net_credit: i64,
    /// Last interaction timestamp (for last-write-wins)
    pub last_interaction: u64,
    /// Prepaid bytes (for seed-only sponsor tracking)
    pub prepaid_bytes: u64,
    /// Successful challenges
    pub successful_challenges: u32,
    /// Failed challenges
    pub failed_challenges: u32,
}

/// A message to reconcile accounting state after a network partition
///
/// Sent as direct wire maintenance traffic (like gossip/prepayment).
/// Large peer sets are split into batches of at most
/// [`MAX_RECONCILIATION_ENTRIES`] entries; receivers process batches
/// sequentially since reconciliation is idempotent.
/// Authenticated: `signature` is Ed25519 over (from_node || timestamp ||
/// blake3(entries_json)) with `identity_public_key`.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AccountingReconciliation {
    /// The sending node's ID
    pub from_node: NodeId,
    /// The sending node's peer credits (subset relevant to the receiver)
    pub peer_credits: Vec<ReconciliationEntry>,
    /// The sending node's total_bytes_served
    pub total_bytes_served: u64,
    /// The sending node's total_bytes_received
    pub total_bytes_received: u64,
    /// Timestamp of this reconciliation message
    pub timestamp: u64,
    /// Ed25519 identity public key of the sender
    #[serde(default)]
    pub identity_public_key: [u8; 32],
    /// Ed25519 signature over [`AccountingReconciliation::signing_bytes`]
    #[serde(default)]
    pub signature: Vec<u8>,
}

impl AccountingReconciliation {
    /// Bytes covered by the reconciliation signature.
    pub fn signing_bytes(&self) -> Vec<u8> {
        let entries_json = serde_json::to_vec(&self.peer_credits).unwrap_or_default();
        let digest = blake3::hash(&entries_json);
        let mut buf = Vec::with_capacity(16 + 8 + 32);
        buf.extend_from_slice(&self.from_node);
        buf.extend_from_slice(&self.timestamp.to_be_bytes());
        buf.extend_from_slice(digest.as_bytes());
        buf
    }

    /// Sign this reconciliation message.
    pub fn sign(&mut self, signing_key: &ed25519_dalek::SigningKey) {
        use ed25519_dalek::Signer;
        self.identity_public_key = signing_key.verifying_key().to_bytes();
        let sig = signing_key.sign(&self.signing_bytes());
        self.signature = sig.to_bytes().to_vec();
    }

    /// Verify sender signature + basic sanity (timestamp not far future,
    /// entry count within batch cap).
    pub fn verify(&self, now_secs: u64) -> bool {
        use ed25519_dalek::{Signature, Verifier, VerifyingKey};
        if self.peer_credits.len() > MAX_RECONCILIATION_ENTRIES {
            return false;
        }
        // Future-timestamp bound: reject >5 minutes in the future (LWW abuse).
        if self.timestamp > now_secs.saturating_add(300) {
            return false;
        }
        if self.signature.len() != 64 {
            return false;
        }
        let Ok(pk) = VerifyingKey::from_bytes(&self.identity_public_key) else {
            return false;
        };
        let mut arr = [0u8; 64];
        arr.copy_from_slice(&self.signature);
        let sig = Signature::from_bytes(&arr);
        // Sanity: per-entry values must be plausible (no u64::MAX inflation).
        for e in &self.peer_credits {
            if e.bytes_served > (1u64 << 60) || e.bytes_received > (1u64 << 60) || e.prepaid_bytes > (1u64 << 60) {
                return false;
            }
        }
        pk.verify(&self.signing_bytes(), &sig).is_ok()
    }
}

/// Errors that can occur during wire protocol operations
#[derive(Debug, thiserror::Error)]
pub enum WireError {
    /// Message is too large
    #[error("message too large: {size} bytes (max {max})")]
    MessageTooLarge {
        /// Actual size
        size: usize,
        /// Maximum allowed size
        max: usize,
    },
    /// Invalid message type
    #[error("invalid message type: {0}")]
    InvalidMessageType(u8),
    /// Buffer too short to read
    #[error("buffer too short: need {needed} bytes, have {have}")]
    BufferTooShort {
        /// Bytes needed
        needed: usize,
        /// Bytes available
        have: usize,
    },
    /// Invalid Sphinx packet structure
    #[error("invalid sphinx packet structure")]
    InvalidSphinxPacket,
    /// I/O error
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

/// Serialize a handshake message into a bytes buffer
///
/// Layout: `[16 node_id][32 mix_pub][2 kem_len][kem][1 compute_en]
/// [1 compute_cap][32 identity_pub][32 nonce][64 signature]`.
fn serialize_handshake(handshake: &Handshake) -> Vec<u8> {
    let kem_len = handshake.kem_public_key.as_ref().map(|k| k.len()).unwrap_or(0);
    let mut buf = Vec::with_capacity(16 + 32 + 2 + kem_len + 2 + 32 + 32 + 64);
    buf.extend_from_slice(&handshake.node_id);
    buf.extend_from_slice(&handshake.public_key);
    buf.extend_from_slice(&(kem_len as u16).to_be_bytes());
    if let Some(kem) = &handshake.kem_public_key {
        buf.extend_from_slice(kem);
    }
    buf.push(u8::from(handshake.compute_enabled));
    buf.push(handshake.compute_capacity);
    buf.extend_from_slice(&handshake.identity_public_key);
    buf.extend_from_slice(&handshake.nonce);
    // Signature must be exactly 64 bytes; pad/truncate defensively (sign
    // always produces 64, this only affects malformed in-memory values).
    let mut sig = [0u8; 64];
    let n = handshake.signature.len().min(64);
    sig[..n].copy_from_slice(&handshake.signature[..n]);
    buf.extend_from_slice(&sig);
    buf
}

/// Deserialize a handshake message from a bytes buffer (unified format only).
fn deserialize_handshake(data: &[u8]) -> Result<Handshake, WireError> {
    const MIN: usize = 16 + 32 + 2 + 2 + 32 + 32 + 64;
    if data.len() < MIN {
        return Err(WireError::BufferTooShort {
            needed: MIN,
            have: data.len(),
        });
    }
    let mut offset = 0;
    let mut node_id = [0u8; 16];
    node_id.copy_from_slice(&data[offset..offset + 16]);
    offset += 16;
    let mut public_key = [0u8; 32];
    public_key.copy_from_slice(&data[offset..offset + 32]);
    offset += 32;
    let kem_len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
    offset += 2;
    if kem_len > 4096 || data.len() < offset + kem_len + 2 + 32 + 32 + 64 {
        return Err(WireError::BufferTooShort {
            needed: offset + kem_len + 2 + 32 + 32 + 64,
            have: data.len(),
        });
    }
    let kem_public_key = if kem_len == 0 {
        None
    } else {
        Some(data[offset..offset + kem_len].to_vec())
    };
    offset += kem_len;
    let compute_enabled = data[offset] == 1;
    let compute_capacity = data[offset + 1];
    offset += 2;
    let mut identity_public_key = [0u8; 32];
    identity_public_key.copy_from_slice(&data[offset..offset + 32]);
    offset += 32;
    let mut nonce = [0u8; 32];
    nonce.copy_from_slice(&data[offset..offset + 32]);
    offset += 32;
    if data.len() < offset + 64 {
        return Err(WireError::BufferTooShort {
            needed: offset + 64,
            have: data.len(),
        });
    }
    let signature = data[offset..offset + 64].to_vec();

    Ok(Handshake {
        node_id,
        public_key,
        kem_public_key,
        compute_enabled,
        compute_capacity,
        identity_public_key,
        nonce,
        signature,
    })
}

/// Serialize a Hello message (un-padded).
fn serialize_hello(hello: &Hello) -> Vec<u8> {
    let kem_len = hello.eph_kem_pub_key.len();
    let mut buf = Vec::with_capacity(32 + 2 + kem_len + 32);
    buf.extend_from_slice(&hello.eph_pub_key);
    buf.extend_from_slice(&(kem_len as u16).to_be_bytes());
    buf.extend_from_slice(&hello.eph_kem_pub_key);
    buf.extend_from_slice(&hello.nonce);
    buf
}

/// Deserialize a Hello message (trailing pad ignored).
fn deserialize_hello(data: &[u8]) -> Result<Hello, WireError> {
    const MIN: usize = 32 + 2 + 32;
    if data.len() < MIN {
        return Err(WireError::BufferTooShort { needed: MIN, have: data.len() });
    }
    let mut eph_pub_key = [0u8; 32];
    eph_pub_key.copy_from_slice(&data[..32]);
    let kem_len = u16::from_be_bytes([data[32], data[33]]) as usize;
    if kem_len != static_sphinx::HYBRID_KEM_PUBLIC_KEY_SIZE {
        return Err(WireError::InvalidSphinxPacket);
    }
    if data.len() < 32 + 2 + kem_len + 32 {
        return Err(WireError::BufferTooShort {
            needed: 32 + 2 + kem_len + 32,
            have: data.len(),
        });
    }
    let eph_kem_pub_key = data[34..34 + kem_len].to_vec();
    let mut nonce = [0u8; 32];
    nonce.copy_from_slice(&data[34 + kem_len..34 + kem_len + 32]);
    Ok(Hello { eph_pub_key, eph_kem_pub_key, nonce })
}

/// Serialize a Welcome message (un-padded).
fn serialize_welcome(welcome: &Welcome) -> Vec<u8> {
    let kem_len = welcome.eph_kem_pub_key.len();
    let ct_len = welcome.kem_ciphertext.len();
    let mut buf = Vec::with_capacity(32 + 2 + kem_len + 32 + 2 + ct_len);
    buf.extend_from_slice(&welcome.eph_pub_key);
    buf.extend_from_slice(&(kem_len as u16).to_be_bytes());
    buf.extend_from_slice(&welcome.eph_kem_pub_key);
    buf.extend_from_slice(&welcome.nonce);
    buf.extend_from_slice(&(ct_len as u16).to_be_bytes());
    buf.extend_from_slice(&welcome.kem_ciphertext);
    buf
}

/// Deserialize a Welcome message (trailing pad ignored).
fn deserialize_welcome(data: &[u8]) -> Result<Welcome, WireError> {
    if data.len() < 32 + 2 + 32 + 2 {
        return Err(WireError::BufferTooShort { needed: 32 + 2 + 32 + 2, have: data.len() });
    }
    let mut eph_pub_key = [0u8; 32];
    eph_pub_key.copy_from_slice(&data[..32]);
    let kem_len = u16::from_be_bytes([data[32], data[33]]) as usize;
    if kem_len != static_sphinx::HYBRID_KEM_PUBLIC_KEY_SIZE {
        return Err(WireError::InvalidSphinxPacket);
    }
    if data.len() < 32 + 2 + kem_len + 32 + 2 {
        return Err(WireError::BufferTooShort {
            needed: 32 + 2 + kem_len + 32 + 2,
            have: data.len(),
        });
    }
    let eph_kem_pub_key = data[34..34 + kem_len].to_vec();
    let mut nonce = [0u8; 32];
    nonce.copy_from_slice(&data[34 + kem_len..34 + kem_len + 32]);
    let ct_off = 34 + kem_len + 32;
    let ct_len = u16::from_be_bytes([data[ct_off], data[ct_off + 1]]) as usize;
    if ct_len != static_sphinx::HYBRID_KEM_CIPHERTEXT_SIZE {
        return Err(WireError::InvalidSphinxPacket);
    }
    if data.len() < ct_off + 2 + ct_len {
        return Err(WireError::BufferTooShort {
            needed: ct_off + 2 + ct_len,
            have: data.len(),
        });
    }
    let kem_ciphertext = data[ct_off + 2..ct_off + 2 + ct_len].to_vec();
    Ok(Welcome { eph_pub_key, eph_kem_pub_key, nonce, kem_ciphertext })
}

/// Serialize an EncryptedIdentity (un-padded).
fn serialize_auth_identity(enc: &EncryptedIdentity) -> Vec<u8> {
    let mut buf = Vec::with_capacity(12 + 2 + enc.ciphertext.len());
    buf.extend_from_slice(&enc.aead_nonce);
    buf.extend_from_slice(&(enc.ciphertext.len() as u16).to_be_bytes());
    buf.extend_from_slice(&enc.ciphertext);
    buf
}

/// Deserialize an EncryptedIdentity (trailing pad ignored).
fn deserialize_auth_identity(data: &[u8]) -> Result<EncryptedIdentity, WireError> {
    if data.len() < 12 + 2 {
        return Err(WireError::BufferTooShort { needed: 14, have: data.len() });
    }
    let mut aead_nonce = [0u8; 12];
    aead_nonce.copy_from_slice(&data[..12]);
    let ct_len = u16::from_be_bytes([data[12], data[13]]) as usize;
    if ct_len == 0 || ct_len > 4096 || data.len() < 14 + ct_len {
        return Err(WireError::BufferTooShort { needed: 14 + ct_len, have: data.len() });
    }
    let ciphertext = data[14..14 + ct_len].to_vec();
    Ok(EncryptedIdentity { aead_nonce, ciphertext })
}

/// Pad a handshake payload to the uniform wire size with random bytes.
///
/// All handshake messages share one size so Hello/Welcome/AuthIdentity are
/// indistinguishable to an observer.
fn pad_handshake(mut payload: Vec<u8>) -> Vec<u8> {
    use rand::RngCore;
    if payload.len() > PADDED_MESSAGE_SIZE {
        return payload;
    }
    let pad_len = PADDED_MESSAGE_SIZE - payload.len();
    let mut pad = vec![0u8; pad_len];
    rand::rngs::OsRng.fill_bytes(&mut pad);
    payload.extend_from_slice(&pad);
    payload
}
///
/// Wrap a maintenance payload for Sphinx transport (Phase 7, Task 1).
///
/// Prepends the Sphinx-body type byte to the (typically JSON-encoded)
/// payload. The result is fragmented via `fragment_payload()` and wrapped
/// in hybrid Sphinx packets; the wire never sees the type byte or JSON.
pub fn wrap_maintenance_payload(body_type: u8, payload: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(1 + payload.len());
    buf.push(body_type);
    buf.extend_from_slice(payload);
    buf
}

/// Split a maintenance payload into its type byte and JSON body.
pub fn split_maintenance_payload(data: &[u8]) -> Option<(u8, &[u8])> {
    let (first, rest) = data.split_first()?;
    Some((*first, rest))
}

/// Serialize a Sphinx packet into a bytes buffer
///
/// Versioned format (v0/v1 emit the same layout; legacy decoders that
/// expect the unversioned layout are handled on the receive side):
/// `[1 byte version][32 ephemeral][4 kem_len][kem bytes][routing][16 mac][body]`.
/// Classical packets carry an empty kem section. Hybrid packets carry the
/// fixed [`KEM_BLOCK_SIZE`] block; bodies are [`WIRE_BODY_SIZE`] (AEAD).
fn serialize_sphinx(packet: &SphinxPacket) -> Vec<u8> {
    let mut buf = Vec::with_capacity(
        1 + 4 + EPHEMERAL_KEY_SIZE + packet.kem_ciphertexts.len() + ROUTING_INFO_SIZE + MAC_SIZE + packet.body.len()
    );

    // Packet version (0 = classical, 1 = hybrid)
    buf.push(packet.header.version);

    // Ephemeral key (32 bytes)
    buf.extend_from_slice(&packet.header.ephemeral_key);

    // Reply-session id (32 bytes)
    buf.extend_from_slice(&packet.header.session_id);

    // ML-KEM block (length-prefixed; empty for classical, fixed for hybrid)
    buf.extend_from_slice(&(packet.kem_ciphertexts.len() as u32).to_be_bytes());
    buf.extend_from_slice(&packet.kem_ciphertexts);

    // Routing info (fixed size)
    buf.extend_from_slice(&packet.header.routing_info);

    // MAC (16 bytes)
    buf.extend_from_slice(&packet.header.mac);

    // Body (WIRE_BODY_SIZE for Phase 7 packets)
    buf.extend_from_slice(&packet.body);

    buf
}

/// Deserialize a Sphinx packet from a bytes buffer
///
/// Accepts both the legacy unversioned layout (exact classical length,
/// no version prefix — emitted by pre-upgrade peers) and the versioned
/// layout. Phase 7 bodies are [`WIRE_BODY_SIZE`]; legacy [`BODY_SIZE`]
/// bodies are also accepted for the classical path (pre-AEAD peers).
/// Hybrid KEM sections must be empty (classical) or exactly
/// [`KEM_BLOCK_SIZE`] (fixed block, no position leak).
fn deserialize_sphinx(data: &[u8]) -> Result<SphinxPacket, WireError> {
    let legacy_len = EPHEMERAL_KEY_SIZE + ROUTING_INFO_SIZE + MAC_SIZE + BODY_SIZE;
    if data.len() == legacy_len {
        // Legacy pre-upgrade packet: classical, no version prefix.
        let mut offset = 0;

        let mut ephemeral_key = [0u8; EPHEMERAL_KEY_SIZE];
        ephemeral_key.copy_from_slice(&data[offset..offset + EPHEMERAL_KEY_SIZE]);
        offset += EPHEMERAL_KEY_SIZE;

        let routing_info = data[offset..offset + ROUTING_INFO_SIZE].to_vec();
        offset += ROUTING_INFO_SIZE;

        let mut mac = [0u8; MAC_SIZE];
        mac.copy_from_slice(&data[offset..offset + MAC_SIZE]);
        offset += MAC_SIZE;

        let body = data[offset..offset + BODY_SIZE].to_vec();

        let header = SphinxHeader {
            version: SPHINX_VERSION_CLASSICAL,
            ephemeral_key,
            session_id: [0u8; SESSION_ID_SIZE],
            routing_info,
            mac,
        };

        return Ok(SphinxPacket { header, kem_ciphertexts: Vec::new(), body });
    }

    let min_len = 1 + EPHEMERAL_KEY_SIZE + SESSION_ID_SIZE + 4 + ROUTING_INFO_SIZE + MAC_SIZE + BODY_SIZE;
    if data.len() < min_len {
        return Err(WireError::BufferTooShort {
            needed: min_len,
            have: data.len(),
        });
    }

    let mut offset = 0;
    let version = data[offset];
    offset += 1;
    let mut ephemeral_key = [0u8; EPHEMERAL_KEY_SIZE];
    ephemeral_key.copy_from_slice(&data[offset..offset + EPHEMERAL_KEY_SIZE]);
    offset += EPHEMERAL_KEY_SIZE;

    let mut session_id = [0u8; SESSION_ID_SIZE];
    session_id.copy_from_slice(&data[offset..offset + SESSION_ID_SIZE]);
    offset += SESSION_ID_SIZE;

    let kem_len =
        u32::from_be_bytes([data[offset], data[offset + 1], data[offset + 2], data[offset + 3]])
            as usize;
    offset += 4;

    // Phase 7: hybrid KEM must be the fixed block; classical must be empty.
    let kem_ok = if version == SPHINX_VERSION_HYBRID {
        kem_len == KEM_BLOCK_SIZE
    } else {
        kem_len == 0 || kem_len % HYBRID_KEM_CIPHERTEXT_SIZE == 0
    };
    if !kem_ok {
        return Err(WireError::InvalidSphinxPacket);
    }
    // Body is WIRE_BODY_SIZE for Phase 7 packets; accept legacy BODY_SIZE
    // for classical backward compat.
    let remaining = data.len() - offset - kem_len - ROUTING_INFO_SIZE - MAC_SIZE;
    let body_len = if remaining == WIRE_BODY_SIZE {
        WIRE_BODY_SIZE
    } else if remaining == BODY_SIZE {
        BODY_SIZE
    } else {
        return Err(WireError::BufferTooShort {
            needed: offset + kem_len + ROUTING_INFO_SIZE + MAC_SIZE + WIRE_BODY_SIZE,
            have: data.len(),
        });
    };
    if data.len() < offset + kem_len + ROUTING_INFO_SIZE + MAC_SIZE + body_len {
        return Err(WireError::BufferTooShort {
            needed: offset + kem_len + ROUTING_INFO_SIZE + MAC_SIZE + body_len,
            have: data.len(),
        });
    }
    let kem_ciphertexts = data[offset..offset + kem_len].to_vec();
    offset += kem_len;

    let routing_info = data[offset..offset + ROUTING_INFO_SIZE].to_vec();
    offset += ROUTING_INFO_SIZE;

    let mut mac = [0u8; MAC_SIZE];
    mac.copy_from_slice(&data[offset..offset + MAC_SIZE]);
    offset += MAC_SIZE;

    let body = data[offset..offset + body_len].to_vec();

    let header = SphinxHeader {
        version,
        ephemeral_key,
        session_id,
        routing_info,
        mac,
    };

    Ok(SphinxPacket { header, kem_ciphertexts, body })
}

/// Serialize a wire message into a framed byte buffer
///
/// Format: [1 byte type] [4 bytes payload length] [N bytes payload]
/// Format: [1 byte type] [4 bytes payload length] [N bytes payload]
/// (Phase 7: handshake messages are pre-padded to the uniform size;
/// Sphinx packets are size-realistic; no direct maintenance messages).
pub fn serialize_message(msg: &WireMessage) -> Result<Vec<u8>, WireError> {
    let (msg_type, payload) = match msg {
        WireMessage::Handshake(hs) => (MSG_HANDSHAKE, serialize_handshake(hs)),
        WireMessage::Hello(h) => (MSG_HELLO, pad_handshake(serialize_hello(h))),
        WireMessage::Welcome(w) => (MSG_WELCOME, pad_handshake(serialize_welcome(w))),
        WireMessage::AuthIdentity(a) => (MSG_AUTH_IDENTITY, pad_handshake(serialize_auth_identity(a))),
        WireMessage::Sphinx(pkt) => (MSG_SPHINX, serialize_sphinx(pkt)),
        // Session replies ride the Sphinx wire type byte with a
        // version-2 payload of identical size (wire uniformity).
        WireMessage::SessionReply(reply) => (MSG_SPHINX, reply.serialize()),
    };

    let total_len = 1 + 4 + payload.len();
    // Sphinx packets and session replies have their own (larger,
    // version-aware) cap since hybrid packets carry the fixed KEM block.
    let max = match msg {
        WireMessage::Sphinx(_) | WireMessage::SessionReply(_) => HYBRID_MAX_MESSAGE_SIZE,
        WireMessage::Handshake(_) => HYBRID_MAX_MESSAGE_SIZE,
        _ => 1 + 4 + PADDED_MESSAGE_SIZE,
    };
    if total_len > max {
        return Err(WireError::MessageTooLarge {
            size: total_len,
            max,
        });
    }

    let mut buf = Vec::with_capacity(total_len);
    buf.push(msg_type);
    buf.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    buf.extend_from_slice(&payload);

    Ok(buf)
}

/// Deserialize a wire message from a framed byte buffer
///
/// Expects the full message including type byte and length prefix.
/// Returns the message and the number of bytes consumed.
pub fn deserialize_message(data: &[u8]) -> Result<(WireMessage, usize), WireError> {
    if data.len() < 5 {
        return Err(WireError::BufferTooShort {
            needed: 5,
            have: data.len(),
        });
    }

    let msg_type = data[0];
    let payload_len = u32::from_be_bytes([
        data[1], data[2], data[3], data[4],
    ]) as usize;

    let total_len = 5 + payload_len;
    if data.len() < total_len {
        return Err(WireError::BufferTooShort {
            needed: total_len,
            have: data.len(),
        });
    }

    let payload = &data[5..total_len];

    let message = match msg_type {
        MSG_HANDSHAKE => {
            WireMessage::Handshake(deserialize_handshake(payload)?)
        }
        MSG_HELLO => {
            WireMessage::Hello(deserialize_hello(payload)?)
        }
        MSG_WELCOME => {
            WireMessage::Welcome(deserialize_welcome(payload)?)
        }
        MSG_AUTH_IDENTITY => {
            WireMessage::AuthIdentity(deserialize_auth_identity(payload)?)
        }
        MSG_SPHINX => {
            // Version-byte discriminator inside the Sphinx payload:
            // 0/1 = classical/hybrid Sphinx, 2 = session reply. Legacy
            // (unversioned) packets are matched by exact length first
            // (their leading byte is random ephemeral key material).
            if payload.len() == SESSION_REPLY_WIRE_SIZE
                && payload[0] == SPHINX_VERSION_SESSION_REPLY
            {
                WireMessage::SessionReply(
                    SessionReply::deserialize(payload)
                        .map_err(|_| WireError::InvalidSphinxPacket)?,
                )
            } else {
                WireMessage::Sphinx(deserialize_sphinx(payload)?)
            }
        }
        _ => return Err(WireError::InvalidMessageType(msg_type)),
    };

    Ok((message, total_len))
}

/// Read a framed message from a BytesMut buffer.
///
/// This is used by the async transport to parse incoming data.
/// Returns Ok(Some(message)) if a complete message is available,
/// Ok(None) if more data is needed, or Err on protocol error.
/// Enforces a length cap before buffering (DoS bound, C5): any
/// payload length exceeding PADDED_MESSAGE_SIZE is rejected immediately
/// instead of waiting for gigabytes.
pub fn try_read_message(buf: &mut BytesMut) -> Result<Option<WireMessage>, WireError> {
    if buf.len() < 5 {
        return Ok(None);
    }

    // Peek at the length without consuming
    let payload_len = u32::from_be_bytes([
        buf[1], buf[2], buf[3], buf[4],
    ]) as usize;

    if payload_len > PADDED_MESSAGE_SIZE {
        return Err(WireError::MessageTooLarge {
            size: 5 + payload_len,
            max: 5 + PADDED_MESSAGE_SIZE,
        });
    }

    let total_len = 5 + payload_len;
    if buf.len() < total_len {
        return Ok(None);
    }

    // Extract the message bytes
    let message_bytes = buf.split_to(total_len);
    let (message, _) = deserialize_message(&message_bytes)?;

    Ok(Some(message))
}

/// Write a framed message into a BytesMut buffer.
///
/// This is used by the async transport to queue outgoing messages.
pub fn write_message(buf: &mut BytesMut, msg: &WireMessage) -> Result<(), WireError> {
    let serialized = serialize_message(msg)?;
    buf.put_slice(&serialized);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
use static_sphinx::{Route, RouteHop, MixNode, create_packet, process_packet};
    use rand::RngCore;

    fn random_node_id() -> NodeId {
        let mut id = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut id);
        id
    }

    fn create_test_route(n: usize) -> (Vec<MixNode>, Route) {
        let mut nodes = Vec::with_capacity(n);
        let mut hops = Vec::with_capacity(n);
        for _ in 0..n {
            let node = MixNode::new();
            hops.push(RouteHop {
                public_key: node.public_key,
                node_id: node.node_id,
            });
            nodes.push(node);
        }
        let destination = random_node_id();
        let route = Route { hops, destination };
        (nodes, route)
    }

    fn signed_test_handshake(
        node_id: NodeId,
        public_key: [u8; 32],
        kem: Option<Vec<u8>>,
        compute_enabled: bool,
        compute_capacity: u8,
    ) -> Handshake {
        use ed25519_dalek::SigningKey;
        use rand::RngCore;
        let mut sk_bytes = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut sk_bytes);
        let sk = SigningKey::from_bytes(&sk_bytes);
        let mut nonce = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut nonce);
        let mut hs = Handshake {
            node_id,
            public_key,
            kem_public_key: kem,
            compute_enabled,
            compute_capacity,
            identity_public_key: [0u8; 32],
            nonce,
            signature: vec![],
        };
        hs.sign(&sk);
        hs
    }

    #[test]
    fn test_handshake_serialization() {
        let hs = signed_test_handshake([0x42u8; 16], [0xABu8; 32], None, false, 0);

        let serialized = serialize_handshake(&hs);
        // 16+32+2+0+2+32+32+64 = 180
        assert_eq!(serialized.len(), 180);

        let deserialized = deserialize_handshake(&serialized).unwrap();
        assert_eq!(deserialized.node_id, hs.node_id);
        assert_eq!(deserialized.public_key, hs.public_key);
        assert!(deserialized.kem_public_key.is_none());
        assert!(!deserialized.compute_enabled);
        assert_eq!(deserialized.compute_capacity, 0);
        assert!(deserialized.verify());
    }

    #[test]
    fn test_handshake_bad_signature_rejected() {
        let mut hs = signed_test_handshake([0x42u8; 16], [0xABu8; 32], None, false, 0);
        hs.signature[0] ^= 0xFF;
        assert!(!hs.verify());
        // Tampered bytes fail after round-trip too.
        let serialized = serialize_handshake(&hs);
        let back = deserialize_handshake(&serialized).unwrap();
        assert!(!back.verify());
    }

    #[test]
    fn test_handshake_too_short() {
        let result = deserialize_handshake(&[0u8; 10]);
        assert!(matches!(result, Err(WireError::BufferTooShort { .. })));
    }

    #[test]
    fn test_sphinx_serialization_roundtrip() {
        let (_nodes, route) = create_test_route(3);
        let body = b"wire protocol test";
        let packet = create_packet(&route, body).unwrap();

        let serialized = serialize_sphinx(&packet);
        let deserialized = deserialize_sphinx(&serialized).unwrap();

        assert_eq!(deserialized.header.ephemeral_key, packet.header.ephemeral_key);
        assert_eq!(deserialized.header.routing_info, packet.header.routing_info);
        assert_eq!(deserialized.header.mac, packet.header.mac);
        assert_eq!(deserialized.body, packet.body);
    }

    #[test]
    fn test_sphinx_packet_still_works_after_wire() {
        let (mut nodes, route) = create_test_route(3);
        let body = b"end-to-end wire test";
        let packet = create_packet(&route, body).unwrap();

        // Serialize and deserialize through wire protocol
        let serialized = serialize_sphinx(&packet);
        let deserialized = deserialize_sphinx(&serialized).unwrap();

        // Process through the mixnet - should still work
        let result0 = process_packet(&mut nodes[0], deserialized).unwrap();
        assert_eq!(result0.flag, static_sphinx::RoutingFlag::Forward);

        let result1 = process_packet(&mut nodes[1], result0.forward_packet.unwrap()).unwrap();
        assert_eq!(result1.flag, static_sphinx::RoutingFlag::Forward);

        let result2 = process_packet(&mut nodes[2], result1.forward_packet.unwrap()).unwrap();
        assert_eq!(result2.flag, static_sphinx::RoutingFlag::Destination);

        let decrypted = result2.body.unwrap();
        assert_eq!(&decrypted[..body.len()], body);
    }

    #[test]
    fn test_message_serialization_handshake() {
        let hs = signed_test_handshake([0x42u8; 16], [0xABu8; 32], None, false, 0);
        let msg = WireMessage::Handshake(hs);

        let serialized = serialize_message(&msg).unwrap();
        assert_eq!(serialized[0], MSG_HANDSHAKE);

        let (deserialized, consumed) = deserialize_message(&serialized).unwrap();
        assert_eq!(consumed, serialized.len());

        match deserialized {
            WireMessage::Handshake(hs2) => {
                assert_eq!(hs2.node_id, [0x42u8; 16]);
                assert_eq!(hs2.public_key, [0xABu8; 32]);
            }
            _ => panic!("expected handshake"),
        }
    }

    #[test]
    fn test_message_serialization_sphinx() {
        let (_nodes, route) = create_test_route(2);
        let packet = create_packet(&route, b"sphinx wire test").unwrap();
        let msg = WireMessage::Sphinx(packet);

        let serialized = serialize_message(&msg).unwrap();
        assert_eq!(serialized[0], MSG_SPHINX);

        let (deserialized, consumed) = deserialize_message(&serialized).unwrap();
        assert_eq!(consumed, serialized.len());

        match deserialized {
            WireMessage::Sphinx(_) => {}
            _ => panic!("expected sphinx"),
        }
    }

    #[test]
    fn test_invalid_message_type() {
        let mut buf = vec![0xFFu8; 10];
        buf[1..5].copy_from_slice(&5u32.to_be_bytes());

        let result = deserialize_message(&buf);
        assert!(matches!(result, Err(WireError::InvalidMessageType(0xFF))));
    }

    #[test]
    fn test_try_read_message_partial() {
        let hs = signed_test_handshake([0x42u8; 16], [0xABu8; 32], None, false, 0);
        let msg = WireMessage::Handshake(hs);
        let serialized = serialize_message(&msg).unwrap();

        // Only first 3 bytes available
        let mut buf = BytesMut::from(&serialized[..3]);
        let result = try_read_message(&mut buf);
        assert!(matches!(result, Ok(None)));
    }

    #[test]
    fn test_try_read_message_complete() {
        let hs = signed_test_handshake([0x42u8; 16], [0xABu8; 32], None, false, 0);
        let msg = WireMessage::Handshake(hs);
        let serialized = serialize_message(&msg).unwrap();

        let mut buf = BytesMut::from(&serialized[..]);
        let result = try_read_message(&mut buf);
        assert!(result.is_ok());
        assert!(result.unwrap().is_some());
        assert_eq!(buf.len(), 0); // Buffer should be consumed
    }

    #[test]
    fn test_try_read_message_multiple() {
        let hs1 = signed_test_handshake([0x01u8; 16], [0x01u8; 32], None, false, 0);
        let hs2 = signed_test_handshake([0x02u8; 16], [0x02u8; 32], None, false, 0);

        let mut buf = BytesMut::new();
        write_message(&mut buf, &WireMessage::Handshake(hs1)).unwrap();
        write_message(&mut buf, &WireMessage::Handshake(hs2)).unwrap();

        // Read first message
        let msg1 = try_read_message(&mut buf).unwrap().unwrap();
        match msg1 {
            WireMessage::Handshake(hs) => assert_eq!(hs.node_id, [0x01u8; 16]),
            _ => panic!("expected handshake"),
        }

        // Read second message
        let msg2 = try_read_message(&mut buf).unwrap().unwrap();
        match msg2 {
            WireMessage::Handshake(hs) => assert_eq!(hs.node_id, [0x02u8; 16]),
            _ => panic!("expected handshake"),
        }

        // No more messages
        let msg3 = try_read_message(&mut buf).unwrap();
        assert!(msg3.is_none());
    }

    #[test]
    fn test_write_and_read_sphinx() {
        let (_nodes, route) = create_test_route(2);
        let packet = create_packet(&route, b"buf test").unwrap();
        let msg = WireMessage::Sphinx(packet);

        let mut buf = BytesMut::new();
        write_message(&mut buf, &msg).unwrap();

        let read_msg = try_read_message(&mut buf).unwrap().unwrap();
        match read_msg {
            WireMessage::Sphinx(_) => {}
            _ => panic!("expected sphinx"),
        }
    }

    #[test]
    fn test_max_message_size() {
        // Sphinx packet should be within max message size
        let (_nodes, route) = create_test_route(3);
        let packet = create_packet(&route, &[0u8; BODY_SIZE]).unwrap();
        let msg = WireMessage::Sphinx(packet);

        let serialized = serialize_message(&msg).unwrap();
        assert!(serialized.len() <= MAX_MESSAGE_SIZE);
    }

    #[test]
    fn test_sphinx_versioned_roundtrip() {
        let (_nodes, route) = create_test_route(2);
        let packet = create_packet(&route, b"versioned").unwrap();
        assert_eq!(packet.header.version, static_sphinx::SPHINX_VERSION_CLASSICAL);

        let serialized = serialize_sphinx(&packet);
        // Versioned encoding carries the version prefix (not legacy length).
        assert!(serialized.len() > EPHEMERAL_KEY_SIZE + ROUTING_INFO_SIZE + MAC_SIZE + BODY_SIZE);
        let back = deserialize_sphinx(&serialized).unwrap();
        assert_eq!(back.header.version, packet.header.version);
        assert!(back.kem_ciphertexts.is_empty());
        assert_eq!(back.body, packet.body);
    }

    #[test]
    fn test_sphinx_legacy_decode() {
        // Pre-upgrade peers emit the unversioned layout; it must still parse
        // as a classical packet.
        let mut legacy = vec![0x11u8; EPHEMERAL_KEY_SIZE + ROUTING_INFO_SIZE + MAC_SIZE + BODY_SIZE];
        let packet = deserialize_sphinx(&legacy).unwrap();
        assert_eq!(packet.header.version, static_sphinx::SPHINX_VERSION_CLASSICAL);
        assert!(packet.kem_ciphertexts.is_empty());
        legacy.push(0x00);
        // One byte too many matches neither layout.
        assert!(deserialize_sphinx(&legacy).is_err());
    }

    #[test]
    fn test_hybrid_sphinx_wire_roundtrip() {
        use static_sphinx::{HybridMixNode, HybridRoute, create_packet_hybrid};
        let mut nodes = vec![HybridMixNode::new(), HybridMixNode::new()];
        let route = HybridRoute {
            hops: vec![nodes[0].as_hop(), nodes[1].as_hop()],
            destination: [0x77u8; 16],
        };
        let packet = create_packet_hybrid(&route, b"hybrid wire").unwrap();
        let msg = WireMessage::Sphinx(packet.clone());
        let serialized = serialize_message(&msg).unwrap();
        assert!(serialized.len() <= HYBRID_MAX_MESSAGE_SIZE);
        let (back, consumed) = deserialize_message(&serialized).unwrap();
        assert_eq!(consumed, serialized.len());
        match back {
            WireMessage::Sphinx(p) => {
                assert_eq!(p.header.version, static_sphinx::SPHINX_VERSION_HYBRID);
                assert_eq!(p.kem_ciphertexts, packet.kem_ciphertexts);
                assert_eq!(p.body, packet.body);
            }
            _ => panic!("expected sphinx"),
        }
        let _ = &mut nodes;
    }

    #[test]
    fn test_handshake_kem_roundtrip() {
        let kem = vec![0x55u8; static_sphinx::HYBRID_KEM_PUBLIC_KEY_SIZE];
        let hs = signed_test_handshake([0x42u8; 16], [0xABu8; 32], Some(kem.clone()), false, 0);
        let serialized = serialize_handshake(&hs);
        assert_eq!(serialized.len(), 180 + kem.len());
        let back = deserialize_handshake(&serialized).unwrap();
        assert_eq!(back.kem_public_key, Some(kem));
        assert!(back.verify());
    }

    #[test]
    fn test_handshake_with_compute() {
        let kem = vec![0x66u8; static_sphinx::HYBRID_KEM_PUBLIC_KEY_SIZE];
        let hs = signed_test_handshake([0x77u8; 16], [0x88u8; 32], Some(kem.clone()), true, 4);

        let serialized = serialize_handshake(&hs);
        assert_eq!(serialized.len(), 180 + kem.len());
        let back = deserialize_handshake(&serialized).unwrap();

        assert_eq!(back.node_id, hs.node_id);
        assert_eq!(back.kem_public_key.as_deref(), Some(kem.as_slice()));
        assert!(back.compute_enabled);
        assert_eq!(back.compute_capacity, 4);
        assert!(back.verify());

        // Truncated buffer fails.
        assert!(deserialize_handshake(&serialized[..20]).is_err());
    }

    #[test]
    fn test_maintenance_messages_sphinx_wrapped() {
        // Phase 7 Task 1: no direct-wire maintenance types exist. The
        // only wire types are handshake-phase + Sphinx; maintenance
        // travels as [type byte][payload] inside Sphinx bodies.
        assert_ne!(MSG_HANDSHAKE, MSG_SPHINX);
        // Old direct-wire type bytes (0x03-0x08, 0x0B, 0x0C) are rejected.
        for bad in [0x03u8, 0x04, 0x05, 0x06, 0x07, 0x08, 0x0B, 0x0C] {
            let mut buf = bytes::BytesMut::from(&[bad, 0, 0, 0, 4, 1, 2, 3, 4][..]);
            let err = try_read_message(&mut buf).unwrap_err();
            assert!(matches!(err, crate::wire::WireError::InvalidMessageType(t) if t == bad));
        }
        // Body type bytes are a separate namespace (0x12+).
        let body = wrap_maintenance_payload(MSG_BODY_GOSSIP, b"{}");
        assert_eq!(body[0], MSG_BODY_GOSSIP);
        let (t, rest) = split_maintenance_payload(&body).unwrap();
        assert_eq!(t, MSG_BODY_GOSSIP);
        assert_eq!(rest, b"{}");
    }

    #[test]
    fn test_handshake_encrypted() {
        // Phase 7 Task 3: an eavesdropper cannot read node identity from
        // the encrypted identity message.
        let mut hs = signed_test_handshake([0xABu8; 16], [0xCDu8; 32], None, false, 0);
        hs.sign(&ed25519_dalek::SigningKey::from_bytes(&[0x11u8; 32]));
        let secret = static_crypto::SymmetricKey::random();
        let aad = handshake_session_aad(&[1u8; 32], &[2u8; 32]);
        let enc = encrypt_identity(&secret, &hs, &aad);
        let serialized = serialize_message(&WireMessage::AuthIdentity(enc.clone())).unwrap();
        let payload = &serialized[5..];
        // Neither node id nor mix pubkey appear in the ciphertext.
        assert!(!contains(payload, &hs.node_id));
        assert!(!contains(payload, &hs.public_key));
        // Wrong AAD or wrong key fails decryption.
        assert!(decrypt_identity(&secret, &enc, &handshake_session_aad(&[9u8; 32], &[2u8; 32])).is_none());
        assert!(decrypt_identity(&static_crypto::SymmetricKey::random(), &enc, &aad).is_none());
        // Right key + AAD recovers and verifies.
        let back = decrypt_identity(&secret, &enc, &aad).unwrap();
        assert_eq!(back.node_id, hs.node_id);
        assert!(back.verify());
    }

    fn contains(haystack: &[u8], needle: &[u8]) -> bool {
        haystack.windows(needle.len()).any(|w| w == needle)
    }

    #[test]
    fn test_handshake_padded() {
        // Phase 7 Task 3: Hello, Welcome, and AuthIdentity all serialize
        // to the same wire size (uniform padding, indistinguishable).
        let hello = Hello {
            eph_pub_key: [1u8; 32],
            eph_kem_pub_key: vec![0u8; static_sphinx::HYBRID_KEM_PUBLIC_KEY_SIZE],
            nonce: [2u8; 32],
        };
        let welcome = Welcome {
            eph_pub_key: [3u8; 32],
            eph_kem_pub_key: vec![0u8; static_sphinx::HYBRID_KEM_PUBLIC_KEY_SIZE],
            nonce: [4u8; 32],
            kem_ciphertext: vec![0u8; static_sphinx::HYBRID_KEM_CIPHERTEXT_SIZE],
        };
        let enc = EncryptedIdentity {
            aead_nonce: [5u8; 12],
            ciphertext: vec![0u8; 200],
        };
        let s1 = serialize_message(&WireMessage::Hello(hello)).unwrap();
        let s2 = serialize_message(&WireMessage::Welcome(welcome)).unwrap();
        let s3 = serialize_message(&WireMessage::AuthIdentity(enc)).unwrap();
        assert_eq!(s1.len(), s2.len());
        assert_eq!(s2.len(), s3.len());
        assert_eq!(s1.len(), 5 + PADDED_MESSAGE_SIZE);
        // Round-trips still parse.
        let (back, _) = deserialize_message(&s1).unwrap();
        assert!(matches!(back, WireMessage::Hello(_)));
    }

    // ---- Session reply wire tests (SURB per-fragment compression) ----

    use static_sphinx::create_packet_hybrid;

    fn test_session_reply() -> static_sphinx::SessionReply {
        let mut sid = [0u8; 32];
        let mut nonce = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut sid);
        rand::rngs::OsRng.fill_bytes(&mut nonce);
        static_sphinx::SessionReply {
            session_id: sid,
            nonce,
            body: vec![0x42u8; static_sphinx::WIRE_BODY_SIZE],
        }
    }

    #[test]
    fn test_session_reply_wire_uniformity() {
        // A session reply's wire frame is byte-for-byte the same size as
        // a hybrid Sphinx packet's: same MSG type byte, same framing,
        // same length. An ISP cannot distinguish them.
        let reply = test_session_reply();
        let reply_frame = serialize_message(&WireMessage::SessionReply(reply.clone())).unwrap();

        let nodes = test_hybrid_route_for_surb();
        let route = nodes.iter().map(|n| n.as_hop()).collect::<Vec<_>>();
        let packet = create_packet_hybrid(
            &static_sphinx::HybridRoute { hops: route, destination: [0x99u8; 16] },
            b"payload",
        )
        .unwrap();
        let sphinx_frame = serialize_message(&WireMessage::Sphinx(packet)).unwrap();

        assert_eq!(reply_frame.len(), sphinx_frame.len());
        assert_eq!(reply_frame[0], sphinx_frame[0]); // same wire type byte (MSG_SPHINX)
        assert_eq!(reply_frame.len(), 5 + SESSION_REPLY_WIRE_SIZE);
        // Serialized payload sizes match exactly.
        assert_eq!(
            reply.serialize().len(),
            static_sphinx::SESSION_REPLY_WIRE_SIZE
        );
    }

    #[test]
    fn test_session_reply_distinguishable_from_sphinx() {
        // Mix nodes distinguish deterministically via the payload
        // version byte (2 = session reply, 0/1 = Sphinx), while both
        // ride the identical MSG_SPHINX type byte and framing.
        let reply = test_session_reply();
        let frame = serialize_message(&WireMessage::SessionReply(reply)).unwrap();
        assert_eq!(frame[0], MSG_SPHINX);
        let (back, consumed) = deserialize_message(&frame).unwrap();
        assert_eq!(consumed, frame.len());
        match back {
            WireMessage::SessionReply(r) => {
                assert_eq!(r.body, vec![0x42u8; static_sphinx::WIRE_BODY_SIZE]);
            }
            _ => panic!("expected session reply"),
        }

        // A hybrid Sphinx packet with the same total size parses as
        // Sphinx (version byte 1), never as a session reply.
        let nodes = test_hybrid_route_for_surb();
        let route = nodes.iter().map(|n| n.as_hop()).collect::<Vec<_>>();
        let packet = create_packet_hybrid(
            &static_sphinx::HybridRoute { hops: route, destination: [0x98u8; 16] },
            b"payload",
        )
        .unwrap();
        let frame = serialize_message(&WireMessage::Sphinx(packet)).unwrap();
        assert_eq!(frame[0], MSG_SPHINX);
        assert!(matches!(
            deserialize_message(&frame).unwrap().0,
            WireMessage::Sphinx(_)
        ));

        // Roundtrip preserves all fields.
        let reply = test_session_reply();
        let (back, _) = deserialize_message(&serialize_message(&WireMessage::SessionReply(reply.clone())).unwrap()).unwrap();
        if let WireMessage::SessionReply(r) = back {
            assert_eq!(r.session_id, reply.session_id);
            assert_eq!(r.nonce, reply.nonce);
        } else {
            panic!("expected session reply");
        }
    }

    /// Small helper: fresh hybrid mix nodes for wire-size comparisons.
    fn test_hybrid_route_for_surb() -> Vec<static_sphinx::HybridMixNode> {
        vec![
            static_sphinx::HybridMixNode::new(),
            static_sphinx::HybridMixNode::new(),
            static_sphinx::HybridMixNode::new(),
        ]
    }
}
