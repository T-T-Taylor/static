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

use crate::routing::PeerGossip;
use static_storage::swap::{SwapProposal, SwapAccept, SwapReject};
// Re-exported so callers can construct `WireMessage::SwapCommit` /
// `WireMessage::SwapAbort` payloads as `crate::wire::SwapCommit { .. }`.
pub use static_storage::swap::{SwapAbort, SwapCommit};
use static_sphinx::{
    SphinxPacket, SphinxHeader, NodeId,
    BODY_SIZE, ROUTING_INFO_SIZE, EPHEMERAL_KEY_SIZE, MAC_SIZE,
    SPHINX_VERSION_CLASSICAL, HYBRID_KEM_CIPHERTEXT_SIZE, MAX_HOPS,
};
use bytes::{BufMut, BytesMut};

/// Handshake message type
pub const MSG_HANDSHAKE: u8 = 0x01;

/// Sphinx packet message type
pub const MSG_SPHINX: u8 = 0x02;

/// Peer gossip message type
pub const MSG_GOSSIP: u8 = 0x03;

/// Swap proposal message type
pub const MSG_SWAP_PROPOSAL: u8 = 0x04;

/// Swap accept message type
pub const MSG_SWAP_ACCEPT: u8 = 0x05;

/// Swap reject message type
pub const MSG_SWAP_REJECT: u8 = 0x06;

/// Prepayment message type
pub const MSG_PREPAYMENT: u8 = 0x07;

/// Accounting reconciliation message type
pub const MSG_ACCOUNTING_RECONCILIATION: u8 = 0x08;

/// Swap commit message type (2-phase commit finalize)
pub const MSG_SWAP_COMMIT: u8 = 0x0B;

/// Swap abort message type (2-phase commit cancel)
pub const MSG_SWAP_ABORT: u8 = 0x0C;

/// Maximum peer credit entries per reconciliation message (batching cap)
///
/// Keeps serialized reconciliation messages under `MAX_MESSAGE_SIZE`.
/// Nodes with more peers send multiple messages; `reconcile()` is
/// idempotent so batches converge to the same result.
pub const MAX_RECONCILIATION_ENTRIES: usize = 50;

/// Maximum message size (header + body + framing overhead)
///
/// Sized for a versioned classical Sphinx packet: outer framing plus the
/// version byte, ephemeral key, kem-length prefix, routing info, MAC, body.
pub const MAX_MESSAGE_SIZE: usize = 1 + 4 + 1 + 4 + EPHEMERAL_KEY_SIZE + ROUTING_INFO_SIZE + MAC_SIZE + BODY_SIZE;

/// Maximum hybrid message size
///
/// Hybrid v1 Sphinx packets additionally carry up to `MAX_HOPS` ML-KEM
/// ciphertexts (1088 bytes each): 1-byte version + u32 kem length +
/// ciphertexts on top of the classical layout.
pub const HYBRID_MAX_MESSAGE_SIZE: usize = MAX_MESSAGE_SIZE
    + 1
    + 4
    + static_sphinx::MAX_HOPS * static_sphinx::HYBRID_KEM_CIPHERTEXT_SIZE;

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

/// A wire message
#[derive(Debug, Clone)]
pub enum WireMessage {
    /// Handshake message
    Handshake(Handshake),
    /// Sphinx packet (real or cover, indistinguishable on the wire)
    Sphinx(SphinxPacket),
    /// Peer gossip message (network maintenance)
    Gossip(PeerGossip),
    /// Swap proposal (storage barter negotiation)
    SwapProposal(SwapProposal),
    /// Swap acceptance (storage barter negotiation)
    SwapAccept(SwapAccept),
    /// Swap rejection (storage barter negotiation)
    SwapReject(SwapReject),
    /// Swap commit (2-phase: both sides retrieved, finalize the swap)
    SwapCommit(SwapCommit),
    /// Swap abort (2-phase: one side failed, cancel the swap)
    SwapAbort(SwapAbort),
    /// Prepayment from a seed-only node to a sponsor
    Prepayment(Prepayment),
    /// Accounting state reconciliation (exchange peer credits after partition heal)
    AccountingReconciliation(AccountingReconciliation),
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

/// Serialize a Sphinx packet into a bytes buffer
///
/// Versioned format (v0/v1 emit the same layout; legacy decoders that
/// expect the unversioned layout are handled on the receive side):
/// `[1 byte version][32 ephemeral][4 kem_len][kem bytes][routing][16 mac][body]`.
/// Classical packets carry an empty kem section.
fn serialize_sphinx(packet: &SphinxPacket) -> Vec<u8> {
    let mut buf = Vec::with_capacity(
        1 + 4 + EPHEMERAL_KEY_SIZE + packet.kem_ciphertexts.len() + ROUTING_INFO_SIZE + MAC_SIZE + BODY_SIZE
    );

    // Packet version (0 = classical, 1 = hybrid)
    buf.push(packet.header.version);

    // Ephemeral key (32 bytes)
    buf.extend_from_slice(&packet.header.ephemeral_key);

    // ML-KEM ciphertexts (length-prefixed; empty for classical)
    buf.extend_from_slice(&(packet.kem_ciphertexts.len() as u32).to_be_bytes());
    buf.extend_from_slice(&packet.kem_ciphertexts);

    // Routing info (fixed size)
    buf.extend_from_slice(&packet.header.routing_info);

    // MAC (16 bytes)
    buf.extend_from_slice(&packet.header.mac);

    // Body (fixed size)
    buf.extend_from_slice(&packet.body);

    buf
}

/// Deserialize a Sphinx packet from a bytes buffer
///
/// Accepts both the legacy unversioned layout (exact classical length,
/// no version prefix — emitted by pre-upgrade peers) and the versioned
/// layout. Hybrid ciphertext length must be a multiple of the KEM
/// ciphertext size and fit within the hop limit.
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
            routing_info,
            mac,
        };

        return Ok(SphinxPacket { header, kem_ciphertexts: Vec::new(), body });
    }

    let min_len = 1 + EPHEMERAL_KEY_SIZE + 4 + ROUTING_INFO_SIZE + MAC_SIZE + BODY_SIZE;
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

    let kem_len =
        u32::from_be_bytes([data[offset], data[offset + 1], data[offset + 2], data[offset + 3]])
            as usize;
    offset += 4;

    if kem_len % HYBRID_KEM_CIPHERTEXT_SIZE != 0
        || kem_len / HYBRID_KEM_CIPHERTEXT_SIZE > MAX_HOPS
    {
        return Err(WireError::InvalidSphinxPacket);
    }
    if data.len() < offset + kem_len + ROUTING_INFO_SIZE + MAC_SIZE + BODY_SIZE {
        return Err(WireError::BufferTooShort {
            needed: offset + kem_len + ROUTING_INFO_SIZE + MAC_SIZE + BODY_SIZE,
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

    let body = data[offset..offset + BODY_SIZE].to_vec();

    let header = SphinxHeader {
        version,
        ephemeral_key,
        routing_info,
        mac,
    };

    Ok(SphinxPacket { header, kem_ciphertexts, body })
}

/// Serialize a wire message into a framed byte buffer
///
/// Format: [1 byte type] [4 bytes payload length] [N bytes payload]
/// (+ zero padding to uniform size for maintenance messages).
pub fn serialize_message(msg: &WireMessage) -> Result<Vec<u8>, WireError> {
    let (msg_type, mut payload) = match msg {
        WireMessage::Handshake(hs) => (MSG_HANDSHAKE, serialize_handshake(hs)),
        WireMessage::Sphinx(pkt) => (MSG_SPHINX, serialize_sphinx(pkt)),
        WireMessage::Gossip(g) => (MSG_GOSSIP, serde_json::to_vec(g).map_err(|_| WireError::InvalidMessageType(0))?),
        WireMessage::SwapProposal(s) => (MSG_SWAP_PROPOSAL, serde_json::to_vec(s).map_err(|_| WireError::InvalidMessageType(0))?),
        WireMessage::SwapAccept(s) => (MSG_SWAP_ACCEPT, serde_json::to_vec(s).map_err(|_| WireError::InvalidMessageType(0))?),
        WireMessage::SwapReject(s) => (MSG_SWAP_REJECT, serde_json::to_vec(s).map_err(|_| WireError::InvalidMessageType(0))?),
        WireMessage::SwapCommit(s) => (MSG_SWAP_COMMIT, serde_json::to_vec(s).map_err(|_| WireError::InvalidMessageType(0))?),
        WireMessage::SwapAbort(s) => (MSG_SWAP_ABORT, serde_json::to_vec(s).map_err(|_| WireError::InvalidMessageType(0))?),
        WireMessage::Prepayment(p) => (MSG_PREPAYMENT, serde_json::to_vec(p).map_err(|_| WireError::InvalidMessageType(0))?),
        WireMessage::AccountingReconciliation(r) => (MSG_ACCOUNTING_RECONCILIATION, serde_json::to_vec(r).map_err(|_| WireError::InvalidMessageType(0))?),
    };

    // Pad maintenance messages to the uniform hybrid size (C3) so an
    // observer cannot distinguish gossip/swap/prepay/reconcile by length.
    // Sphinx payloads are left as-is (already size-realistic). Handshakes
    // are left unpadded (variable KEM length is inherent to the handshake;
    // tier no longer leaks, KEM presence is required post-mandate).
    if !matches!(msg, WireMessage::Sphinx(_) | WireMessage::Handshake(_)) {
        if payload.len() > PADDED_MESSAGE_SIZE {
            return Err(WireError::MessageTooLarge {
                size: 1 + 4 + payload.len(),
                max: 1 + 4 + PADDED_MESSAGE_SIZE,
            });
        }
        payload.resize(PADDED_MESSAGE_SIZE, 0);
    }

    let total_len = 1 + 4 + payload.len();
    // Sphinx packets have their own (larger, version-aware) cap since
    // hybrid packets carry ML-KEM ciphertexts.
    let max = match msg {
        WireMessage::Sphinx(_) => HYBRID_MAX_MESSAGE_SIZE,
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

    // Maintenance messages are zero-padded to PADDED_MESSAGE_SIZE; strip
    // trailing zeros before JSON parsing. Sphinx/handshake are binary.
    fn trim_padded(p: &[u8]) -> &[u8] {
        let mut end = p.len();
        while end > 0 && p[end - 1] == 0 {
            end -= 1;
        }
        &p[..end]
    }

    let message = match msg_type {
        MSG_HANDSHAKE => {
            WireMessage::Handshake(deserialize_handshake(payload)?)
        }
        MSG_SPHINX => {
            WireMessage::Sphinx(deserialize_sphinx(payload)?)
        }
        MSG_GOSSIP => {
            WireMessage::Gossip(serde_json::from_slice(trim_padded(payload)).map_err(|_| WireError::InvalidMessageType(msg_type))?)
        }
        MSG_SWAP_PROPOSAL => {
            WireMessage::SwapProposal(serde_json::from_slice(trim_padded(payload)).map_err(|_| WireError::InvalidMessageType(msg_type))?)
        }
        MSG_SWAP_ACCEPT => {
            WireMessage::SwapAccept(serde_json::from_slice(trim_padded(payload)).map_err(|_| WireError::InvalidMessageType(msg_type))?)
        }
        MSG_SWAP_REJECT => {
            WireMessage::SwapReject(serde_json::from_slice(trim_padded(payload)).map_err(|_| WireError::InvalidMessageType(msg_type))?)
        }
        MSG_SWAP_COMMIT => {
            WireMessage::SwapCommit(serde_json::from_slice(trim_padded(payload)).map_err(|_| WireError::InvalidMessageType(msg_type))?)
        }
        MSG_SWAP_ABORT => {
            WireMessage::SwapAbort(serde_json::from_slice(trim_padded(payload)).map_err(|_| WireError::InvalidMessageType(msg_type))?)
        }
        MSG_PREPAYMENT => {
            WireMessage::Prepayment(serde_json::from_slice(trim_padded(payload)).map_err(|_| WireError::InvalidMessageType(msg_type))?)
        }
        MSG_ACCOUNTING_RECONCILIATION => {
            WireMessage::AccountingReconciliation(serde_json::from_slice(trim_padded(payload)).map_err(|_| WireError::InvalidMessageType(msg_type))?)
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
    fn test_swap_commit_serialization() {
        let commit = static_storage::swap::SwapCommit {
            proposal_id: [0x77u8; 32],
            from_node: [0x42u8; 16],
        };
        let msg = WireMessage::SwapCommit(commit.clone());
        let serialized = serialize_message(&msg).unwrap();
        assert_eq!(serialized[0], MSG_SWAP_COMMIT);
        // Padded to the uniform maintenance size like other swap messages.
        assert_eq!(serialized.len(), 1 + 4 + PADDED_MESSAGE_SIZE);
        let (deserialized, consumed) = deserialize_message(&serialized).unwrap();
        assert_eq!(consumed, serialized.len());
        match deserialized {
            WireMessage::SwapCommit(c) => {
                assert_eq!(c.proposal_id, commit.proposal_id);
                assert_eq!(c.from_node, commit.from_node);
            }
            _ => panic!("expected swap commit"),
        }
    }

    #[test]
    fn test_swap_abort_serialization() {
        let abort = static_storage::swap::SwapAbort {
            proposal_id: [0x88u8; 32],
            from_node: [0x43u8; 16],
            reason: "peer timed out".to_string(),
        };
        let msg = WireMessage::SwapAbort(abort.clone());
        let serialized = serialize_message(&msg).unwrap();
        assert_eq!(serialized[0], MSG_SWAP_ABORT);
        assert_eq!(serialized.len(), 1 + 4 + PADDED_MESSAGE_SIZE);
        let (deserialized, consumed) = deserialize_message(&serialized).unwrap();
        assert_eq!(consumed, serialized.len());
        match deserialized {
            WireMessage::SwapAbort(a) => {
                assert_eq!(a.proposal_id, abort.proposal_id);
                assert_eq!(a.from_node, abort.from_node);
                assert_eq!(a.reason, abort.reason);
            }
            _ => panic!("expected swap abort"),
        }
    }

    #[test]
    fn test_swap_proposal_fits_mtu() {
        // S0: swap messages are metadata-only (chunk payloads travel via
        // the Sphinx retrieval protocol), so a full proposal — lease,
        // Merkle proof, content signature — must fit the padded wire MTU.
        // Before the fix a 1 MiB chunk JSON-encoded inside the proposal
        // was ~4.2 MB and `serialize_message` rejected it.
        // Realistic worst case: a deep proof (20 siblings = 1 Mi-tree of
        // 1 KiB leaves) plus a signed content binding.
        let proof = static_storage::integrity::MerkleProof {
            leaf_index: 1_048_575,
            siblings: vec![[0xABu8; 32]; 20],
        };
        let content_sk = ed25519_dalek::SigningKey::from_bytes(&[0x5Au8; 32]);
        let content_pub = content_sk.verifying_key().to_bytes();
        let content_id = *blake3::hash(&content_pub).as_bytes();
        let proposal = static_storage::swap::create_swap_proposal(
            [0x42u8; 16],
            [0x77u8; 32],
            &static_crypto::SymmetricKey::random(),
            86400,
            [0x11u8; 32],
            proof,
            content_id,
            content_pub,
            Some(&content_sk),
        );
        let msg = WireMessage::SwapProposal(proposal.clone());
        let serialized = serialize_message(&msg).expect("metadata proposal must fit the MTU");
        assert_eq!(serialized[0], MSG_SWAP_PROPOSAL);
        assert_eq!(serialized.len(), 1 + 4 + PADDED_MESSAGE_SIZE);
        let (deserialized, consumed) = deserialize_message(&serialized).unwrap();
        assert_eq!(consumed, serialized.len());
        match deserialized {
            WireMessage::SwapProposal(p) => {
                assert_eq!(p.chunk_id, proposal.chunk_id);
                assert_eq!(p.content_signature, proposal.content_signature);
                assert_eq!(p.merkle_proof.siblings.len(), 20);
                assert_eq!(p.lease.expires_at, proposal.lease.expires_at);
            }
            _ => panic!("expected swap proposal"),
        }
        // Same for the metadata-only accept.
        let accept = static_storage::swap::create_swap_accept(
            [0x43u8; 16],
            [0x78u8; 32],
            &static_crypto::SymmetricKey::random(),
            [0x99u8; 32],
            86400,
        );
        let serialized = serialize_message(&WireMessage::SwapAccept(accept)).unwrap();
        assert_eq!(serialized[0], MSG_SWAP_ACCEPT);
        assert_eq!(serialized.len(), 1 + 4 + PADDED_MESSAGE_SIZE);
    }

    #[test]
    fn test_prepayment_serialization() {
        use ed25519_dalek::SigningKey;
        let sk_bytes = [0x77u8; 32];
        let sk = SigningKey::from_bytes(&sk_bytes);
        let pre = Prepayment::sign([0x42u8; 16], 1_048_576, [0xABu8; 32], &sk);
        assert!(pre.validate());
        let msg = WireMessage::Prepayment(pre.clone());
        let serialized = serialize_message(&msg).unwrap();
        assert_eq!(serialized[0], MSG_PREPAYMENT);
        let (deserialized, consumed) = deserialize_message(&serialized).unwrap();
        assert_eq!(consumed, serialized.len());
        match deserialized {
            WireMessage::Prepayment(p) => {
                assert_eq!(p.from_node, pre.from_node);
                assert_eq!(p.bytes, pre.bytes);
                assert_eq!(p.content_id, pre.content_id);
                assert_eq!(p.signature, pre.signature);
                assert!(p.validate());
            }
            _ => panic!("expected prepayment"),
        }
        // Invalid prepayments fail validation
        let bad = Prepayment {
            from_node: [0u8; 16],
            bytes: 0,
            content_id: [0u8; 32],
            identity_public_key: [0u8; 32],
            signature: vec![],
        };
        assert!(!bad.validate());
        // Forged signature fails.
        let mut forged = pre.clone();
        forged.bytes = 999_999_999;
        assert!(!forged.validate());
    }

    #[test]
    fn test_reconciliation_entry_serialization() {
        let entry = ReconciliationEntry {
            peer_id: [0x11u8; 16],
            bytes_served: 5000,
            bytes_received: 1000,
            net_credit: 4000,
            last_interaction: 1_700_000,
            prepaid_bytes: 777,
            successful_challenges: 9,
            failed_challenges: 1,
        };
        let json = serde_json::to_vec(&entry).unwrap();
        let back: ReconciliationEntry = serde_json::from_slice(&json).unwrap();
        assert_eq!(back.peer_id, entry.peer_id);
        assert_eq!(back.bytes_served, 5000);
        assert_eq!(back.net_credit, 4000);
        assert_eq!(back.prepaid_bytes, 777);
        assert_eq!(back.successful_challenges, 9);
    }

    #[test]
    fn test_accounting_reconciliation_serialization() {
        let entries = vec![
            ReconciliationEntry {
                peer_id: [0x01u8; 16],
                bytes_served: 100,
                bytes_received: 50,
                net_credit: 50,
                last_interaction: 1000,
                prepaid_bytes: 0,
                successful_challenges: 1,
                failed_challenges: 0,
            },
            ReconciliationEntry {
                peer_id: [0x02u8; 16],
                bytes_served: 200,
                bytes_received: 300,
                net_credit: -100,
                last_interaction: 2000,
                prepaid_bytes: 1234,
                successful_challenges: 0,
                failed_challenges: 2,
            },
        ];
        let mut recon = AccountingReconciliation {
            from_node: [0xAAu8; 16],
            peer_credits: entries,
            total_bytes_served: 10_000,
            total_bytes_received: 8_000,
            timestamp: 1_700_000,
            identity_public_key: [0u8; 32],
            signature: vec![],
        };
        {
            use ed25519_dalek::SigningKey;
            let sk = SigningKey::from_bytes(&[0x99u8; 32]);
            recon.sign(&sk);
        }
        assert!(recon.verify(1_700_100));
        // Future timestamp rejected.
        let mut future = recon.clone();
        future.timestamp = 1_700_100 + 10_000;
        assert!(!future.verify(1_700_100));
        let msg = WireMessage::AccountingReconciliation(recon.clone());
        let serialized = serialize_message(&msg).unwrap();
        assert_eq!(serialized[0], MSG_ACCOUNTING_RECONCILIATION);
        // Padded to uniform size.
        assert_eq!(serialized.len(), 1 + 4 + PADDED_MESSAGE_SIZE);
        let (deserialized, consumed) = deserialize_message(&serialized).unwrap();
        assert_eq!(consumed, serialized.len());
        match deserialized {
            WireMessage::AccountingReconciliation(r) => {
                assert_eq!(r.from_node, recon.from_node);
                assert_eq!(r.peer_credits.len(), 2);
                assert_eq!(r.peer_credits[1].prepaid_bytes, 1234);
                assert_eq!(r.peer_credits[1].net_credit, -100);
                assert_eq!(r.total_bytes_served, 10_000);
                assert_eq!(r.timestamp, 1_700_000);
            }
            _ => panic!("expected reconciliation"),
        }
        // Batching cap keeps messages small.
        assert!(MAX_RECONCILIATION_ENTRIES <= 50);
    }
}
