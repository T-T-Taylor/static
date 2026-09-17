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
use static_sphinx::{
    SphinxPacket, SphinxHeader, NodeId,
    BODY_SIZE, ROUTING_INFO_SIZE, EPHEMERAL_KEY_SIZE, MAC_SIZE,
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

/// Maximum peer credit entries per reconciliation message (batching cap)
///
/// Keeps serialized reconciliation messages under `MAX_MESSAGE_SIZE`.
/// Nodes with more peers send multiple messages; `reconcile()` is
/// idempotent so batches converge to the same result.
pub const MAX_RECONCILIATION_ENTRIES: usize = 50;

/// Maximum message size (header + body + framing overhead)
pub const MAX_MESSAGE_SIZE: usize = 1 + 4 + EPHEMERAL_KEY_SIZE + ROUTING_INFO_SIZE + MAC_SIZE + BODY_SIZE;

/// A handshake message exchanged when peers connect
#[derive(Debug, Clone)]
pub struct Handshake {
    /// The sending node's ID
    pub node_id: NodeId,
    /// The sending node's public key (Montgomery point bytes)
    pub public_key: [u8; 32],
    /// The sending node's bandwidth tier
    pub tier: crate::BandwidthTier,
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
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Prepayment {
    /// The sending node's ID
    pub from_node: NodeId,
    /// Amount of bytes being prepaid
    pub bytes: u64,
    /// Content ID this prepayment is for
    pub content_id: [u8; 32],
    /// Signature proving the seed-only node authorized this payment
    pub signature: Vec<u8>,
}

impl Prepayment {
    /// Validate the prepayment fields (stub signature check)
    ///
    /// Currently checks non-zero bytes and non-empty signature.
    /// TODO: Add ed25519-dalek for real signature verification
    /// (deferred until post-quantum signature pass, TODO item 7).
    pub fn validate(&self) -> bool {
        // TODO: Add ed25519-dalek for real signature verification
        self.bytes > 0 && !self.signature.is_empty()
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
fn serialize_handshake(handshake: &Handshake) -> Vec<u8> {
    let mut buf = Vec::with_capacity(16 + 32 + 1);
    buf.extend_from_slice(&handshake.node_id);
    buf.extend_from_slice(&handshake.public_key);
    buf.push(handshake.tier as u8);
    buf
}

/// Deserialize a handshake message from a bytes buffer
fn deserialize_handshake(data: &[u8]) -> Result<Handshake, WireError> {
    if data.len() < 16 + 32 + 1 {
        return Err(WireError::BufferTooShort {
            needed: 49,
            have: data.len(),
        });
    }

    let mut node_id = [0u8; 16];
    node_id.copy_from_slice(&data[..16]);

    let mut public_key = [0u8; 32];
    public_key.copy_from_slice(&data[16..48]);

    let tier = match data[48] {
        0 => crate::BandwidthTier::Low,
        1 => crate::BandwidthTier::Standard,
        2 => crate::BandwidthTier::High,
        _ => return Err(WireError::InvalidMessageType(data[48])), // Reusing error type for simplicity
    };

    Ok(Handshake { node_id, public_key, tier })
}

/// Serialize a Sphinx packet into a bytes buffer
fn serialize_sphinx(packet: &SphinxPacket) -> Vec<u8> {
    let mut buf = Vec::with_capacity(
        EPHEMERAL_KEY_SIZE + ROUTING_INFO_SIZE + MAC_SIZE + BODY_SIZE
    );

    // Ephemeral key (32 bytes)
    buf.extend_from_slice(&packet.header.ephemeral_key);

    // Routing info (fixed size)
    buf.extend_from_slice(&packet.header.routing_info);

    // MAC (16 bytes)
    buf.extend_from_slice(&packet.header.mac);

    // Body (fixed size)
    buf.extend_from_slice(&packet.body);

    buf
}

/// Deserialize a Sphinx packet from a bytes buffer
fn deserialize_sphinx(data: &[u8]) -> Result<SphinxPacket, WireError> {
    let expected_len = EPHEMERAL_KEY_SIZE + ROUTING_INFO_SIZE + MAC_SIZE + BODY_SIZE;
    if data.len() < expected_len {
        return Err(WireError::BufferTooShort {
            needed: expected_len,
            have: data.len(),
        });
    }

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
        ephemeral_key,
        routing_info,
        mac,
    };

    Ok(SphinxPacket { header, body })
}

/// Serialize a wire message into a framed byte buffer
///
/// Format: [1 byte type] [4 bytes payload length] [N bytes payload]
pub fn serialize_message(msg: &WireMessage) -> Result<Vec<u8>, WireError> {
    let (msg_type, payload) = match msg {
        WireMessage::Handshake(hs) => (MSG_HANDSHAKE, serialize_handshake(hs)),
        WireMessage::Sphinx(pkt) => (MSG_SPHINX, serialize_sphinx(pkt)),
        WireMessage::Gossip(g) => (MSG_GOSSIP, serde_json::to_vec(g).map_err(|_| WireError::InvalidMessageType(0))?),
        WireMessage::SwapProposal(s) => (MSG_SWAP_PROPOSAL, serde_json::to_vec(s).map_err(|_| WireError::InvalidMessageType(0))?),
        WireMessage::SwapAccept(s) => (MSG_SWAP_ACCEPT, serde_json::to_vec(s).map_err(|_| WireError::InvalidMessageType(0))?),
        WireMessage::SwapReject(s) => (MSG_SWAP_REJECT, serde_json::to_vec(s).map_err(|_| WireError::InvalidMessageType(0))?),
        WireMessage::Prepayment(p) => (MSG_PREPAYMENT, serde_json::to_vec(p).map_err(|_| WireError::InvalidMessageType(0))?),
        WireMessage::AccountingReconciliation(r) => (MSG_ACCOUNTING_RECONCILIATION, serde_json::to_vec(r).map_err(|_| WireError::InvalidMessageType(0))?),
    };

    let total_len = 1 + 4 + payload.len();
    if total_len > MAX_MESSAGE_SIZE {
        return Err(WireError::MessageTooLarge {
            size: total_len,
            max: MAX_MESSAGE_SIZE,
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
        MSG_SPHINX => {
            WireMessage::Sphinx(deserialize_sphinx(payload)?)
        }
        MSG_GOSSIP => {
            WireMessage::Gossip(serde_json::from_slice(payload).map_err(|_| WireError::InvalidMessageType(msg_type))?)
        }
        MSG_SWAP_PROPOSAL => {
            WireMessage::SwapProposal(serde_json::from_slice(payload).map_err(|_| WireError::InvalidMessageType(msg_type))?)
        }
        MSG_SWAP_ACCEPT => {
            WireMessage::SwapAccept(serde_json::from_slice(payload).map_err(|_| WireError::InvalidMessageType(msg_type))?)
        }
        MSG_SWAP_REJECT => {
            WireMessage::SwapReject(serde_json::from_slice(payload).map_err(|_| WireError::InvalidMessageType(msg_type))?)
        }
        MSG_PREPAYMENT => {
            WireMessage::Prepayment(serde_json::from_slice(payload).map_err(|_| WireError::InvalidMessageType(msg_type))?)
        }
        MSG_ACCOUNTING_RECONCILIATION => {
            WireMessage::AccountingReconciliation(serde_json::from_slice(payload).map_err(|_| WireError::InvalidMessageType(msg_type))?)
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
pub fn try_read_message(buf: &mut BytesMut) -> Result<Option<WireMessage>, WireError> {
    if buf.len() < 5 {
        return Ok(None);
    }

    // Peek at the length without consuming
    let payload_len = u32::from_be_bytes([
        buf[1], buf[2], buf[3], buf[4],
    ]) as usize;

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

    #[test]
    fn test_handshake_serialization() {
        let hs = Handshake {
            node_id: [0x42u8; 16],
            public_key: [0xABu8; 32],
            tier: crate::BandwidthTier::Standard,
        };

        let serialized = serialize_handshake(&hs);
        assert_eq!(serialized.len(), 49);

        let deserialized = deserialize_handshake(&serialized).unwrap();
        assert_eq!(deserialized.node_id, hs.node_id);
        assert_eq!(deserialized.public_key, hs.public_key);
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
        let hs = Handshake {
            node_id: [0x42u8; 16],
            public_key: [0xABu8; 32],
            tier: crate::BandwidthTier::Standard,
        };
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
        let hs = Handshake {
            node_id: [0x42u8; 16],
            public_key: [0xABu8; 32],
            tier: crate::BandwidthTier::Standard,
        };
        let msg = WireMessage::Handshake(hs);
        let serialized = serialize_message(&msg).unwrap();

        // Only first 3 bytes available
        let mut buf = BytesMut::from(&serialized[..3]);
        let result = try_read_message(&mut buf);
        assert!(matches!(result, Ok(None)));
    }

    #[test]
    fn test_try_read_message_complete() {
        let hs = Handshake {
            node_id: [0x42u8; 16],
            public_key: [0xABu8; 32],
            tier: crate::BandwidthTier::Standard,
        };
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
        let hs1 = Handshake {
            node_id: [0x01u8; 16],
            public_key: [0x01u8; 32],
            tier: crate::BandwidthTier::Standard,
        };
        let hs2 = Handshake {
            node_id: [0x02u8; 16],
            public_key: [0x02u8; 32],
            tier: crate::BandwidthTier::Standard,
        };

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
    fn test_prepayment_serialization() {
        let pre = Prepayment {
            from_node: [0x42u8; 16],
            bytes: 1_048_576,
            content_id: [0xABu8; 32],
            // TODO: Add ed25519-dalek for real signature verification
            signature: vec![0x01u8; 64],
        };
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
            signature: vec![],
        };
        assert!(!bad.validate());
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
        let recon = AccountingReconciliation {
            from_node: [0xAAu8; 16],
            peer_credits: entries,
            total_bytes_served: 10_000,
            total_bytes_received: 8_000,
            timestamp: 1_700_000,
        };
        let msg = WireMessage::AccountingReconciliation(recon.clone());
        let serialized = serialize_message(&msg).unwrap();
        assert_eq!(serialized[0], MSG_ACCOUNTING_RECONCILIATION);
        assert!(serialized.len() <= MAX_MESSAGE_SIZE);
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
