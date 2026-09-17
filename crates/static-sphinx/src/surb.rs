//! Single-Use Reply Blocks (SURBs) for anonymous responses
//!
//! A SURB allows a node to receive a response without the responder
//! knowing who they are or where they are. The requester pre-builds
//! a Sphinx header for the return route and gives it to the responder
//! along with the body encryption keys. The responder encrypts their
//! payload with the keys and attaches the pre-built header. The mixnet
//! processes it normally, and the requester receives the decrypted
//! response.
//!
//! The responder cannot read the route (it's in the opaque header).
//! They only see the first hop's address. This preserves anonymity
//! in both directions: the requester doesn't know who served the chunk,
//! and the responder doesn't know who requested it.

use crate::{
    Route, SphinxHeader, SphinxPacket, SphinxError,
    NodeId, MAX_HOPS, NODE_ID_SIZE, FLAG_SIZE, MAC_SIZE, SLOT_SIZE, Mac,
    ROUTING_INFO_SIZE, BODY_SIZE,
    RoutingFlag,
    SymmetricKey, derive_hop_keys, compute_mac, xor_slot, xor_body,
    blinding_factor, random_bytes, random_scalar,
    BASE_POINT,
    SPHINX_VERSION_CLASSICAL, SPHINX_VERSION_HYBRID,
    HybridRoute, HybridMixNode, HybridProcessedPacket,
    process_packet_hybrid,
    KEM_CIPHERTEXT_SIZE,
};
use static_crypto::{KemKeypair, derive_hybrid_shared_secret};
use crate::HYBRID_HOP_CONTEXT;
use curve25519_dalek::montgomery::MontgomeryPoint;

/// A Single-Use Reply Block
///
/// Contains everything a responder needs to send a Sphinx packet
/// back to the requester without knowing the route:
/// - The pre-built Sphinx header (opaque to responder)
/// - The ML-KEM ciphertexts for hybrid headers (opaque, empty if classical)
/// - The body encryption keys for each hop
/// - The first hop's node ID (where to send the packet)
#[derive(Clone)]
pub struct Surb {
    /// The pre-built Sphinx header (opaque to responder)
    pub header: SphinxHeader,
    /// ML-KEM ciphertexts for hybrid headers (empty for classical SURBs)
    pub kem_ciphertexts: Vec<u8>,
    /// Body encryption keys for each hop (responder encrypts, mixnet peels)
    pub body_keys: Vec<SymmetricKey>,
    /// The first hop's node ID (where the responder sends the packet)
    pub first_hop: NodeId,
}

/// Keys retained by the SURB creator for verification
#[derive(Clone)]
pub struct SurbSecret {
    /// The fragment ID this SURB is associated with
    pub fragment_id: u32,
    /// The number of hops in the return route
    pub hop_count: usize,
}

/// Create a SURB for a return route
///
/// The requester calls this with a route back to themselves.
/// Returns (Surb, SurbSecret) — the Surb is sent to the responder,
/// the SurbSecret is kept locally for tracking.
pub fn create_surb(route: &Route) -> Result<(Surb, SurbSecret), SphinxError> {
    let n = route.hops.len();
    if n == 0 || n > MAX_HOPS {
        return Err(SphinxError::RouteTooLong);
    }

    // Generate ephemeral scalar and public key
    let ephemeral_scalar = random_scalar();
    let ephemeral_pub = (&BASE_POINT * &ephemeral_scalar).0;

    // Compute shared secrets with running scalar blinding
    let mut hop_keys = Vec::with_capacity(n);
    let mut alphas = Vec::with_capacity(n);
    let mut current_alpha = ephemeral_pub;
    let mut current_scalar = ephemeral_scalar.clone();

    for i in 0..n {
        let pub_point = MontgomeryPoint(route.hops[i].public_key);
        let shared_point = &pub_point * &current_scalar;
        let shared = SymmetricKey::from_bytes(shared_point.0);
        let keys = derive_hop_keys(&shared);
        hop_keys.push(keys);

        alphas.push(current_alpha);

        if i < n - 1 {
            let blind = blinding_factor(&shared);
            current_scalar = &current_scalar * &blind;
            let alpha_point = MontgomeryPoint(current_alpha);
            current_alpha = (&alpha_point * &blind).0;
        }
    }

    // Build routing blocks and compute MACs from last hop to first
    let mut blocks: Vec<[u8; SLOT_SIZE]> = vec![[0u8; SLOT_SIZE]; n];
    let mut enc_blocks: Vec<[u8; SLOT_SIZE]> = vec![[0u8; SLOT_SIZE]; n];
    let mut macs: Vec<Mac> = vec![[0u8; MAC_SIZE]; n];

    for i in (0..n).rev() {
        if i == n - 1 {
            // Last hop: destination is the requester
            blocks[i][..NODE_ID_SIZE].copy_from_slice(&route.destination);
            blocks[i][NODE_ID_SIZE] = RoutingFlag::Destination as u8;
        } else {
            blocks[i][..NODE_ID_SIZE].copy_from_slice(&route.hops[i + 1].node_id);
            blocks[i][NODE_ID_SIZE] = RoutingFlag::Forward as u8;
            blocks[i][NODE_ID_SIZE + FLAG_SIZE..].copy_from_slice(&macs[i + 1]);
        }

        enc_blocks[i] = blocks[i];
        xor_slot(&hop_keys[i].stream_key, &mut enc_blocks[i]);
        macs[i] = compute_mac(&hop_keys[i].mac_key, &alphas[i], &enc_blocks[i]);
    }

    // Build routing info with padding
    let mut routing_info = vec![0u8; ROUTING_INFO_SIZE];
    for i in 0..n {
        routing_info[i * SLOT_SIZE..(i + 1) * SLOT_SIZE].copy_from_slice(&enc_blocks[i]);
    }
    routing_info[n * SLOT_SIZE..].copy_from_slice(&random_bytes(ROUTING_INFO_SIZE - n * SLOT_SIZE));

    let header = SphinxHeader {
        version: SPHINX_VERSION_CLASSICAL,
        ephemeral_key: alphas[0],
        routing_info,
        mac: macs[0],
    };

    // Extract body keys for the responder
    let body_keys: Vec<SymmetricKey> = hop_keys.iter().map(|k| k.body_key.clone()).collect();

    // The first hop is the first node in the route
    let first_hop = route.hops[0].node_id;

    let surb = Surb {
        header,
        kem_ciphertexts: Vec::new(),
        body_keys,
        first_hop,
    };

    let secret = SurbSecret {
        fragment_id: 0, // Set by caller
        hop_count: n,
    };

    Ok((surb, secret))
}

/// Wrap a payload with a SURB to create a Sphinx packet
///
/// The responder calls this with the SURB and their payload.
/// The payload is encrypted in layers (last hop first, first hop last),
/// matching the order that mix nodes will peel (first hop first).
///
/// The resulting Sphinx packet is sent to the SURB's first hop.
pub fn wrap_with_surb(surb: &Surb, payload: &[u8]) -> Result<SphinxPacket, SphinxError> {
    if payload.len() > BODY_SIZE {
        return Err(SphinxError::BodyTooLarge);
    }

    // Pad payload to BODY_SIZE
    let mut body = vec![0u8; BODY_SIZE];
    body[..payload.len()].copy_from_slice(payload);

    // Encrypt body in layers (last hop first, first hop last)
    // This matches create_packet's behavior
    for i in (0..surb.body_keys.len()).rev() {
        xor_body(&surb.body_keys[i], &mut body);
    }

    Ok(SphinxPacket {
        header: surb.header.clone(),
        kem_ciphertexts: surb.kem_ciphertexts.clone(),
        body,
    })
}

/// Create a hybrid SURB for a return route
///
/// Mirrors [`create_surb`] but derives per-hop keys with the hybrid
/// X25519 + ML-KEM combination. The KEM ciphertexts ride opaquely in
/// the SURB and are copied into the wrapped packet.
pub fn create_surb_hybrid(route: &HybridRoute) -> Result<(Surb, SurbSecret), SphinxError> {
    use crate::KEM_PUBLIC_KEY_SIZE;

    let n = route.hops.len();
    if n == 0 || n > MAX_HOPS {
        return Err(SphinxError::RouteTooLong);
    }
    for hop in &route.hops {
        if hop.kem_public_key.len() != KEM_PUBLIC_KEY_SIZE {
            return Err(SphinxError::InvalidKemPublicKey);
        }
    }

    let ephemeral_scalar = random_scalar();
    let ephemeral_pub = (&BASE_POINT * &ephemeral_scalar).0;

    let mut hop_keys = Vec::with_capacity(n);
    let mut alphas = Vec::with_capacity(n);
    let mut kem_ciphertexts: Vec<u8> = Vec::with_capacity(n * KEM_CIPHERTEXT_SIZE);
    let mut current_alpha = ephemeral_pub;
    let mut current_scalar = ephemeral_scalar.clone();

    for i in 0..n {
        let pub_point = MontgomeryPoint(route.hops[i].classical_public_key);
        let shared_point = &pub_point * &current_scalar;
        let classical_shared = SymmetricKey::from_bytes(shared_point.0);

        let (kem_shared, ciphertext) =
            KemKeypair::encapsulate_to(&route.hops[i].kem_public_key)
                .map_err(|_| SphinxError::InvalidKemPublicKey)?;
        kem_ciphertexts.extend_from_slice(&ciphertext);

        let hybrid_shared =
            derive_hybrid_shared_secret(&classical_shared, &kem_shared, HYBRID_HOP_CONTEXT);
        let keys = derive_hop_keys(&hybrid_shared);
        hop_keys.push(keys);

        alphas.push(current_alpha);

        if i < n - 1 {
            let blind = blinding_factor(&hybrid_shared);
            current_scalar = &current_scalar * &blind;
            let alpha_point = MontgomeryPoint(current_alpha);
            current_alpha = (&alpha_point * &blind).0;
        }
    }

    let mut blocks: Vec<[u8; SLOT_SIZE]> = vec![[0u8; SLOT_SIZE]; n];
    let mut enc_blocks: Vec<[u8; SLOT_SIZE]> = vec![[0u8; SLOT_SIZE]; n];
    let mut macs: Vec<Mac> = vec![[0u8; MAC_SIZE]; n];

    for i in (0..n).rev() {
        if i == n - 1 {
            blocks[i][..NODE_ID_SIZE].copy_from_slice(&route.destination);
            blocks[i][NODE_ID_SIZE] = RoutingFlag::Destination as u8;
        } else {
            blocks[i][..NODE_ID_SIZE].copy_from_slice(&route.hops[i + 1].node_id);
            blocks[i][NODE_ID_SIZE] = RoutingFlag::Forward as u8;
            blocks[i][NODE_ID_SIZE + FLAG_SIZE..].copy_from_slice(&macs[i + 1]);
        }

        enc_blocks[i] = blocks[i];
        xor_slot(&hop_keys[i].stream_key, &mut enc_blocks[i]);
        macs[i] = compute_mac(&hop_keys[i].mac_key, &alphas[i], &enc_blocks[i]);
    }

    let mut routing_info = vec![0u8; ROUTING_INFO_SIZE];
    for i in 0..n {
        routing_info[i * SLOT_SIZE..(i + 1) * SLOT_SIZE].copy_from_slice(&enc_blocks[i]);
    }
    routing_info[n * SLOT_SIZE..].copy_from_slice(&random_bytes(ROUTING_INFO_SIZE - n * SLOT_SIZE));

    let header = SphinxHeader {
        version: SPHINX_VERSION_HYBRID,
        ephemeral_key: alphas[0],
        routing_info,
        mac: macs[0],
    };

    let body_keys: Vec<SymmetricKey> = hop_keys.iter().map(|k| k.body_key.clone()).collect();
    let first_hop = route.hops[0].node_id;

    let surb = Surb {
        header,
        kem_ciphertexts,
        body_keys,
        first_hop,
    };

    let secret = SurbSecret {
        fragment_id: 0, // Set by caller
        hop_count: n,
    };

    Ok((surb, secret))
}

/// Wrap a payload with a hybrid SURB to create a hybrid Sphinx packet
///
/// Requires a SURB built by [`create_surb_hybrid`]; rejects classical
/// SURBs with [`SphinxError::UnsupportedVersion`].
pub fn wrap_with_surb_hybrid(surb: &Surb, payload: &[u8]) -> Result<SphinxPacket, SphinxError> {
    if surb.header.version != SPHINX_VERSION_HYBRID {
        return Err(SphinxError::UnsupportedVersion(surb.header.version));
    }
    if payload.len() > BODY_SIZE {
        return Err(SphinxError::BodyTooLarge);
    }

    let mut body = vec![0u8; BODY_SIZE];
    body[..payload.len()].copy_from_slice(payload);

    for i in (0..surb.body_keys.len()).rev() {
        xor_body(&surb.body_keys[i], &mut body);
    }

    Ok(SphinxPacket {
        header: surb.header.clone(),
        kem_ciphertexts: surb.kem_ciphertexts.clone(),
        body,
    })
}

/// Process a hybrid SURB-wrapped packet at a mix node
///
/// Convenience re-export of [`process_packet_hybrid`] for the SURB path.
pub fn process_surb_hybrid(
    node: &mut HybridMixNode,
    packet: SphinxPacket,
) -> Result<HybridProcessedPacket, SphinxError> {
    process_packet_hybrid(node, packet)
}

/// Create multiple SURBs at once (for fragmented responses)
///
/// Each SURB gets a unique fragment ID. The requester creates N SURBs,
/// sends them to the responder, and the responder uses each one for
/// one fragment of the response.
pub fn create_surb_batch(route: &Route, count: usize) -> Result<Vec<(Surb, SurbSecret)>, SphinxError> {
    let mut surbs = Vec::with_capacity(count);
    for i in 0..count {
        let (surb, mut secret) = create_surb(route)?;
        secret.fragment_id = i as u32;
        surbs.push((surb, secret));
    }
    Ok(surbs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{create_packet, process_packet, MixNode, RouteHop, random_node_id};

    fn create_route(n: usize) -> (Vec<MixNode>, Route) {
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
    fn test_surb_creation() {
        let (nodes, route) = create_route(3);
        let (surb, secret) = create_surb(&route).unwrap();

        assert_eq!(surb.body_keys.len(), 3);
        assert_eq!(surb.first_hop, nodes[0].node_id);
        assert_eq!(secret.hop_count, 3);
    }

    #[test]
    fn test_surb_wrap_and_process() {
        let (mut nodes, route) = create_route(3);
        let (surb, _secret) = create_surb(&route).unwrap();

        let payload = b"hello back via surb";
        let packet = wrap_with_surb(&surb, payload).unwrap();

        // Process through the mixnet
        let result0 = process_packet(&mut nodes[0], packet).unwrap();
        assert_eq!(result0.flag, RoutingFlag::Forward);

        let result1 = process_packet(&mut nodes[1], result0.forward_packet.unwrap()).unwrap();
        assert_eq!(result1.flag, RoutingFlag::Forward);

        let result2 = process_packet(&mut nodes[2], result1.forward_packet.unwrap()).unwrap();
        assert_eq!(result2.flag, RoutingFlag::Destination);

        let body = result2.body.unwrap();
        assert_eq!(&body[..payload.len()], payload);
    }

    #[test]
    fn test_surb_batch() {
        let (_nodes, route) = create_route(2);
        let surbs = create_surb_batch(&route, 5).unwrap();

        assert_eq!(surbs.len(), 5);
        for (i, (_, secret)) in surbs.iter().enumerate() {
            assert_eq!(secret.fragment_id, i as u32);
        }
    }

    #[test]
    fn test_surb_payload_too_large() {
        let (_nodes, route) = create_route(2);
        let (surb, _) = create_surb(&route).unwrap();

        let payload = vec![0u8; BODY_SIZE + 1];
        let result = wrap_with_surb(&surb, &payload);
        assert!(matches!(result, Err(SphinxError::BodyTooLarge)));
    }

    #[test]
    fn test_surb_empty_payload() {
        let (mut nodes, route) = create_route(1);
        let (surb, _) = create_surb(&route).unwrap();

        let payload: Vec<u8> = vec![];
        let packet = wrap_with_surb(&surb, &payload).unwrap();

        let result = process_packet(&mut nodes[0], packet).unwrap();
        let body = result.body.unwrap();
        assert_eq!(body, vec![0u8; BODY_SIZE]);
    }
    #[test]
    fn test_surb_indistinguishable_from_normal_packet() {
        let (_nodes, route) = create_route(3);
        let (surb, _) = create_surb(&route).unwrap();

        let surb_packet = wrap_with_surb(&surb, b"surb payload").unwrap();
        let normal_packet = create_packet(&route, b"normal payload").unwrap();

        // Both should be the same size
        assert_eq!(surb_packet.body.len(), normal_packet.body.len());
        assert_eq!(surb_packet.header.routing_info.len(), normal_packet.header.routing_info.len());
        assert_eq!(surb_packet.header.ephemeral_key.len(), normal_packet.header.ephemeral_key.len());
    }

    fn create_hybrid_route(n: usize) -> (Vec<HybridMixNode>, HybridRoute) {
        let mut nodes = Vec::with_capacity(n);
        let mut hops = Vec::with_capacity(n);
        for _ in 0..n {
            let node = HybridMixNode::new();
            hops.push(node.as_hop());
            nodes.push(node);
        }
        let destination = random_node_id();
        let route = HybridRoute { hops, destination };
        (nodes, route)
    }

    #[test]
    fn test_hybrid_surb_creation() {
        let (nodes, route) = create_hybrid_route(3);
        let (surb, secret) = create_surb_hybrid(&route).unwrap();

        assert_eq!(surb.header.version, SPHINX_VERSION_HYBRID);
        assert_eq!(surb.body_keys.len(), 3);
        assert_eq!(surb.first_hop, nodes[0].node_id());
        assert_eq!(surb.kem_ciphertexts.len(), 3 * KEM_CIPHERTEXT_SIZE);
        assert_eq!(secret.hop_count, 3);
    }

    #[test]
    fn test_hybrid_surb_wrap_and_process() {
        let (mut nodes, route) = create_hybrid_route(3);
        let (surb, _) = create_surb_hybrid(&route).unwrap();

        let payload = b"hybrid hello back via surb";
        let packet = wrap_with_surb_hybrid(&surb, payload).unwrap();
        assert_eq!(packet.header.version, SPHINX_VERSION_HYBRID);

        let result0 = process_surb_hybrid(&mut nodes[0], packet).unwrap();
        assert_eq!(result0.flag, RoutingFlag::Forward);

        let result1 =
            process_surb_hybrid(&mut nodes[1], result0.forward_packet.unwrap()).unwrap();
        assert_eq!(result1.flag, RoutingFlag::Forward);

        let result2 =
            process_surb_hybrid(&mut nodes[2], result1.forward_packet.unwrap()).unwrap();
        assert_eq!(result2.flag, RoutingFlag::Destination);

        let body = result2.body.unwrap();
        assert_eq!(&body[..payload.len()], payload);
    }
}
