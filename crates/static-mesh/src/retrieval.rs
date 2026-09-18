//! Anonymous chunk retrieval protocol over Sphinx
//!
//! This module ties together SURBs, fragmentation, and the Sphinx
//! mixnet to provide anonymous chunk retrieval.
//!
//! Flow:
//! 1. Requester creates a return route and ChunkRequest
//! 2. Requester wraps in Sphinx, sends to holding node via forward route
//! 3. Holding node receives, finds chunk, fragments response
//! 4. Each fragment wrapped in Sphinx using return route, sent back
//! 5. Requester receives fragments, reassembles into ChunkResponse
//!
//! The holding node does not know who requested the chunk (the request
//! arrived through a Sphinx path). The requester does not know which
//! node served the chunk (the response arrives through a different
//! Sphinx path). Both paths go through mix nodes, providing anonymity
//! in both directions.

use crate::fragment::{
    fragment_payload, serialize_fragment, deserialize_fragment, Reassembler,
    MAX_FRAGMENTS_PER_MESSAGE,
};
use static_sphinx::{
    Route, SphinxPacket, process_packet, RoutingFlag,
    BODY_SIZE, MixNode,
};
use static_sphinx::{HybridRoute, HybridRouteHop, create_packet_hybrid};
use static_storage::ChunkId;
use static_storage::retrieval::{
    ChunkRequest, ChunkResponse, ReturnRoute,
    serialize_request, deserialize_request,
    serialize_response, deserialize_response,
};
use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

/// Maximum concurrent pending chunk retrievals.
///
/// Bounds `pending` memory; oldest retrieval is evicted on overflow.
pub const MAX_PENDING_RETRIEVALS: usize = 64;

/// Per-chunk retrieval timeout in seconds (10 minutes).
pub const RETRIEVAL_TIMEOUT_SECS: u64 = 600;

/// A pending chunk retrieval tracked by the requester
pub struct PendingRetrieval {
    /// The chunk ID being requested
    pub chunk_id: ChunkId,
    /// Reassembler for incoming response fragments
    pub reassembler: Reassembler,
    /// When this retrieval started (for expiry)
    pub created_at: Instant,
}

/// Manager for tracking pending retrievals at the requester
pub struct RetrievalManager {
    /// Pending retrievals (chunk_id -> PendingRetrieval)
    pending: HashMap<ChunkId, PendingRetrieval>,
    /// Insertion order for FIFO eviction (oldest front)
    order: VecDeque<ChunkId>,
}

impl RetrievalManager {
    /// Create a new retrieval manager
    pub fn new() -> Self {
        Self {
            pending: HashMap::new(),
            order: VecDeque::new(),
        }
    }

    /// Start a new retrieval
    ///
    /// Bounded: if [`MAX_PENDING_RETRIEVALS`] retrievals are already
    /// pending, the oldest is evicted first.
    pub fn start_retrieval(&mut self, chunk_id: ChunkId) {
        if self.pending.contains_key(&chunk_id) {
            // Refresh existing: move to back of eviction order.
            self.order.retain(|id| *id != chunk_id);
            self.order.push_back(chunk_id);
            if let Some(p) = self.pending.get_mut(&chunk_id) {
                // Keep existing reassembler progress but refresh timeout.
                p.created_at = Instant::now();
            }
            return;
        }
        if self.pending.len() >= MAX_PENDING_RETRIEVALS {
            if let Some(oldest) = self.order.pop_front() {
                self.pending.remove(&oldest);
            }
        }
        self.pending.insert(
            chunk_id,
            PendingRetrieval {
                chunk_id,
                reassembler: Reassembler::new(),
                created_at: Instant::now(),
            },
        );
        self.order.push_back(chunk_id);
    }

    /// Remove expired pending retrievals (older than `timeout_secs`).
    ///
    /// Returns the number removed.
    pub fn cleanup_expired_with_timeout(&mut self, timeout_secs: u64) -> usize {
        let now = Instant::now();
        let expired: Vec<ChunkId> = self
            .pending
            .iter()
            .filter(|(_, p)| {
                now.duration_since(p.created_at) >= Duration::from_secs(timeout_secs)
            })
            .map(|(id, _)| *id)
            .collect();
        let n = expired.len();
        for id in expired {
            self.pending.remove(&id);
            self.order.retain(|kept| *kept != id);
        }
        n
    }

    /// Remove pending retrievals older than [`RETRIEVAL_TIMEOUT_SECS`].
    ///
    /// Returns the number removed.
    pub fn cleanup_expired(&mut self) -> usize {
        self.cleanup_expired_with_timeout(RETRIEVAL_TIMEOUT_SECS)
    }

    /// Process an incoming response fragment
    ///
    /// Returns Some(ChunkResponse) if all fragments received and reassembled.
    pub fn process_fragment(
        &mut self,
        fragment_body: &[u8],
    ) -> Result<Option<ChunkResponse>, RetrievalError> {
        let fragment = deserialize_fragment(fragment_body)
            .map_err(|_| RetrievalError::InvalidFragment)?;

        // Validate attacker-controlled bounds before touching pendings.
        if fragment.total_fragments == 0
            || fragment.total_fragments > MAX_FRAGMENTS_PER_MESSAGE
            || fragment.fragment_id >= fragment.total_fragments
        {
            return Err(RetrievalError::InvalidFragment);
        }

        // Find the pending retrieval for this fragment.
        // Fragments carry no chunk hint, so scope by what we can: only
        // sessions whose expected total is unset or matches, and that
        // don't already hold this fragment id. Read-only scan first so
        // at most ONE clone/insert happens per call (bounded clones).
        let target: Option<ChunkId> = self
            .pending
            .iter()
            .find_map(|(id, p)| {
                if p.reassembler.can_accept(&fragment) {
                    Some(*id)
                } else {
                    None
                }
            });

        let target = target.ok_or(RetrievalError::NoMatchingRetrieval)?;
        // Single clone per call: `fragment` moved into exactly one session.
        let pending = self.pending.get_mut(&target).expect("just found");
        let was_new = pending.reassembler.add_fragment(fragment);
        if !was_new {
            return Err(RetrievalError::NoMatchingRetrieval);
        }
        if pending.reassembler.is_complete() {
            let data = pending.reassembler.reassemble()
                .map_err(|_| RetrievalError::ReassemblyFailed)?;
            let response = deserialize_response(&data)
                .map_err(|_| RetrievalError::InvalidResponse)?;
            let chunk_id = response.chunk_id;
            self.pending.remove(&chunk_id);
            self.order.retain(|kept| *kept != chunk_id);
            // Also drop the target slot if the response id differs
            // (mis-attributed fragment completing a wrong session).
            if chunk_id != target {
                self.pending.remove(&target);
                self.order.retain(|kept| *kept != target);
            }
            return Ok(Some(response));
        }
        Ok(None)
    }

    /// Check if a retrieval is in progress
    pub fn is_pending(&self, chunk_id: &ChunkId) -> bool {
        self.pending.contains_key(chunk_id)
    }

    /// Get the number of pending retrievals
    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }

    /// Get progress for a specific retrieval
    pub fn progress(&self, chunk_id: &ChunkId) -> Option<f64> {
        self.pending.get(chunk_id).map(|p| p.reassembler.progress())
    }
}

impl Default for RetrievalManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Create an anonymous chunk request with a hybrid forward packet
///
/// The requester creates a return route through the mixnet back to
/// themselves, wraps the ChunkRequest (including the return route) in a
/// hybrid Sphinx packet and sends it to the holding node via the forward
/// route. The forward route provides anonymity for the requester (the
/// holding node doesn't know who asked); the return route provides the
/// path for the response to come back.
///
/// The return route stays classical so the request fits in one body; the
/// forward and return packets are independent, so mixing versions is
/// safe. Falls back to an error when the forward peer's KEM key is
/// unknown — callers should only pass routes built from handshake-known
/// keys.
pub fn create_anonymous_request_hybrid(
    chunk_id: ChunkId,
    return_route: &Route,
    forward_route: &HybridRoute,
) -> Result<SphinxPacket, RetrievalError> {
    // Create the return route info
    let return_info = ReturnRoute::from_sphinx_route(return_route);

    // Create the chunk request
    let request = ChunkRequest {
        chunk_id,
        return_route: return_info,
    };

    // Serialize the request
    let request_bytes = serialize_request(&request);

    if request_bytes.len() > BODY_SIZE {
        return Err(RetrievalError::RequestTooLarge);
    }

    // Wrap in a hybrid Sphinx packet using the forward route
    let packet = create_packet_hybrid(forward_route, &request_bytes)
        .map_err(|_| RetrievalError::SphinxError)?;

    Ok(packet)
}

/// Handle a retrieval request at a holding node
///
/// The holding node:
/// 1. Receives the decrypted Sphinx body (which contains the ChunkRequest)
/// 2. Looks up the requested chunk
/// 3. If found, creates a ChunkResponse and fragments it
/// 4. For each fragment, creates a hybrid Sphinx packet using the return
///    route (Phase 0 hybrid-only mandate: `kem_lookup` must resolve every
///    hop, typically from the routing table learned via handshakes)
/// 5. Returns the packets to send back through the mixnet
///
/// The holding node uses the return route from the request to send
/// responses back. The return route goes through mix nodes, so the
/// holding node cannot directly identify the requester.
pub fn handle_retrieval_request(
    request_body: &[u8],
    chunk_data: Option<&[u8]>,
    kem_lookup: &dyn Fn(&[u8; 16]) -> Option<Vec<u8>>,
) -> Result<Vec<SphinxPacket>, RetrievalError> {
    // Deserialize the request
    let request = deserialize_request(request_body)
        .map_err(|_| RetrievalError::InvalidRequest)?;

    // Create the response
    let response = ChunkResponse {
        chunk_id: request.chunk_id,
        chunk_data: chunk_data.map(|d| d.to_vec()).unwrap_or_default(),
        found: chunk_data.is_some(),
    };

    // Serialize the response
    let response_bytes = serialize_response(&response);

    // Get the return route
    let return_route = request.return_route.to_sphinx_route();

    // Fragment the response
    let fragments = fragment_payload(&response_bytes);

    // Build the hybrid return route: every hop needs a KEM key
    // (hybrid-only mandate). Missing key = cannot respond anonymously.
    // The return route's hops already include the destination (requester)
    // as the final hop, matching `HybridRoute` semantics.
    let mut hops = Vec::with_capacity(return_route.hops.len());
    for hop in &return_route.hops {
        let kem = kem_lookup(&hop.node_id).ok_or(RetrievalError::SphinxError)?;
        hops.push(static_sphinx::HybridRouteHop {
            node_id: hop.node_id,
            classical_public_key: hop.public_key,
            kem_public_key: kem,
        });
    }
    if hops.last().map(|h| h.node_id) != Some(return_route.destination) {
        // Destination missing from hops: append it (requires its own key).
        let kem = kem_lookup(&return_route.destination).ok_or(RetrievalError::SphinxError)?;
        let classical = return_route
            .hops
            .last()
            .map(|h| h.public_key)
            .unwrap_or([0u8; 32]);
        hops.push(static_sphinx::HybridRouteHop {
            node_id: return_route.destination,
            classical_public_key: classical,
            kem_public_key: kem,
        });
    }
    let effective = HybridRoute {
        hops,
        destination: return_route.destination,
    };

    // Create a hybrid Sphinx packet for each fragment using the return route
    let mut packets = Vec::with_capacity(fragments.len());
    for fragment in &fragments {
        let fragment_body = serialize_fragment(fragment);
        let packet = create_packet_hybrid(&effective, &fragment_body)
            .map_err(|_| RetrievalError::SphinxError)?;
        packets.push(packet);
    }

    Ok(packets)
}

/// Process incoming Sphinx packets at the requester
///
/// The requester receives Sphinx packets (response fragments) and
/// processes them through their mix node. If the packet is destined
/// for this node (RoutingFlag::Destination), the body contains a
/// fragment that should be fed to the RetrievalManager.
///
/// Returns Some(ChunkResponse) if this fragment completes a retrieval.
pub fn process_response_packet(
    manager: &mut RetrievalManager,
    mix_node: &mut MixNode,
    packet: SphinxPacket,
) -> Result<Option<ChunkResponse>, RetrievalError> {
    let result = process_packet(mix_node, packet)
        .map_err(|_| RetrievalError::SphinxError)?;

    if result.flag == RoutingFlag::Destination {
        if let Some(body) = result.body {
            return manager.process_fragment(&body);
        }
    }

    Ok(None)
}

/// Fragment `payload` and wrap each fragment in a hybrid Sphinx packet
/// (Phase 1).
///
/// Generalizes the KEM-lookup return-route pattern of
/// [`handle_retrieval_request`]: every hop (and the destination, if not
/// already present as the last hop) needs a KEM key, typically resolved
/// from the handshake-learned routing table. Used by lifecycle traffic
/// (missing-chunk gossip responses, heartbeat propagation) that must
/// satisfy the hybrid-only mandate.
pub fn create_hybrid_payload_packets(
    payload: &[u8],
    route: &Route,
    kem_lookup: &dyn Fn(&[u8; 16]) -> Option<Vec<u8>>,
) -> Result<Vec<SphinxPacket>, RetrievalError> {
    let mut hops = Vec::with_capacity(route.hops.len());
    for hop in &route.hops {
        let kem = kem_lookup(&hop.node_id).ok_or(RetrievalError::SphinxError)?;
        hops.push(HybridRouteHop {
            node_id: hop.node_id,
            classical_public_key: hop.public_key,
            kem_public_key: kem,
        });
    }
    if hops.last().map(|h| h.node_id) != Some(route.destination) {
        let kem = kem_lookup(&route.destination).ok_or(RetrievalError::SphinxError)?;
        let classical = route
            .hops
            .last()
            .map(|h| h.public_key)
            .unwrap_or([0u8; 32]);
        hops.push(HybridRouteHop {
            node_id: route.destination,
            classical_public_key: classical,
            kem_public_key: kem,
        });
    }
    let effective = HybridRoute {
        hops,
        destination: route.destination,
    };

    let mut packets = Vec::new();
    for fragment in fragment_payload(payload) {
        let fragment_body = serialize_fragment(&fragment);
        let packet = create_packet_hybrid(&effective, &fragment_body)
            .map_err(|_| RetrievalError::SphinxError)?;
        packets.push(packet);
    }
    Ok(packets)
}

/// Errors that can occur during anonymous retrieval
#[derive(Debug, thiserror::Error)]
pub enum RetrievalError {
    /// Request too large for a single Sphinx body
    #[error("request too large for single Sphinx body")]
    RequestTooLarge,
    /// Sphinx packet creation/processing failed
    #[error("sphinx error")]
    SphinxError,
    /// Invalid request format
    #[error("invalid request format")]
    InvalidRequest,
    /// Invalid fragment format
    #[error("invalid fragment format")]
    InvalidFragment,
    /// Fragment reassembly failed
    #[error("reassembly failed")]
    ReassemblyFailed,
    /// Invalid response format
    #[error("invalid response format")]
    InvalidResponse,
    /// No matching pending retrieval for fragment
    #[error("no matching pending retrieval")]
    NoMatchingRetrieval,
}

#[cfg(test)]
mod tests {
    use super::*;
    use static_sphinx::{RouteHop, HybridMixNode, process_packet_hybrid, HybridRoute};
    use rand::RngCore;
    use std::collections::HashMap;

    /// A hybrid mix node plus its KEM lookup entry.
    fn hybrid_route(n: usize) -> (Vec<HybridMixNode>, HybridRoute, Route) {
        let mut nodes = Vec::with_capacity(n);
        let mut hops = Vec::with_capacity(n);
        let mut classical_hops = Vec::with_capacity(n);
        for _ in 0..n {
            let node = HybridMixNode::new();
            hops.push(node.as_hop());
            classical_hops.push(RouteHop {
                public_key: node.classical_public_key(),
                node_id: node.node_id(),
            });
            nodes.push(node);
        }
        let destination = nodes.last().unwrap().node_id();
        let hybrid = HybridRoute { hops, destination };
        let classical = Route { hops: classical_hops, destination };
        (nodes, hybrid, classical)
    }

    /// KEM lookup over a node set + requester (for handle_retrieval_request).
    fn kem_lookup_for(nodes: &[HybridMixNode], requester: &HybridMixNode) -> impl Fn(&[u8; 16]) -> Option<Vec<u8>> {
        let mut map: HashMap<[u8; 16], Vec<u8>> = HashMap::new();
        for n in nodes {
            map.insert(n.node_id(), n.kem_public_key_bytes());
        }
        map.insert(requester.node_id(), requester.kem_public_key_bytes());
        move |id| map.get(id).cloned()
    }

    fn random_chunk_id() -> ChunkId {
        let mut id = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut id);
        id
    }

    #[test]
    fn test_create_anonymous_request_hybrid() {
        let (_return_nodes, return_route, _rc) = hybrid_route(3);
        let (_forward_nodes, forward_route, _fc) = hybrid_route(3);
        let chunk_id = random_chunk_id();

        let packet = create_anonymous_request_hybrid(chunk_id, &return_route_route(&return_route), &forward_route).unwrap();

        assert_eq!(packet.body.len(), BODY_SIZE);
        assert_ne!(packet.header.ephemeral_key, [0u8; 32]);
        assert_eq!(packet.header.version, static_sphinx::SPHINX_VERSION_HYBRID);
    }

    /// Convert a HybridRoute to the classical Route shape used for
    /// ReturnRoute (public keys + ids only).
    fn return_route_route(h: &HybridRoute) -> Route {
        Route {
            hops: h.hops.iter().map(|hp| RouteHop {
                public_key: hp.classical_public_key,
                node_id: hp.node_id,
            }).collect(),
            destination: h.destination,
        }
    }

    #[test]
    fn test_create_hybrid_payload_packets_roundtrip() {
        // Single-hop route to a destination with a KEM key, like
        // lifecycle sends (gossip response / heartbeat propagation).
        let dest = HybridMixNode::new();
        let route = Route {
            hops: vec![RouteHop {
                public_key: dest.classical_public_key(),
                node_id: dest.node_id(),
            }],
            destination: dest.node_id(),
        };
        let mut kem_map: HashMap<[u8; 16], Vec<u8>> = HashMap::new();
        kem_map.insert(dest.node_id(), dest.kem_public_key_bytes());
        let kem_lookup = |id: &[u8; 16]| kem_map.get(id).cloned();

        let payload = b"lifecycle payload bytes".to_vec();
        let packets =
            create_hybrid_payload_packets(&payload, &route, &kem_lookup).unwrap();
        assert!(!packets.is_empty());

        // Every fragment must decrypt back at the destination and
        // reassemble into the original payload.
        let mut reassembler = Reassembler::new();
        let mut mix = dest;
        for packet in packets {
            assert_eq!(packet.header.version, static_sphinx::SPHINX_VERSION_HYBRID);
            let result = process_packet_hybrid(&mut mix, packet).unwrap();
            assert_eq!(result.flag, RoutingFlag::Destination);
            let fragment =
                deserialize_fragment(&result.body.expect("body")).unwrap();
            reassembler.add_fragment(fragment);
        }
        assert!(reassembler.is_complete());
        assert_eq!(reassembler.reassemble().unwrap(), payload);
    }

    #[test]
    fn test_create_hybrid_payload_packets_missing_kem_key() {
        let dest = HybridMixNode::new();
        let route = Route {
            hops: vec![RouteHop {
                public_key: dest.classical_public_key(),
                node_id: dest.node_id(),
            }],
            destination: dest.node_id(),
        };
        let kem_lookup = |_id: &[u8; 16]| -> Option<Vec<u8>> { None };
        let result = create_hybrid_payload_packets(b"x", &route, &kem_lookup);
        assert!(matches!(result, Err(RetrievalError::SphinxError)));
    }

    #[test]
    fn test_full_retrieval_roundtrip_small_chunk() {
        let (mut fwd_nodes, fwd_hybrid, _fc) = hybrid_route(3);
        let (mut ret_nodes, ret_hybrid, _rc) = hybrid_route(2);
        let mut requester_node = HybridMixNode::new();
        let mut holding_node = HybridMixNode::new();

        let chunk_data = b"this is a small chunk of data for testing";

        // Forward route: fwd nodes -> holding node (destination last).
        let mut forward_route = fwd_hybrid;
        forward_route.hops.push(holding_node.as_hop());
        forward_route.destination = holding_node.node_id();

        // Return route: ret nodes -> requester (destination last).
        let mut return_route = ret_hybrid;
        return_route.hops.push(requester_node.as_hop());
        return_route.destination = requester_node.node_id();

        let chunk_id = random_chunk_id();
        let request_packet =
            create_anonymous_request_hybrid(chunk_id, &return_route_route(&return_route), &forward_route).unwrap();

        let mut current_packet = request_packet;
        for node in fwd_nodes.iter_mut() {
            let result = process_packet_hybrid(node, current_packet).unwrap();
            assert_eq!(result.flag, RoutingFlag::Forward);
            current_packet = result.forward_packet.unwrap();
        }

        let result = process_packet_hybrid(&mut holding_node, current_packet).unwrap();
        assert_eq!(result.flag, RoutingFlag::Destination);
        let request_body = result.body.unwrap();

        let lookup = kem_lookup_for(&ret_nodes, &requester_node);
        let response_packets = handle_retrieval_request(&request_body, Some(chunk_data), &lookup).unwrap();
        assert!(!response_packets.is_empty());

        let mut manager = RetrievalManager::new();
        manager.start_retrieval(chunk_id);
        let mut final_response: Option<ChunkResponse> = None;

        for resp_packet in response_packets {
            let mut current = resp_packet;
            for node in ret_nodes.iter_mut() {
                let result = process_packet_hybrid(node, current).unwrap();
                assert_eq!(result.flag, RoutingFlag::Forward);
                current = result.forward_packet.unwrap();
            }
            let result = process_packet_hybrid(&mut requester_node, current).unwrap();
            assert_eq!(result.flag, RoutingFlag::Destination);
            if let Some(response) = manager.process_fragment(&result.body.unwrap()).unwrap() {
                final_response = Some(response);
            }
        }

        let response = final_response.expect("should have received response");
        assert!(response.found);
        assert_eq!(response.chunk_id, chunk_id);
        assert_eq!(&response.chunk_data, chunk_data);
    }

    #[test]
    fn test_handle_request_chunk_not_found() {
        let (ret_nodes, ret_hybrid, _rc) = hybrid_route(2);
        let requester = HybridMixNode::new();
        let mut return_route = ret_hybrid;
        return_route.hops.push(requester.as_hop());
        return_route.destination = requester.node_id();

        let chunk_id = random_chunk_id();
        let request = ChunkRequest {
            chunk_id,
            return_route: ReturnRoute::from_sphinx_route(&return_route_route(&return_route)),
        };
        let request_bytes = serialize_request(&request);

        let lookup = kem_lookup_for(&ret_nodes, &requester);
        let response_packets = handle_retrieval_request(&request_bytes, None, &lookup).unwrap();
        assert!(!response_packets.is_empty());
        // All packets are hybrid.
        assert!(response_packets.iter().all(|p| p.header.version == static_sphinx::SPHINX_VERSION_HYBRID));
    }

    #[test]
    fn test_handle_request_missing_kem_key_fails() {
        // Hybrid-only mandate: a hop without a KEM key cannot be routed.
        let request = ChunkRequest {
            chunk_id: random_chunk_id(),
            return_route: ReturnRoute {
                hops: vec![static_storage::retrieval::RouteHopInfo {
                    public_key: [0u8; 32],
                    node_id: [0x01u8; 16],
                }],
                destination: [0x01u8; 16],
            },
        };
        let request_bytes = serialize_request(&request);
        let lookup = |_id: &[u8; 16]| -> Option<Vec<u8>> { None };
        let result = handle_retrieval_request(&request_bytes, None, &lookup);
        assert!(result.is_err());
    }

    #[test]
    fn test_end_to_end_anonymous_retrieval() {
        let (mut fwd_nodes, _fh, _fc) = hybrid_route(2);
        let (mut ret_nodes, _rh, _rc2) = hybrid_route(2);
        let mut requester_node = HybridMixNode::new();
        let mut holding_node = HybridMixNode::new();

        let chunk_id = random_chunk_id();
        let chunk_data = b"end to end anonymous retrieval test data";

        let forward_route = HybridRoute {
            hops: vec![
                fwd_nodes[0].as_hop(),
                fwd_nodes[1].as_hop(),
                holding_node.as_hop(),
            ],
            destination: holding_node.node_id(),
        };
        let return_route = HybridRoute {
            hops: vec![
                ret_nodes[0].as_hop(),
                ret_nodes[1].as_hop(),
                requester_node.as_hop(),
            ],
            destination: requester_node.node_id(),
        };

        let request_packet = create_anonymous_request_hybrid(
            chunk_id,
            &return_route_route(&return_route),
            &forward_route,
        ).unwrap();

        let mut current = request_packet;
        for node in fwd_nodes.iter_mut() {
            let result = process_packet_hybrid(node, current).unwrap();
            assert_eq!(result.flag, RoutingFlag::Forward);
            current = result.forward_packet.unwrap();
        }

        let result = process_packet_hybrid(&mut holding_node, current).unwrap();
        assert_eq!(result.flag, RoutingFlag::Destination);
        let request_body = result.body.unwrap();

        let lookup = kem_lookup_for(&ret_nodes, &requester_node);
        let response_packets = handle_retrieval_request(&request_body, Some(chunk_data), &lookup).unwrap();
        assert!(!response_packets.is_empty());

        let mut manager = RetrievalManager::new();
        manager.start_retrieval(chunk_id);
        let mut final_response: Option<ChunkResponse> = None;

        for resp_packet in response_packets {
            let mut current = resp_packet;
            for node in ret_nodes.iter_mut() {
                let result = process_packet_hybrid(node, current).unwrap();
                assert_eq!(result.flag, RoutingFlag::Forward);
                current = result.forward_packet.unwrap();
            }
            let result = process_packet_hybrid(&mut requester_node, current).unwrap();
            assert_eq!(result.flag, RoutingFlag::Destination);
            if let Some(response) = manager.process_fragment(&result.body.unwrap()).unwrap() {
                final_response = Some(response);
            }
        }

        let response = final_response.expect("should have received response");
        assert!(response.found);
        assert_eq!(response.chunk_id, chunk_id);
        assert_eq!(&response.chunk_data, chunk_data);
    }

    #[test]
    fn test_end_to_end_chunk_not_found() {
        let (mut fwd_nodes, _fh, _fc) = hybrid_route(2);
        let (mut ret_nodes, _rh, _rc2) = hybrid_route(2);
        let mut requester_node = HybridMixNode::new();
        let mut holding_node = HybridMixNode::new();

        let chunk_id = random_chunk_id();

        let forward_route = HybridRoute {
            hops: vec![
                fwd_nodes[0].as_hop(),
                fwd_nodes[1].as_hop(),
                holding_node.as_hop(),
            ],
            destination: holding_node.node_id(),
        };
        let return_route = HybridRoute {
            hops: vec![
                ret_nodes[0].as_hop(),
                ret_nodes[1].as_hop(),
                requester_node.as_hop(),
            ],
            destination: requester_node.node_id(),
        };

        let request_packet = create_anonymous_request_hybrid(
            chunk_id,
            &return_route_route(&return_route),
            &forward_route,
        ).unwrap();

        let mut current = request_packet;
        for node in fwd_nodes.iter_mut() {
            let result = process_packet_hybrid(node, current).unwrap();
            current = result.forward_packet.unwrap();
        }

        let result = process_packet_hybrid(&mut holding_node, current).unwrap();
        let request_body = result.body.unwrap();

        let lookup = kem_lookup_for(&ret_nodes, &requester_node);
        let response_packets = handle_retrieval_request(&request_body, None, &lookup).unwrap();

        let mut manager = RetrievalManager::new();
        manager.start_retrieval(chunk_id);
        let mut final_response: Option<ChunkResponse> = None;

        for resp_packet in response_packets {
            let mut current = resp_packet;
            for node in ret_nodes.iter_mut() {
                let result = process_packet_hybrid(node, current).unwrap();
                current = result.forward_packet.unwrap();
            }
            let result = process_packet_hybrid(&mut requester_node, current).unwrap();
            let fragment_body = result.body.unwrap();
            if let Some(response) = manager.process_fragment(&fragment_body).unwrap() {
                final_response = Some(response);
            }
        }

        let response = final_response.expect("should have received response");
        assert!(!response.found);
        assert_eq!(response.chunk_id, chunk_id);
        assert!(response.chunk_data.is_empty());
    }

    #[test]
    fn test_large_chunk_retrieval() {
        let (mut fwd_nodes, _fh, _fc) = hybrid_route(3);
        let (mut ret_nodes, _rh, _rc2) = hybrid_route(3);
        let mut requester_node = HybridMixNode::new();
        let mut holding_node = HybridMixNode::new();

        let chunk_id = random_chunk_id();
        let chunk_data = vec![0xABu8; 50_000]; // 50 KB - multiple fragments

        let forward_route = HybridRoute {
            hops: vec![
                fwd_nodes[0].as_hop(),
                fwd_nodes[1].as_hop(),
                fwd_nodes[2].as_hop(),
                holding_node.as_hop(),
            ],
            destination: holding_node.node_id(),
        };
        let return_route = HybridRoute {
            hops: vec![
                ret_nodes[0].as_hop(),
                ret_nodes[1].as_hop(),
                ret_nodes[2].as_hop(),
                requester_node.as_hop(),
            ],
            destination: requester_node.node_id(),
        };

        let request_packet = create_anonymous_request_hybrid(
            chunk_id,
            &return_route_route(&return_route),
            &forward_route,
        ).unwrap();

        let mut current = request_packet;
        for node in fwd_nodes.iter_mut() {
            let result = process_packet_hybrid(node, current).unwrap();
            current = result.forward_packet.unwrap();
        }

        let result = process_packet_hybrid(&mut holding_node, current).unwrap();
        let request_body = result.body.unwrap();

        let lookup = kem_lookup_for(&ret_nodes, &requester_node);
        let response_packets = handle_retrieval_request(&request_body, Some(&chunk_data), &lookup).unwrap();
        assert!(response_packets.len() > 1);

        let mut manager = RetrievalManager::new();
        manager.start_retrieval(chunk_id);
        let mut final_response: Option<ChunkResponse> = None;

        for resp_packet in response_packets {
            let mut current = resp_packet;
            for node in ret_nodes.iter_mut() {
                let result = process_packet_hybrid(node, current).unwrap();
                current = result.forward_packet.unwrap();
            }
            let result = process_packet_hybrid(&mut requester_node, current).unwrap();
            let fragment_body = result.body.unwrap();
            if let Some(response) = manager.process_fragment(&fragment_body).unwrap() {
                final_response = Some(response);
            }
        }

        let response = final_response.expect("should have received response");
        assert!(response.found);
        assert_eq!(response.chunk_id, chunk_id);
        assert_eq!(response.chunk_data, chunk_data);
    }
}
