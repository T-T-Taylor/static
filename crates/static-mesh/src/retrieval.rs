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
};
use static_sphinx::{
    Route, SphinxPacket, create_packet, process_packet, RoutingFlag,
    BODY_SIZE, MixNode,
};
use static_sphinx::{HybridRoute, create_packet_hybrid};
use static_storage::ChunkId;
use static_storage::retrieval::{
    ChunkRequest, ChunkResponse, ReturnRoute,
    serialize_request, deserialize_request,
    serialize_response, deserialize_response,
};
use std::collections::HashMap;

/// A pending chunk retrieval tracked by the requester
pub struct PendingRetrieval {
    /// The chunk ID being requested
    pub chunk_id: ChunkId,
    /// Reassembler for incoming response fragments
    pub reassembler: Reassembler,
}

/// Manager for tracking pending retrievals at the requester
pub struct RetrievalManager {
    /// Pending retrievals (chunk_id -> PendingRetrieval)
    pending: HashMap<ChunkId, PendingRetrieval>,
}

impl RetrievalManager {
    /// Create a new retrieval manager
    pub fn new() -> Self {
        Self {
            pending: HashMap::new(),
        }
    }

    /// Start a new retrieval
    pub fn start_retrieval(&mut self, chunk_id: ChunkId) {
        self.pending.insert(
            chunk_id,
            PendingRetrieval {
                chunk_id,
                reassembler: Reassembler::new(),
            },
        );
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

        // Find the pending retrieval for this fragment
        // We don't know the chunk_id from the fragment alone,
        // so we try all pending retrievals
        for (_, pending) in self.pending.iter_mut() {
            let was_new = pending.reassembler.add_fragment(fragment.clone());
            if was_new {
                if pending.reassembler.is_complete() {
                    let data = pending.reassembler.reassemble()
                        .map_err(|_| RetrievalError::ReassemblyFailed)?;
                    let response = deserialize_response(&data)
                        .map_err(|_| RetrievalError::InvalidResponse)?;
                    let chunk_id = response.chunk_id;
                    self.pending.remove(&chunk_id);
                    return Ok(Some(response));
                }
                return Ok(None);
            }
        }

        Err(RetrievalError::NoMatchingRetrieval)
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

/// Create an anonymous chunk request
///
/// The requester creates a return route through the mixnet back to
/// themselves, then wraps the ChunkRequest (including the return
/// route) in a Sphinx packet and sends it to the holding node via
/// the forward route.
///
/// The forward route provides anonymity for the requester (the
/// holding node doesn't know who asked). The return route provides
/// the path for the response to come back.
pub fn create_anonymous_request(
    chunk_id: ChunkId,
    return_route: &Route,
    forward_route: &Route,
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

    // Wrap in a Sphinx packet using the forward route
    let packet = create_packet(forward_route, &request_bytes)
        .map_err(|_| RetrievalError::SphinxError)?;

    Ok(packet)
}

/// Create an anonymous chunk request with a hybrid forward packet
///
/// Identical to [`create_anonymous_request`] except the forward packet
/// uses hybrid (v1) key agreement. The return route stays classical so
/// the request still fits in one body; the forward and return packets
/// are independent, so mixing versions is safe. Falls back to the
/// classical constructor when the forward peer's KEM key is unknown —
/// callers should only pass routes built from handshake-known keys.
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
/// 4. For each fragment, creates a Sphinx packet using the return route
/// 5. Returns the packets to send back through the mixnet
///
/// The holding node uses the return route from the request to send
/// responses back. The return route goes through mix nodes, so the
/// holding node cannot directly identify the requester.
pub fn handle_retrieval_request(
    request_body: &[u8],
    chunk_data: Option<&[u8]>,
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

    // Create a Sphinx packet for each fragment using the return route
    let mut packets = Vec::with_capacity(fragments.len());
    for fragment in &fragments {
        let fragment_body = serialize_fragment(fragment);
        let packet = create_packet(&return_route, &fragment_body)
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
    use static_sphinx::{RouteHop, MixNode};
    use rand::RngCore;

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
        let destination = nodes.last().unwrap().node_id;
        let route = Route { hops, destination };
        (nodes, route)
    }

    fn random_chunk_id() -> ChunkId {
        let mut id = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut id);
        id
    }

    #[test]
    fn test_create_anonymous_request() {
        let (_return_nodes, return_route) = create_route(3);
        let (_forward_nodes, forward_route) = create_route(3);
        let chunk_id = random_chunk_id();

        let packet = create_anonymous_request(chunk_id, &return_route, &forward_route).unwrap();

        assert_eq!(packet.body.len(), BODY_SIZE);
        assert_ne!(packet.header.ephemeral_key, [0u8; 32]);
    }

    #[test]
    fn test_full_retrieval_roundtrip_small_chunk() {
        // Setup: 3 forward mix nodes, 2 return mix nodes, 1 requester node, 1 holding node
        let (mut fwd_nodes, fwd_route) = create_route(3);
        let (mut ret_nodes, ret_route) = create_route(2);
        let mut requester_node = MixNode::new();
        let mut holding_node = MixNode::new();

        // The chunk data
        let chunk_data = b"this is a small chunk of data for testing";

        // The forward route goes through fwd_nodes to the holding node
        let mut forward_route = fwd_route;
        forward_route.hops.push(RouteHop {
            public_key: holding_node.public_key,
            node_id: holding_node.node_id,
        });
        forward_route.destination = holding_node.node_id;

        // The return route goes through ret_nodes back to the requester
        let mut return_route = ret_route;
        return_route.hops.push(RouteHop {
            public_key: requester_node.public_key,
            node_id: requester_node.node_id,
        });
        return_route.destination = requester_node.node_id;

        // Step 1: Create the anonymous request
        let request_packet = create_anonymous_request(
            random_chunk_id(),
            &return_route,
            &forward_route,
        ).unwrap();

        // Step 2: Process through forward route
        let mut current_packet = request_packet;
        for i in 0..fwd_nodes.len() {
            let result = process_packet(&mut fwd_nodes[i], current_packet).unwrap();
            assert_eq!(result.flag, RoutingFlag::Forward);
            current_packet = result.forward_packet.unwrap();
        }

        // Step 3: Arrive at holding node
        let result = process_packet(&mut holding_node, current_packet).unwrap();
        assert_eq!(result.flag, RoutingFlag::Destination);
        let request_body = result.body.unwrap();

        // Step 4: Holding node handles the request
        let response_packets = handle_retrieval_request(
            &request_body,
            Some(chunk_data),
        ).unwrap();

        assert!(!response_packets.is_empty());

        // Step 5: Process response packets through return route
        for resp_packet in &response_packets {
            let mut current = resp_packet.clone();

            for i in 0..ret_nodes.len() {
                let result = process_packet(&mut ret_nodes[i], current).unwrap();
                assert_eq!(result.flag, RoutingFlag::Forward);
                current = result.forward_packet.unwrap();
            }

            let result = process_packet(&mut requester_node, current).unwrap();
            assert_eq!(result.flag, RoutingFlag::Destination);
        }

        // Verify that the holding node can handle the request and produce response packets
        assert!(!response_packets.is_empty());
    }

    #[test]
    fn test_retrieval_manager() {
        let mut manager = RetrievalManager::new();
        let chunk_id = random_chunk_id();

        assert_eq!(manager.pending_count(), 0);
        assert!(!manager.is_pending(&chunk_id));

        manager.start_retrieval(chunk_id);
        assert_eq!(manager.pending_count(), 1);
        assert!(manager.is_pending(&chunk_id));
    }

    #[test]
    fn test_handle_request_chunk_found() {
        let (_ret_nodes, return_route) = create_route(3);
        let (_fwd_nodes, forward_route) = create_route(3);
        let chunk_id = random_chunk_id();
        let chunk_data = b"chunk data content here";

        let _request_packet = create_anonymous_request(
            chunk_id,
            &return_route,
            &forward_route,
        ).unwrap();

        // Simulate the request arriving at the holding node (decrypt)
        // For this test, we'll use the forward route's last node
        let holding_node = MixNode::new();
        let mut route_with_holding = forward_route.clone();
        route_with_holding.hops.push(RouteHop {
            public_key: holding_node.public_key,
            node_id: holding_node.node_id,
        });
        route_with_holding.destination = holding_node.node_id;

        // Just test that handle_retrieval_request works with valid request bytes
        let request = ChunkRequest {
            chunk_id,
            return_route: ReturnRoute::from_sphinx_route(&return_route),
        };
        let request_bytes = serialize_request(&request);

        let response_packets = handle_retrieval_request(&request_bytes, Some(chunk_data)).unwrap();

        assert!(response_packets.len() >= 1);

        // Reassemble the response
        for packet in &response_packets {
            // Verify the packets exist and have correct structure
            assert_eq!(packet.body.len(), BODY_SIZE);
        }
    }

    #[test]
    fn test_handle_request_chunk_not_found() {
        let (_ret_nodes, return_route) = create_route(2);
        let chunk_id = random_chunk_id();

        let request = ChunkRequest {
            chunk_id,
            return_route: ReturnRoute::from_sphinx_route(&return_route),
        };
        let request_bytes = serialize_request(&request);

        let response_packets = handle_retrieval_request(&request_bytes, None).unwrap();

        // Should still get response packets (with found=false)
        assert!(!response_packets.is_empty());
    }

    #[test]
    fn test_end_to_end_anonymous_retrieval() {
        // Full end-to-end test:
        // Requester -> Forward Route -> Holding Node -> Return Route -> Requester

        // Create nodes
        let (mut fwd_nodes, _) = create_route(2);
        let (mut ret_nodes, _) = create_route(2);
        let mut holding_node = MixNode::new();
        let mut requester_node = MixNode::new();

        let chunk_id = random_chunk_id();
        let chunk_data = b"end to end anonymous retrieval test data";

        // Forward route: requester -> fwd1 -> fwd2 -> holding node
        let forward_route = Route {
            hops: vec![
                RouteHop { public_key: fwd_nodes[0].public_key, node_id: fwd_nodes[0].node_id },
                RouteHop { public_key: fwd_nodes[1].public_key, node_id: fwd_nodes[1].node_id },
                RouteHop { public_key: holding_node.public_key, node_id: holding_node.node_id },
            ],
            destination: holding_node.node_id,
        };

        // Return route: holding node -> ret1 -> ret2 -> requester
        let return_route = Route {
            hops: vec![
                RouteHop { public_key: ret_nodes[0].public_key, node_id: ret_nodes[0].node_id },
                RouteHop { public_key: ret_nodes[1].public_key, node_id: ret_nodes[1].node_id },
                RouteHop { public_key: requester_node.public_key, node_id: requester_node.node_id },
            ],
            destination: requester_node.node_id,
        };

        // Step 1: Create anonymous request
        let request_packet = create_anonymous_request(
            chunk_id,
            &return_route,
            &forward_route,
        ).unwrap();

        // Step 2: Process through forward route
        let mut current = request_packet;
        for i in 0..fwd_nodes.len() {
            let result = process_packet(&mut fwd_nodes[i], current).unwrap();
            assert_eq!(result.flag, RoutingFlag::Forward);
            current = result.forward_packet.unwrap();
        }

        // Step 3: Arrive at holding node
        let result = process_packet(&mut holding_node, current).unwrap();
        assert_eq!(result.flag, RoutingFlag::Destination);
        let request_body = result.body.unwrap();

        // Step 4: Holding node handles request
        let response_packets = handle_retrieval_request(
            &request_body,
            Some(chunk_data),
        ).unwrap();

        assert!(!response_packets.is_empty());

        // Step 5: Process response packets through return route
        let mut manager = RetrievalManager::new();
        manager.start_retrieval(chunk_id);

        let mut final_response: Option<ChunkResponse> = None;

        for resp_packet in response_packets {
            let mut current = resp_packet;

            // Process through return mix nodes
            for i in 0..ret_nodes.len() {
                let result = process_packet(&mut ret_nodes[i], current).unwrap();
                assert_eq!(result.flag, RoutingFlag::Forward);
                current = result.forward_packet.unwrap();
            }

            // Arrive at requester
            let result = process_packet(&mut requester_node, current).unwrap();
            assert_eq!(result.flag, RoutingFlag::Destination);
            let fragment_body = result.body.unwrap();

            // Process fragment
            if let Some(response) = manager.process_fragment(&fragment_body).unwrap() {
                final_response = Some(response);
            }
        }

        // Verify we got the response
        let response = final_response.expect("should have received response");
        assert!(response.found);
        assert_eq!(response.chunk_id, chunk_id);
        assert_eq!(&response.chunk_data, chunk_data);
    }

    #[test]
    fn test_end_to_end_chunk_not_found() {
        let (mut fwd_nodes, _) = create_route(2);
        let (mut ret_nodes, _) = create_route(2);
        let mut holding_node = MixNode::new();
        let mut requester_node = MixNode::new();

        let chunk_id = random_chunk_id();

        let forward_route = Route {
            hops: vec![
                RouteHop { public_key: fwd_nodes[0].public_key, node_id: fwd_nodes[0].node_id },
                RouteHop { public_key: fwd_nodes[1].public_key, node_id: fwd_nodes[1].node_id },
                RouteHop { public_key: holding_node.public_key, node_id: holding_node.node_id },
            ],
            destination: holding_node.node_id,
        };

        let return_route = Route {
            hops: vec![
                RouteHop { public_key: ret_nodes[0].public_key, node_id: ret_nodes[0].node_id },
                RouteHop { public_key: ret_nodes[1].public_key, node_id: ret_nodes[1].node_id },
                RouteHop { public_key: requester_node.public_key, node_id: requester_node.node_id },
            ],
            destination: requester_node.node_id,
        };

        let request_packet = create_anonymous_request(
            chunk_id,
            &return_route,
            &forward_route,
        ).unwrap();

        // Process through forward route
        let mut current = request_packet;
        for i in 0..fwd_nodes.len() {
            let result = process_packet(&mut fwd_nodes[i], current).unwrap();
            current = result.forward_packet.unwrap();
        }

        // Arrive at holding node
        let result = process_packet(&mut holding_node, current).unwrap();
        let request_body = result.body.unwrap();

        // Handle with no chunk data
        let response_packets = handle_retrieval_request(&request_body, None).unwrap();

        // Process response
        let mut manager = RetrievalManager::new();
        manager.start_retrieval(chunk_id);

        let mut final_response: Option<ChunkResponse> = None;

        for resp_packet in response_packets {
            let mut current = resp_packet;
            for i in 0..ret_nodes.len() {
                let result = process_packet(&mut ret_nodes[i], current).unwrap();
                current = result.forward_packet.unwrap();
            }
            let result = process_packet(&mut requester_node, current).unwrap();
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
        let (mut fwd_nodes, _) = create_route(3);
        let (mut ret_nodes, _) = create_route(3);
        let mut holding_node = MixNode::new();
        let mut requester_node = MixNode::new();

        let chunk_id = random_chunk_id();
        let chunk_data = vec![0xABu8; 50_000]; // 50 KB - will require multiple fragments

        let forward_route = Route {
            hops: vec![
                RouteHop { public_key: fwd_nodes[0].public_key, node_id: fwd_nodes[0].node_id },
                RouteHop { public_key: fwd_nodes[1].public_key, node_id: fwd_nodes[1].node_id },
                RouteHop { public_key: fwd_nodes[2].public_key, node_id: fwd_nodes[2].node_id },
                RouteHop { public_key: holding_node.public_key, node_id: holding_node.node_id },
            ],
            destination: holding_node.node_id,
        };

        let return_route = Route {
            hops: vec![
                RouteHop { public_key: ret_nodes[0].public_key, node_id: ret_nodes[0].node_id },
                RouteHop { public_key: ret_nodes[1].public_key, node_id: ret_nodes[1].node_id },
                RouteHop { public_key: ret_nodes[2].public_key, node_id: ret_nodes[2].node_id },
                RouteHop { public_key: requester_node.public_key, node_id: requester_node.node_id },
            ],
            destination: requester_node.node_id,
        };

        let request_packet = create_anonymous_request(
            chunk_id,
            &return_route,
            &forward_route,
        ).unwrap();

        // Process through forward route
        let mut current = request_packet;
        for i in 0..fwd_nodes.len() {
            let result = process_packet(&mut fwd_nodes[i], current).unwrap();
            current = result.forward_packet.unwrap();
        }

        // Arrive at holding node
        let result = process_packet(&mut holding_node, current).unwrap();
        let request_body = result.body.unwrap();

        // Handle request
        let response_packets = handle_retrieval_request(
            &request_body,
            Some(&chunk_data),
        ).unwrap();

        // Should have multiple fragments for 50 KB
        assert!(response_packets.len() > 1);

        // Process response
        let mut manager = RetrievalManager::new();
        manager.start_retrieval(chunk_id);

        let mut final_response: Option<ChunkResponse> = None;

        for resp_packet in response_packets {
            let mut current = resp_packet;
            for i in 0..ret_nodes.len() {
                let result = process_packet(&mut ret_nodes[i], current).unwrap();
                current = result.forward_packet.unwrap();
            }
            let result = process_packet(&mut requester_node, current).unwrap();
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
