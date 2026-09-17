//! Compute request/response protocol over Sphinx
//!
//! Mirrors the chunk retrieval protocol (`crate::retrieval`): messages are
//! Sphinx packet bodies, never direct wire traffic. Requests and responses
//! are fragmented across multiple Sphinx bodies by the caller (see
//! `static_mesh::fragment`) and reassembled at the destination.
//!
//! Wire format (all integers big-endian):
//!
//! ```text
//! ComputeRequest:  [0x03][from_node 16][module_content_id 32]
//!                  [module_content_pub_key 32][fee_offer 8]
//!                  [request_id 32][return_route][input_len 4][input..]
//!
//! ComputeResponse: [0x04][request_id 32][success 1][error_len 4][error..]
//!                  [cpu_time_ms 8][memory_used 8][fee_charged 8]
//!                  [output_len 4][output..]
//!
//! return_route:    [hop_count 4][{public_key 32, node_id 16}..][destination 16]
//! ```
//!
//! Both message types are indistinguishable from cover traffic on the wire.
//! The provider does not learn who requested computation beyond the mixnet's
//! guarantees; `from_node` exists only for accounting bookkeeping and cannot
//! be verified through the mixnet.

use crate::{ContentId, StorageError};
use static_sphinx::NodeId;

/// Compute request message type
pub const MSG_COMPUTE_REQUEST: u8 = 0x03;

/// Compute response message type
pub const MSG_COMPUTE_RESPONSE: u8 = 0x04;

/// Maximum compute input size per request (bytes)
pub const MAX_COMPUTE_INPUT_SIZE: usize = 32 * 1024;

/// Maximum compute output size per response (bytes)
pub const MAX_COMPUTE_OUTPUT_SIZE: usize = 32 * 1024;

/// A request to execute a WASM module on a remote compute provider
///
/// Sent as a fragmented Sphinx body. The provider fetches the module
/// (identified by its content public key) from the network if it is not
/// cached, executes it with `input_data`, and returns a [`ComputeResponse`]
/// over the [`ReturnRoute`].
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct ComputeRequest {
    /// The requesting node's ID (accounting bookkeeping only; unverifiable
    /// through the mixnet)
    pub from_node: NodeId,
    /// Content ID of the WASM module to execute
    pub module_content_id: ContentId,
    /// Content public key for fetching and decrypting the module
    pub module_content_pub_key: [u8; 32],
    /// Fee offered in storage-credit bytes
    pub fee_offer: u64,
    /// Request ID for matching responses to requests
    pub request_id: [u8; 32],
    /// Return route for the response (Sphinx reply route back to requester)
    pub return_route: ReturnRoute,
    /// Input data passed to the module's `process` function
    pub input_data: Vec<u8>,
}

/// A response from a compute execution
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct ComputeResponse {
    /// The request ID this responds to
    pub request_id: [u8; 32],
    /// Output data produced by the module
    pub output_data: Vec<u8>,
    /// Whether execution succeeded
    pub success: bool,
    /// Error message if execution failed
    pub error: Option<String>,
    /// CPU time used in milliseconds (wall-clock estimate)
    pub cpu_time_ms: u64,
    /// Peak WASM memory used in bytes
    pub memory_used: u64,
    /// Fee charged (may be less than or equal to the offered fee)
    pub fee_charged: u64,
}

/// A return route for anonymous compute responses
///
/// Same shape as `crate::retrieval::ReturnRoute`; re-declared here so the
/// compute protocol has no dependency on the retrieval module.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct ReturnRoute {
    /// The route hops (in order from requester to first mix)
    pub hops: Vec<RouteHopInfo>,
    /// The destination node ID (the requester)
    pub destination: NodeId,
}

/// Route hop information for serialization
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct RouteHopInfo {
    /// The mix node's public key
    pub public_key: [u8; 32],
    /// The mix node's ID
    pub node_id: NodeId,
}

impl ReturnRoute {
    /// Convert to a Sphinx route for response packet creation
    pub fn to_sphinx_route(&self) -> static_sphinx::Route {
        static_sphinx::Route {
            hops: self
                .hops
                .iter()
                .map(|h| static_sphinx::RouteHop {
                    public_key: h.public_key,
                    node_id: h.node_id,
                })
                .collect(),
            destination: self.destination,
        }
    }

    /// Create from a Sphinx route (the requester's own return path)
    pub fn from_sphinx_route(route: &static_sphinx::Route) -> Self {
        Self {
            hops: route
                .hops
                .iter()
                .map(|h| RouteHopInfo {
                    public_key: h.public_key,
                    node_id: h.node_id,
                })
                .collect(),
            destination: route.destination,
        }
    }
}

/// Serialize a compute request into a Sphinx body payload
pub fn serialize_request(req: &ComputeRequest) -> Result<Vec<u8>, StorageError> {
    if req.input_data.len() > MAX_COMPUTE_INPUT_SIZE {
        return Err(StorageError::InvalidChunkSize {
            expected: MAX_COMPUTE_INPUT_SIZE,
            actual: req.input_data.len(),
        });
    }

    let mut buf = Vec::with_capacity(121 + req.return_route.hops.len() * 48 + req.input_data.len());

    buf.push(MSG_COMPUTE_REQUEST);
    buf.extend_from_slice(&req.from_node);
    buf.extend_from_slice(&req.module_content_id);
    buf.extend_from_slice(&req.module_content_pub_key);
    buf.extend_from_slice(&req.fee_offer.to_be_bytes());
    buf.extend_from_slice(&req.request_id);

    buf.extend_from_slice(&(req.return_route.hops.len() as u32).to_be_bytes());
    for hop in &req.return_route.hops {
        buf.extend_from_slice(&hop.public_key);
        buf.extend_from_slice(&hop.node_id);
    }
    buf.extend_from_slice(&req.return_route.destination);

    buf.extend_from_slice(&(req.input_data.len() as u32).to_be_bytes());
    buf.extend_from_slice(&req.input_data);

    Ok(buf)
}

/// Deserialize a compute request from a Sphinx body payload
pub fn deserialize_request(data: &[u8]) -> Result<ComputeRequest, StorageError> {
    let short = |needed: usize| StorageError::InvalidChunkSize {
        expected: needed,
        actual: data.len(),
    };

    if data.is_empty() || data[0] != MSG_COMPUTE_REQUEST {
        return Err(StorageError::InvalidChunkSize {
            expected: MSG_COMPUTE_REQUEST as usize,
            actual: data.first().copied().map(|b| b as usize).unwrap_or(0),
        });
    }

    let mut offset = 1;

    if offset + 16 > data.len() {
        return Err(short(offset + 16));
    }
    let mut from_node = [0u8; 16];
    from_node.copy_from_slice(&data[offset..offset + 16]);
    offset += 16;

    if offset + 32 > data.len() {
        return Err(short(offset + 32));
    }
    let mut module_content_id = [0u8; 32];
    module_content_id.copy_from_slice(&data[offset..offset + 32]);
    offset += 32;

    if offset + 32 > data.len() {
        return Err(short(offset + 32));
    }
    let mut module_content_pub_key = [0u8; 32];
    module_content_pub_key.copy_from_slice(&data[offset..offset + 32]);
    offset += 32;

    if offset + 8 > data.len() {
        return Err(short(offset + 8));
    }
    let mut fee_bytes = [0u8; 8];
    fee_bytes.copy_from_slice(&data[offset..offset + 8]);
    let fee_offer = u64::from_be_bytes(fee_bytes);
    offset += 8;

    if offset + 32 > data.len() {
        return Err(short(offset + 32));
    }
    let mut request_id = [0u8; 32];
    request_id.copy_from_slice(&data[offset..offset + 32]);
    offset += 32;

    // Return route
    if offset + 4 > data.len() {
        return Err(short(offset + 4));
    }
    let hop_count = u32::from_be_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ]) as usize;
    offset += 4;

    if offset + hop_count * 48 + 16 > data.len() {
        return Err(short(offset + hop_count * 48 + 16));
    }
    let mut hops = Vec::with_capacity(hop_count);
    for _ in 0..hop_count {
        let mut public_key = [0u8; 32];
        public_key.copy_from_slice(&data[offset..offset + 32]);
        offset += 32;

        let mut node_id = [0u8; 16];
        node_id.copy_from_slice(&data[offset..offset + 16]);
        offset += 16;

        hops.push(RouteHopInfo { public_key, node_id });
    }

    let mut destination = [0u8; 16];
    destination.copy_from_slice(&data[offset..offset + 16]);
    offset += 16;

    // Input data
    if offset + 4 > data.len() {
        return Err(short(offset + 4));
    }
    let input_len = u32::from_be_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ]) as usize;
    offset += 4;

    if offset + input_len > data.len() {
        return Err(short(offset + input_len));
    }
    let input_data = data[offset..offset + input_len].to_vec();

    if input_data.len() > MAX_COMPUTE_INPUT_SIZE {
        return Err(StorageError::InvalidChunkSize {
            expected: MAX_COMPUTE_INPUT_SIZE,
            actual: input_data.len(),
        });
    }

    Ok(ComputeRequest {
        from_node,
        module_content_id,
        module_content_pub_key,
        fee_offer,
        request_id,
        return_route: ReturnRoute { hops, destination },
        input_data,
    })
}

/// Serialize a compute response into a Sphinx body payload
pub fn serialize_response(resp: &ComputeResponse) -> Result<Vec<u8>, StorageError> {
    if resp.output_data.len() > MAX_COMPUTE_OUTPUT_SIZE {
        return Err(StorageError::InvalidChunkSize {
            expected: MAX_COMPUTE_OUTPUT_SIZE,
            actual: resp.output_data.len(),
        });
    }

    let error = resp.error.clone().unwrap_or_default();

    let mut buf =
        Vec::with_capacity(66 + error.len() + resp.output_data.len());

    buf.push(MSG_COMPUTE_RESPONSE);
    buf.extend_from_slice(&resp.request_id);
    buf.push(if resp.success { 1 } else { 0 });

    buf.extend_from_slice(&(error.len() as u32).to_be_bytes());
    buf.extend_from_slice(error.as_bytes());

    buf.extend_from_slice(&resp.cpu_time_ms.to_be_bytes());
    buf.extend_from_slice(&resp.memory_used.to_be_bytes());
    buf.extend_from_slice(&resp.fee_charged.to_be_bytes());

    buf.extend_from_slice(&(resp.output_data.len() as u32).to_be_bytes());
    buf.extend_from_slice(&resp.output_data);

    Ok(buf)
}

/// Deserialize a compute response from a Sphinx body payload
pub fn deserialize_response(data: &[u8]) -> Result<ComputeResponse, StorageError> {
    let short = |needed: usize| StorageError::InvalidChunkSize {
        expected: needed,
        actual: data.len(),
    };

    if data.is_empty() || data[0] != MSG_COMPUTE_RESPONSE {
        return Err(StorageError::InvalidChunkSize {
            expected: MSG_COMPUTE_RESPONSE as usize,
            actual: data.first().copied().map(|b| b as usize).unwrap_or(0),
        });
    }

    let mut offset = 1;

    if offset + 32 > data.len() {
        return Err(short(offset + 32));
    }
    let mut request_id = [0u8; 32];
    request_id.copy_from_slice(&data[offset..offset + 32]);
    offset += 32;

    if offset + 1 > data.len() {
        return Err(short(offset + 1));
    }
    let success = data[offset] == 1;
    offset += 1;

    if offset + 4 > data.len() {
        return Err(short(offset + 4));
    }
    let error_len = u32::from_be_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ]) as usize;
    offset += 4;

    if offset + error_len > data.len() {
        return Err(short(offset + error_len));
    }
    let error = if error_len > 0 {
        Some(
            String::from_utf8(data[offset..offset + error_len].to_vec())
                .map_err(|_| StorageError::DecryptionFailed)?,
        )
    } else {
        None
    };
    offset += error_len;

    if offset + 24 > data.len() {
        return Err(short(offset + 24));
    }
    let mut cpu_bytes = [0u8; 8];
    cpu_bytes.copy_from_slice(&data[offset..offset + 8]);
    let cpu_time_ms = u64::from_be_bytes(cpu_bytes);
    offset += 8;

    let mut mem_bytes = [0u8; 8];
    mem_bytes.copy_from_slice(&data[offset..offset + 8]);
    let memory_used = u64::from_be_bytes(mem_bytes);
    offset += 8;

    let mut fee_bytes = [0u8; 8];
    fee_bytes.copy_from_slice(&data[offset..offset + 8]);
    let fee_charged = u64::from_be_bytes(fee_bytes);
    offset += 8;

    if offset + 4 > data.len() {
        return Err(short(offset + 4));
    }
    let output_len = u32::from_be_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ]) as usize;
    offset += 4;

    if offset + output_len > data.len() {
        return Err(short(offset + output_len));
    }
    let output_data = data[offset..offset + output_len].to_vec();

    if output_data.len() > MAX_COMPUTE_OUTPUT_SIZE {
        return Err(StorageError::InvalidChunkSize {
            expected: MAX_COMPUTE_OUTPUT_SIZE,
            actual: output_data.len(),
        });
    }

    Ok(ComputeResponse {
        request_id,
        output_data,
        success,
        error,
        cpu_time_ms,
        memory_used,
        fee_charged,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_request_roundtrip() {
        let request = ComputeRequest {
            from_node: [0x11u8; 16],
            module_content_id: [0x22u8; 32],
            module_content_pub_key: [0x33u8; 32],
            fee_offer: 10_240,
            request_id: [0x44u8; 32],
            return_route: ReturnRoute {
                hops: vec![RouteHopInfo {
                    public_key: [0x55u8; 32],
                    node_id: [0x66u8; 16],
                }],
                destination: [0x77u8; 16],
            },
            input_data: b"hello compute".to_vec(),
        };

        let serialized = serialize_request(&request).unwrap();
        assert_eq!(serialized[0], MSG_COMPUTE_REQUEST);

        let back = deserialize_request(&serialized).unwrap();
        assert_eq!(back, request);
    }

    #[test]
    fn test_compute_response_roundtrip() {
        let response = ComputeResponse {
            request_id: [0x44u8; 32],
            output_data: vec![0xAAu8; 512],
            success: true,
            error: None,
            cpu_time_ms: 42,
            memory_used: 65_536,
            fee_charged: 5_120,
        };

        let serialized = serialize_response(&response).unwrap();
        assert_eq!(serialized[0], MSG_COMPUTE_RESPONSE);

        let back = deserialize_response(&serialized).unwrap();
        assert_eq!(back, response);

        // Error variant roundtrips too
        let failed = ComputeResponse {
            request_id: [0x01u8; 32],
            output_data: vec![],
            success: false,
            error: Some("module not found".to_string()),
            cpu_time_ms: 0,
            memory_used: 0,
            fee_charged: 0,
        };
        let back = deserialize_response(&serialize_response(&failed).unwrap()).unwrap();
        assert_eq!(back, failed);
    }

    #[test]
    fn test_compute_request_rejects_oversized_input() {
        let mut request = ComputeRequest {
            from_node: [0u8; 16],
            module_content_id: [0u8; 32],
            module_content_pub_key: [0u8; 32],
            fee_offer: 1,
            request_id: [0u8; 32],
            return_route: ReturnRoute {
                hops: vec![],
                destination: [0u8; 16],
            },
            input_data: vec![0u8; MAX_COMPUTE_INPUT_SIZE + 1],
        };
        assert!(serialize_request(&request).is_err());

        request.input_data = vec![0u8; MAX_COMPUTE_INPUT_SIZE];
        assert!(serialize_request(&request).is_ok());
    }

    #[test]
    fn test_compute_invalid_type_byte() {
        assert!(deserialize_request(&[0x01, 0, 0]).is_err());
        assert!(deserialize_response(&[0x01, 0, 0]).is_err());
        assert!(deserialize_request(&[]).is_err());
    }
}
