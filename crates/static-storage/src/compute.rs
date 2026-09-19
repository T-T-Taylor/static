//! Compute request/response and payment protocol over Sphinx
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
//!                  [module_content_pub_key 32][currency 1]
//!                  [payment_addr_len 4][payment_addr..]
//!                  [request_id 32][return_route][input_len 4][input..]
//!
//! ComputeResponse: [0x04][request_id 32][success 1][error_len 4][error..]
//!                  [cpu_time_ms 8][memory_used 8][payment_required 1]
//!                  [payreq_len 4][payreq..][output_len 4][output..]
//!
//! PaymentRequest:  [0x05][request_id 32][currency 1][amount 8]
//!                  [addr_len 4][addr..][confirmations 4]
//!
//! PaymentConfirmation: [0x06][request_id 32][currency 1]
//!                      [tx_hash_len 4][tx_hash..]
//!
//! return_route:    [hop_count 4][{public_key 32, node_id 16}..][destination 16]
//! ```
//!
//! All four message types are indistinguishable from cover traffic on the
//! wire. The provider does not learn who requested computation beyond the
//! mixnet's guarantees; `from_node` exists only for accounting bookkeeping
//! and cannot be verified through the mixnet.
//!
//! Compute is paid in cryptocurrency prepayment: the provider quotes a
//! price with a [`PaymentRequest`] (fresh receive address per request),
//! the requester pays on-chain and signals intent with a
//! [`PaymentConfirmation`], and the provider verifies the payment on the
//! blockchain before executing.

use crate::{ContentId, StorageError};
use static_sphinx::NodeId;

/// Compute request message type
pub const MSG_COMPUTE_REQUEST: u8 = 0x03;

/// Compute response message type
pub const MSG_COMPUTE_RESPONSE: u8 = 0x04;

/// Payment request message type (provider -> requester)
pub const MSG_PAYMENT_REQUEST: u8 = 0x05;

/// Payment confirmation message type (requester -> provider)
pub const MSG_PAYMENT_CONFIRMATION: u8 = 0x06;

/// Maximum compute input size per request (bytes)
pub const MAX_COMPUTE_INPUT_SIZE: usize = 32 * 1024;

/// Maximum compute output size per response (bytes)
pub const MAX_COMPUTE_OUTPUT_SIZE: usize = 32 * 1024;

/// Maximum payment address length (bytes)
pub const MAX_PAYMENT_ADDRESS_SIZE: usize = 1024;

/// Maximum payment transaction hash length (bytes)
pub const MAX_TX_HASH_SIZE: usize = 1024;

/// Maximum embedded [`PaymentRequest`] blob in a [`ComputeResponse`] (bytes)
pub const MAX_PAYMENT_REQUEST_SIZE: usize = 2048;

/// Maximum return-route hops accepted during deserialization (DoS bound).
pub const MAX_COMPUTE_ROUTE_HOPS: usize = 32;

/// Supported cryptocurrencies for compute payment
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[repr(u8)]
pub enum Currency {
    /// Monero (XMR)
    Monero = 0,
    /// Darkfi (DARK)
    Darkfi = 1,
    /// Navio (NAV)
    Navio = 2,
}

impl Currency {
    /// Parse a currency from a ticker or name (case-insensitive)
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "xmr" | "monero" => Some(Currency::Monero),
            "dark" | "darkfi" => Some(Currency::Darkfi),
            "nav" | "navio" => Some(Currency::Navio),
            _ => None,
        }
    }

    /// Ticker symbol
    pub fn as_str(&self) -> &'static str {
        match self {
            Currency::Monero => "XMR",
            Currency::Darkfi => "DARK",
            Currency::Navio => "NAV",
        }
    }

    /// Serialize to a wire byte
    pub fn to_byte(self) -> u8 {
        self as u8
    }

    /// Deserialize from a wire byte
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            0 => Some(Currency::Monero),
            1 => Some(Currency::Darkfi),
            2 => Some(Currency::Navio),
            _ => None,
        }
    }
}

/// A request to execute a WASM module on a remote compute provider
///
/// Sent as a fragmented Sphinx body. The provider fetches the module
/// (identified by its content public key) from the network if it is not
/// cached, and either executes it immediately (free tier) or quotes a
/// [`PaymentRequest`] first. The result comes back as a [`ComputeResponse`]
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
    /// Currency the requester intends to pay in (`Currency::to_byte()`);
    /// ignored by providers offering free compute
    pub currency: u8,
    /// Payment address (always empty in an initial request; the provider
    /// quotes a fresh address in its `PaymentRequest`)
    pub payment_address: Vec<u8>,
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
    /// Whether payment is required before execution (true on
    /// payment-timeout rejections; false once paid or on the free tier)
    pub payment_required: bool,
    /// Serialized [`PaymentRequest`] quote (empty when `payment_required`
    /// is false)
    pub payment_request: Vec<u8>,
}

/// A payment quote from provider to requester
///
/// The provider generates a fresh receive address for every request (no
/// address reuse) and watches the blockchain for the incoming payment.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct PaymentRequest {
    /// The request ID this quote is for
    pub request_id: [u8; 32],
    /// The currency to pay in
    pub currency: Currency,
    /// The amount to pay in atomic units (smallest denomination)
    pub amount: u64,
    /// The provider's receive address (new for each request)
    pub address: String,
    /// Number of confirmations required before execution
    pub required_confirmations: u32,
}

/// A payment confirmation from requester to provider
///
/// Signals that the requester has sent the on-chain payment; the provider
/// independently verifies it on the blockchain before executing.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct PaymentConfirmation {
    /// The request ID this confirmation is for
    pub request_id: [u8; 32],
    /// The transaction hash (provider verifies on blockchain)
    pub tx_hash: String,
    /// The currency
    pub currency: Currency,
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
    if req.payment_address.len() > MAX_PAYMENT_ADDRESS_SIZE {
        return Err(StorageError::InvalidChunkSize {
            expected: MAX_PAYMENT_ADDRESS_SIZE,
            actual: req.payment_address.len(),
        });
    }

    let mut buf = Vec::with_capacity(
        122
            + req.payment_address.len()
            + req.return_route.hops.len() * 48
            + req.input_data.len(),
    );

    buf.push(MSG_COMPUTE_REQUEST);
    buf.extend_from_slice(&req.from_node);
    buf.extend_from_slice(&req.module_content_id);
    buf.extend_from_slice(&req.module_content_pub_key);
    buf.push(req.currency);
    buf.extend_from_slice(&(req.payment_address.len() as u32).to_be_bytes());
    buf.extend_from_slice(&req.payment_address);
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

    if offset + 1 > data.len() {
        return Err(short(offset + 1));
    }
    let currency = data[offset];
    offset += 1;

    if offset + 4 > data.len() {
        return Err(short(offset + 4));
    }
    let addr_len = u32::from_be_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ]) as usize;
    offset += 4;

    if addr_len > MAX_PAYMENT_ADDRESS_SIZE {
        return Err(StorageError::InvalidChunkSize {
            expected: MAX_PAYMENT_ADDRESS_SIZE,
            actual: addr_len,
        });
    }
    if offset + addr_len > data.len() {
        return Err(short(offset + addr_len));
    }
    let payment_address = data[offset..offset + addr_len].to_vec();
    offset += addr_len;

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

    if hop_count > MAX_COMPUTE_ROUTE_HOPS {
        return Err(short(MAX_COMPUTE_ROUTE_HOPS));
    }
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
        currency,
        payment_address,
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
    if resp.payment_request.len() > MAX_PAYMENT_REQUEST_SIZE {
        return Err(StorageError::InvalidChunkSize {
            expected: MAX_PAYMENT_REQUEST_SIZE,
            actual: resp.payment_request.len(),
        });
    }

    let error = resp.error.clone().unwrap_or_default();

    let mut buf = Vec::with_capacity(
        66 + error.len() + resp.payment_request.len() + resp.output_data.len(),
    );

    buf.push(MSG_COMPUTE_RESPONSE);
    buf.extend_from_slice(&resp.request_id);
    buf.push(if resp.success { 1 } else { 0 });

    buf.extend_from_slice(&(error.len() as u32).to_be_bytes());
    buf.extend_from_slice(error.as_bytes());

    buf.extend_from_slice(&resp.cpu_time_ms.to_be_bytes());
    buf.extend_from_slice(&resp.memory_used.to_be_bytes());

    buf.push(if resp.payment_required { 1 } else { 0 });
    buf.extend_from_slice(&(resp.payment_request.len() as u32).to_be_bytes());
    buf.extend_from_slice(&resp.payment_request);

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

    if offset + 16 > data.len() {
        return Err(short(offset + 16));
    }
    let mut cpu_bytes = [0u8; 8];
    cpu_bytes.copy_from_slice(&data[offset..offset + 8]);
    let cpu_time_ms = u64::from_be_bytes(cpu_bytes);
    offset += 8;

    let mut mem_bytes = [0u8; 8];
    mem_bytes.copy_from_slice(&data[offset..offset + 8]);
    let memory_used = u64::from_be_bytes(mem_bytes);
    offset += 8;

    if offset + 1 > data.len() {
        return Err(short(offset + 1));
    }
    let payment_required = data[offset] == 1;
    offset += 1;

    if offset + 4 > data.len() {
        return Err(short(offset + 4));
    }
    let payreq_len = u32::from_be_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ]) as usize;
    offset += 4;

    if payreq_len > MAX_PAYMENT_REQUEST_SIZE {
        return Err(StorageError::InvalidChunkSize {
            expected: MAX_PAYMENT_REQUEST_SIZE,
            actual: payreq_len,
        });
    }
    if offset + payreq_len > data.len() {
        return Err(short(offset + payreq_len));
    }
    let payment_request = data[offset..offset + payreq_len].to_vec();
    offset += payreq_len;

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
        payment_required,
        payment_request,
    })
}

/// Serialize a payment request quote into a Sphinx body payload
pub fn serialize_payment_request(req: &PaymentRequest) -> Result<Vec<u8>, StorageError> {
    let address = req.address.as_bytes();
    if address.len() > MAX_PAYMENT_ADDRESS_SIZE {
        return Err(StorageError::InvalidChunkSize {
            expected: MAX_PAYMENT_ADDRESS_SIZE,
            actual: address.len(),
        });
    }

    let mut buf = Vec::with_capacity(49 + address.len());

    buf.push(MSG_PAYMENT_REQUEST);
    buf.extend_from_slice(&req.request_id);
    buf.push(req.currency.to_byte());
    buf.extend_from_slice(&req.amount.to_be_bytes());
    buf.extend_from_slice(&(address.len() as u32).to_be_bytes());
    buf.extend_from_slice(address);
    buf.extend_from_slice(&req.required_confirmations.to_be_bytes());

    Ok(buf)
}

/// Deserialize a payment request quote from a Sphinx body payload
pub fn deserialize_payment_request(data: &[u8]) -> Result<PaymentRequest, StorageError> {
    let short = |needed: usize| StorageError::InvalidChunkSize {
        expected: needed,
        actual: data.len(),
    };

    if data.is_empty() || data[0] != MSG_PAYMENT_REQUEST {
        return Err(StorageError::InvalidChunkSize {
            expected: MSG_PAYMENT_REQUEST as usize,
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
    let currency = Currency::from_byte(data[offset]).ok_or(StorageError::DecryptionFailed)?;
    offset += 1;

    if offset + 8 > data.len() {
        return Err(short(offset + 8));
    }
    let mut amount_bytes = [0u8; 8];
    amount_bytes.copy_from_slice(&data[offset..offset + 8]);
    let amount = u64::from_be_bytes(amount_bytes);
    offset += 8;

    if offset + 4 > data.len() {
        return Err(short(offset + 4));
    }
    let addr_len = u32::from_be_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ]) as usize;
    offset += 4;

    if addr_len > MAX_PAYMENT_ADDRESS_SIZE {
        return Err(StorageError::InvalidChunkSize {
            expected: MAX_PAYMENT_ADDRESS_SIZE,
            actual: addr_len,
        });
    }
    if offset + addr_len > data.len() {
        return Err(short(offset + addr_len));
    }
    let address = String::from_utf8(data[offset..offset + addr_len].to_vec())
        .map_err(|_| StorageError::DecryptionFailed)?;
    offset += addr_len;

    if offset + 4 > data.len() {
        return Err(short(offset + 4));
    }
    let required_confirmations = u32::from_be_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ]);

    Ok(PaymentRequest {
        request_id,
        currency,
        amount,
        address,
        required_confirmations,
    })
}

/// Serialize a payment confirmation into a Sphinx body payload
pub fn serialize_payment_confirmation(confirmation: &PaymentConfirmation) -> Result<Vec<u8>, StorageError> {
    let tx_hash = confirmation.tx_hash.as_bytes();
    if tx_hash.len() > MAX_TX_HASH_SIZE {
        return Err(StorageError::InvalidChunkSize {
            expected: MAX_TX_HASH_SIZE,
            actual: tx_hash.len(),
        });
    }

    let mut buf = Vec::with_capacity(37 + tx_hash.len());

    buf.push(MSG_PAYMENT_CONFIRMATION);
    buf.extend_from_slice(&confirmation.request_id);
    buf.push(confirmation.currency.to_byte());
    buf.extend_from_slice(&(tx_hash.len() as u32).to_be_bytes());
    buf.extend_from_slice(tx_hash);

    Ok(buf)
}

/// Deserialize a payment confirmation from a Sphinx body payload
pub fn deserialize_payment_confirmation(data: &[u8]) -> Result<PaymentConfirmation, StorageError> {
    let short = |needed: usize| StorageError::InvalidChunkSize {
        expected: needed,
        actual: data.len(),
    };

    if data.is_empty() || data[0] != MSG_PAYMENT_CONFIRMATION {
        return Err(StorageError::InvalidChunkSize {
            expected: MSG_PAYMENT_CONFIRMATION as usize,
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
    let currency = Currency::from_byte(data[offset]).ok_or(StorageError::DecryptionFailed)?;
    offset += 1;

    if offset + 4 > data.len() {
        return Err(short(offset + 4));
    }
    let tx_hash_len = u32::from_be_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ]) as usize;
    offset += 4;

    if tx_hash_len > MAX_TX_HASH_SIZE {
        return Err(StorageError::InvalidChunkSize {
            expected: MAX_TX_HASH_SIZE,
            actual: tx_hash_len,
        });
    }
    if offset + tx_hash_len > data.len() {
        return Err(short(offset + tx_hash_len));
    }
    let tx_hash = String::from_utf8(data[offset..offset + tx_hash_len].to_vec())
        .map_err(|_| StorageError::DecryptionFailed)?;

    Ok(PaymentConfirmation {
        request_id,
        tx_hash,
        currency,
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
            currency: Currency::Monero.to_byte(),
            payment_address: vec![], // empty in initial requests
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
        // currency byte sits right after the fixed header (no fee field)
        assert_eq!(serialized[81], Currency::Monero.to_byte());

        let back = deserialize_request(&serialized).unwrap();
        assert_eq!(back, request);
    }

    #[test]
    fn test_compute_response_roundtrip() {
        let quote = PaymentRequest {
            request_id: [0x44u8; 32],
            currency: Currency::Monero,
            amount: 100_000_000_000,
            address: "4AddressExampleXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX".to_string(),
            required_confirmations: 2,
        };
        let response = ComputeResponse {
            request_id: [0x44u8; 32],
            output_data: vec![0xAAu8; 512],
            success: true,
            error: None,
            cpu_time_ms: 42,
            memory_used: 65_536,
            payment_required: false,
            payment_request: vec![],
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
            payment_required: true,
            payment_request: serialize_payment_request(&quote).unwrap(),
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
            currency: 0,
            payment_address: vec![],
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
        assert!(deserialize_payment_request(&[0x01, 0, 0]).is_err());
        assert!(deserialize_payment_confirmation(&[0x01, 0, 0]).is_err());
        assert!(deserialize_request(&[]).is_err());
    }

    #[test]
    fn test_payment_request_roundtrip() {
        let quote = PaymentRequest {
            request_id: [0x88u8; 32],
            currency: Currency::Darkfi,
            amount: 42,
            address: "darkfi1qypqxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx".to_string(),
            required_confirmations: 3,
        };

        let serialized = serialize_payment_request(&quote).unwrap();
        assert_eq!(serialized[0], MSG_PAYMENT_REQUEST);
        let back = deserialize_payment_request(&serialized).unwrap();
        assert_eq!(back, quote);

        // Truncated payloads are rejected
        assert!(deserialize_payment_request(&serialized[..serialized.len() - 1]).is_err());
        // Oversized addresses are rejected on both ends
        let mut huge = quote.clone();
        huge.address = "x".repeat(MAX_PAYMENT_ADDRESS_SIZE + 1);
        assert!(serialize_payment_request(&huge).is_err());
    }

    #[test]
    fn test_payment_confirmation_roundtrip() {
        let confirmation = PaymentConfirmation {
            request_id: [0x99u8; 32],
            tx_hash: "abc123def4567890abcdef1234567890abcdef1234567890abcdef1234567890".to_string(),
            currency: Currency::Navio,
        };

        let serialized = serialize_payment_confirmation(&confirmation).unwrap();
        assert_eq!(serialized[0], MSG_PAYMENT_CONFIRMATION);
        let back = deserialize_payment_confirmation(&serialized).unwrap();
        assert_eq!(back, confirmation);

        // Truncated payloads are rejected
        assert!(deserialize_payment_confirmation(&serialized[..serialized.len() - 1]).is_err());
        // Oversized tx hashes are rejected on both ends
        let mut huge = confirmation.clone();
        huge.tx_hash = "a".repeat(MAX_TX_HASH_SIZE + 1);
        assert!(serialize_payment_confirmation(&huge).is_err());
    }
}
