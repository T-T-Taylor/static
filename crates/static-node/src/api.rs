//! Local API server for the Static node
//!
//! Provides a simple JSON API over TCP for the CLI to interact
//! with the running node (e.g., publishing and retrieving content).

use crate::runner::NodeRunner;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// A request to the local API
#[derive(Serialize, Deserialize, Debug)]
pub struct ApiRequest {
    /// The action to perform ("publish", "retrieve", "compute",
    /// "compute_result" or "compute_confirm")
    pub action: String,
    /// Hex encoded file data (for publish), input data (for compute), or
    /// request ID (for compute_result)
    pub data: Option<String>,
    /// Hex encoded content public key (for retrieve/compute)
    pub content_pub_key: Option<String>,
    /// Payment currency ticker (for compute; default "xmr")
    pub compute_currency: Option<String>,
    /// Hex encoded compute request ID (for compute_confirm)
    pub request_id: Option<String>,
    /// Transaction hash proving on-chain payment (for compute_confirm)
    pub tx_hash: Option<String>,
    /// Bearer token for optional local-API auth (serde default for
    /// backwards compatibility with old clients that send no token).
    #[serde(default)]
    pub token: Option<String>,
}

/// A response from the local API
#[derive(Serialize, Deserialize, Debug, Default)]
pub struct ApiResponse {
    /// Status ("ok", "pending", or "error")
    pub status: String,
    /// Message (error details or info)
    pub message: String,
    /// Content ID (for publish response)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_id: Option<String>,
    /// Content manifest (for publish response)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub manifest: Option<static_storage::ContentManifest>,
    /// Hex encoded file/output data (for retrieve/compute_result response)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<String>,
    /// Hex encoded content public key (for publish response)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_pub_key: Option<String>,
    /// Compute request ID (for compute responses)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    /// Whether payment is required before execution (compute_result)
    #[serde(default)]
    pub payment_required: bool,
    /// Payment currency ticker (compute_result, when payment is required)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payment_currency: Option<String>,
    /// Provider receive address (compute_result, when payment is required)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payment_address: Option<String>,
    /// Amount to pay in atomic units (compute_result, when payment required)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payment_amount: Option<u64>,
}

/// Serialize an API response without panicking.
///
/// `ApiResponse` serialization is infallible in practice, but a panic in
/// a spawned connection task would kill that connection silently. Fall
/// back to a minimal static error payload instead.
fn serialize_response(resp: &ApiResponse) -> Vec<u8> {
    serde_json::to_vec(resp).unwrap_or_else(|_| {
        b"{\"status\":\"error\",\"message\":\"response serialization failed\"}".to_vec()
    })
}

/// Check an incoming request's bearer token against the expected value.
///
/// - `None` expected: auth disabled, any request (with or without a token)
///   is accepted.
/// - `Some(expected)`: the request must carry `token == expected`,
///   otherwise it is rejected. Comparison is constant-time over the
///   token bytes to avoid leaking prefix length via timing; the token
///   is never logged.
pub fn verify_token(request_token: Option<&str>, expected_token: Option<&str>) -> bool {
    match expected_token {
        None => true,
        Some(expected) => match request_token {
            None => false,
            Some(got) => constant_time_eq(got.as_bytes(), expected.as_bytes()),
        },
    }
}

/// Constant-time byte equality (length + content).
///
/// Compares up to the longer length, folding length difference into the
/// accumulator so both length and content mismatches take the same path.
/// No early exit on first mismatch.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    let max_len = a.len().max(b.len());
    let mut diff = (a.len() ^ b.len()) as u8;
    for i in 0..max_len {
        let x = *a.get(i).unwrap_or(&0);
        let y = *b.get(i).unwrap_or(&0);
        diff |= x ^ y;
    }
    diff == 0
}

/// Start the local API server without token auth (backwards-compatible
/// wrapper for existing callers such as `runner.rs`).
pub async fn start_api_server(runner: Arc<NodeRunner>, addr: String) -> Result<()> {
    start_api_server_with_token(runner, addr, None).await
}

/// Start the local API server, optionally requiring a bearer token.
///
/// When `expected_token` is `Some`, every [`ApiRequest`] must carry a
/// matching `token` field or it is rejected with an `"error"` response
/// before any action is performed.
pub async fn start_api_server_with_token(
    runner: Arc<NodeRunner>,
    addr: String,
    expected_token: Option<String>,
) -> Result<()> {
    if addr.starts_with("0.0.0.0") || addr.contains(":0.0.0.0") {
        tracing::warn!(
            "Local API bound to {} (all interfaces): ensure --api-token is set; loopback 127.0.0.1 is recommended",
            addr
        );
    }
    if expected_token.is_none() {
        tracing::warn!(
            "Local API auth disabled (no --api-token): any local user can publish/retrieve/compute"
        );
    }
    let listener = TcpListener::bind(&addr).await?;
    tracing::info!("Local API listening on {}", addr);

    loop {
        let (mut socket, _) = listener.accept().await?;
        let runner = runner.clone();
        let expected_token = expected_token.clone();

        tokio::spawn(async move {
            // Chunked framing (P1-local): accumulate 8 KiB reads up to a
            // 1 MiB cap so TCP segmentation cannot truncate a request.
            // The CLI sends one JSON object then waits for a response
            // (no EOF), so after the buffer parses as JSON we drain with
            // a short timeout instead of waiting for close.
            const MAX_API_REQUEST_BYTES: usize = 1024 * 1024;
            let mut buf = Vec::with_capacity(8192);
            let mut chunk = [0u8; 8192];
            // First blocking read (must get data).
            match socket.read(&mut chunk).await {
                Ok(0) => return,
                Ok(n) => buf.extend_from_slice(&chunk[..n]),
                Err(_) => return,
            }
            if buf.len() > MAX_API_REQUEST_BYTES {
                let resp = ApiResponse {
                    status: "error".into(),
                    message: "request too large".into(),
                    ..Default::default()
                };
                let _ = socket.write_all(&serialize_response(&resp)).await;
                return;
            }
            // Gather segmentation tail: while the buffer does not yet
            // parse, keep reading (blocking, data is in flight). Once it
            // parses, poll briefly for a tail then proceed.
            loop {
                if serde_json::from_slice::<ApiRequest>(&buf).is_ok() {
                    match tokio::time::timeout(
                        std::time::Duration::from_millis(50),
                        socket.read(&mut chunk),
                    )
                    .await
                    {
                        Ok(Ok(0)) => break,
                        Ok(Ok(n)) => {
                            if buf.len() + n > MAX_API_REQUEST_BYTES {
                                let resp = ApiResponse {
                                    status: "error".into(),
                                    message: "request too large".into(),
                                    ..Default::default()
                                };
                                let _ = socket.write_all(&serialize_response(&resp)).await;
                                return;
                            }
                            buf.extend_from_slice(&chunk[..n]);
                            // If the extra bytes break parsing, keep them:
                            // the final parse below will error safely.
                            break;
                        }
                        _ => break,
                    }
                }
                // Incomplete JSON: more segments in flight, read blocking.
                match tokio::time::timeout(
                    std::time::Duration::from_secs(5),
                    socket.read(&mut chunk),
                )
                .await
                {
                    Ok(Ok(0)) => break,
                    Ok(Ok(n)) => {
                        if buf.len() + n > MAX_API_REQUEST_BYTES {
                            let resp = ApiResponse {
                                status: "error".into(),
                                message: "request too large".into(),
                                ..Default::default()
                            };
                            let _ = socket.write_all(&serialize_response(&resp)).await;
                            return;
                        }
                        buf.extend_from_slice(&chunk[..n]);
                    }
                    _ => break,
                }
                if buf.len() > MAX_API_REQUEST_BYTES {
                    break;
                }
            }
            if buf.is_empty() {
                return;
            }
            if buf.len() > MAX_API_REQUEST_BYTES {
                let resp = ApiResponse {
                    status: "error".into(),
                    message: "request too large".into(),
                    ..Default::default()
                };
                let _ = socket.write_all(&serialize_response(&resp)).await;
                return;
            }

            let request: ApiRequest = match serde_json::from_slice(&buf) {
                Ok(r) => r,
                Err(e) => {
                    let resp = ApiResponse {
                        status: "error".into(),
                        message: format!("Invalid request: {}", e),
                        ..Default::default()
                    };
                    let _ = socket.write_all(&serialize_response(&resp)).await;
                    return;
                }
            };

            let response = handle_request(&runner, request, expected_token.as_deref()).await;
            let _ = socket.write_all(&serialize_response(&response)).await;
        });
    }
}

async fn handle_request(
    runner: &NodeRunner,
    request: ApiRequest,
    expected_token: Option<&str>,
) -> ApiResponse {
    // Token check comes first: reject unauthenticated requests before
    // touching any node state.
    if !verify_token(request.token.as_deref(), expected_token) {
        return api_error("unauthorized: invalid or missing API token".into());
    }
    match request.action.as_str() {
        "publish" => {
            let data_hex = request.data.unwrap_or_default();
            let data = match hex_decode(&data_hex) {
                Ok(d) => d,
                Err(e) => return api_error(format!("Invalid hex: {}", e)),
            };

            match runner.publish_content(&data).await {
                Ok((content_id, manifest, content_pub_key)) => {
                    let id_hex = hex_encode(&content_id);
                    let key_hex = hex_encode(&content_pub_key);
                    ApiResponse {
                        status: "ok".into(),
                        message: "Published".into(),
                        content_id: Some(id_hex),
                        manifest: Some(manifest),
                        content_pub_key: Some(key_hex),
                        ..Default::default()
                    }
                }
                Err(e) => api_error(format!("Publish failed: {}", e)),
            }
        }
        "retrieve" => {
            let key_arr = match parse_content_key(request.content_pub_key.as_deref()) {
                Ok(k) => k,
                Err(e) => return api_error(e),
            };

            match runner.retrieve_content(&key_arr).await {
                Ok(data) => {
                    let data_hex = hex_encode(&data);
                    ApiResponse {
                        status: "ok".into(),
                        message: "Retrieved".into(),
                        data: Some(data_hex),
                        ..Default::default()
                    }
                }
                Err(e) => api_error(format!("Retrieve failed: {}", e)),
            }
        }
        "compute" => {
            let key_arr = match parse_content_key(request.content_pub_key.as_deref()) {
                Ok(k) => k,
                Err(e) => return api_error(e),
            };
            let input = match request.data.as_deref().map(hex_decode) {
                Some(Ok(input)) => input,
                Some(Err(e)) => return api_error(format!("Invalid input hex: {}", e)),
                None => return api_error("Missing input data".into()),
            };
            let currency = match request.compute_currency.as_deref() {
                None => static_storage::compute::Currency::Monero,
                Some(ticker) => match static_storage::compute::Currency::from_str(ticker) {
                    Some(c) => c,
                    None => {
                        return api_error(format!(
                            "Unsupported currency '{}' (accepted: xmr, dark, nav)",
                            ticker
                        ))
                    }
                },
            };

            match runner
                .submit_compute_request(&key_arr, input, currency)
                .await
            {
                Ok(request_id) => ApiResponse {
                    status: "ok".into(),
                    message: "Compute request submitted".into(),
                    request_id: Some(hex_encode(&request_id)),
                    ..Default::default()
                },
                Err(e) => api_error(format!("Compute failed: {}", e)),
            }
        }
        "compute_result" => {
            let request_id_hex = request.data.unwrap_or_default();
            let request_id = match hex_decode(&request_id_hex) {
                Ok(id) => id,
                Err(e) => return api_error(format!("Invalid request ID: {}", e)),
            };
            if request_id.len() != 32 {
                return api_error("request ID must be 32 bytes".into());
            }
            let mut id_arr = [0u8; 32];
            id_arr.copy_from_slice(&request_id);

            match runner.compute_result(&id_arr).await {
                Some(result) if result.success => ApiResponse {
                    status: "ok".into(),
                    message: "Compute complete".into(),
                    data: Some(hex_encode(&result.output_data)),
                    request_id: Some(hex_encode(&result.request_id)),
                    ..Default::default()
                },
                Some(result) => ApiResponse {
                    status: "ok".into(),
                    message: "failed".into(),
                    data: Some(result.error.unwrap_or_else(|| "unknown error".into())),
                    request_id: Some(hex_encode(&result.request_id)),
                    ..Default::default()
                },
                // No result yet: if the provider quoted a payment, surface
                // the payment details so the user can pay from their wallet.
                None => match runner.pending_payment(&id_arr).await {
                    Some(quote) => ApiResponse {
                        status: "pending".into(),
                        message: "payment required before execution".into(),
                        request_id: Some(hex_encode(&id_arr)),
                        payment_required: true,
                        payment_currency: Some(quote.currency.as_str().to_string()),
                        payment_address: Some(quote.address),
                        payment_amount: Some(quote.amount),
                        ..Default::default()
                    },
                    None => ApiResponse {
                        status: "pending".into(),
                        message: "Result not ready".into(),
                        request_id: Some(hex_encode(&id_arr)),
                        ..Default::default()
                    },
                },
            }
        }
        "compute_confirm" => {
            let request_id_hex = match request.request_id.as_deref() {
                Some(id) => id.to_string(),
                None => return api_error("Missing request_id".into()),
            };
            let tx_hash = match request.tx_hash.as_deref() {
                Some(hash) if !hash.is_empty() => hash.to_string(),
                _ => return api_error("Missing tx_hash".into()),
            };
            let request_id = match hex_decode(&request_id_hex) {
                Ok(id) => id,
                Err(e) => return api_error(format!("Invalid request ID: {}", e)),
            };
            if request_id.len() != 32 {
                return api_error("request ID must be 32 bytes".into());
            }
            let mut id_arr = [0u8; 32];
            id_arr.copy_from_slice(&request_id);

            match runner.confirm_compute_payment(&id_arr, tx_hash).await {
                Ok(()) => ApiResponse {
                    status: "ok".into(),
                    message: "Payment confirmation sent; waiting for blockchain confirmation"
                        .into(),
                    request_id: Some(hex_encode(&id_arr)),
                    ..Default::default()
                },
                Err(e) => api_error(format!("Compute confirm failed: {}", e)),
            }
        }
        _ => api_error("Unknown action".into()),
    }
}

/// Build an error response with all payload fields empty
fn api_error(message: String) -> ApiResponse {
    ApiResponse {
        status: "error".into(),
        message,
        ..Default::default()
    }
}

/// Parse a hex-encoded 32-byte content public key
fn parse_content_key(key_hex: Option<&str>) -> Result<[u8; 32], String> {
    let key_hex = key_hex.ok_or("Missing content_pub_key".to_string())?;
    let key_bytes = hex_decode(key_hex).map_err(|e| format!("Invalid content_pub_key: {}", e))?;
    if key_bytes.len() != 32 {
        return Err("content_pub_key must be 32 bytes".to_string());
    }
    let mut key_arr = [0u8; 32];
    key_arr.copy_from_slice(&key_bytes);
    Ok(key_arr)
}

// Simple hex helpers to avoid adding more dependencies
fn hex_encode(data: &[u8]) -> String {
    data.iter().map(|b| format!("{:02x}", b)).collect()
}

fn hex_decode(data: &str) -> Result<Vec<u8>> {
    // Reject odd-length input up front: slicing `data[i..i+2]` below
    // would panic on the trailing nibble.
    if data.len() % 2 != 0 {
        return Err(anyhow::anyhow!("Hex decode error: odd length"));
    }
    (0..data.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&data[i..i + 2], 16)
                .map_err(|e| anyhow::anyhow!("Hex decode error: {}", e))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hex_decode_odd_length_returns_err() {
        assert!(hex_decode("abc").is_err());
        assert!(hex_decode("0").is_err());
        assert!(hex_decode("12345").is_err());
        // Even-length inputs still work.
        assert_eq!(hex_decode("").unwrap(), Vec::<u8>::new());
        assert_eq!(hex_decode("00ff").unwrap(), vec![0x00, 0xff]);
    }

    #[test]
    fn test_hex_decode_invalid_chars_returns_err() {
        assert!(hex_decode("zz").is_err());
        assert!(hex_decode("0g").is_err());
    }

    #[test]
    fn test_verify_token_disabled_accepts_all() {
        assert!(verify_token(None, None));
        assert!(verify_token(Some("anything"), None));
    }

    #[test]
    fn test_verify_token_bad_token_rejected() {
        assert!(!verify_token(None, Some("secret")));
        assert!(!verify_token(Some("wrong"), Some("secret")));
        assert!(!verify_token(Some(""), Some("secret")));
    }

    #[test]
    fn test_verify_token_good_token_accepted() {
        assert!(verify_token(Some("secret"), Some("secret")));
    }

    #[test]
    fn test_api_request_token_serde_default() {
        // Old clients send no `token` field; it must default to None.
        let req: ApiRequest = serde_json::from_str(r#"{"action":"retrieve"}"#).unwrap();
        assert_eq!(req.token, None);
        let req: ApiRequest =
            serde_json::from_str(r#"{"action":"retrieve","token":"abc"}"#).unwrap();
        assert_eq!(req.token.as_deref(), Some("abc"));
    }

    #[test]
    fn test_serialize_response_never_panics() {
        let resp = ApiResponse {
            status: "ok".into(),
            message: "hi".into(),
            ..Default::default()
        };
        let bytes = serialize_response(&resp);
        let back: ApiResponse = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(back.status, "ok");
    }

    async fn test_runner() -> NodeRunner {
        let config = crate::NodeConfig::default();
        NodeRunner::new(config, [0x42u8; 16], static_sphinx::MixNode::new())
    }

    fn req_with_token(action: &str, token: Option<&str>) -> ApiRequest {
        ApiRequest {
            action: action.to_string(),
            data: None,
            content_pub_key: None,
            compute_currency: None,
            request_id: None,
            tx_hash: None,
            token: token.map(|s| s.to_string()),
        }
    }

    #[tokio::test]
    async fn test_handle_request_bad_token_rejected_before_action() {
        let runner = test_runner().await;
        // Unknown action would return "Unknown action" if auth passed;
        // with a bad token it must return unauthorized instead.
        let resp = handle_request(&runner, req_with_token("nope", None), Some("secret")).await;
        assert_eq!(resp.status, "error");
        assert!(resp.message.contains("unauthorized"));

        let resp = handle_request(
            &runner,
            req_with_token("nope", Some("wrong")),
            Some("secret"),
        )
        .await;
        assert_eq!(resp.status, "error");
        assert!(resp.message.contains("unauthorized"));
    }

    #[tokio::test]
    async fn test_handle_request_good_token_passes_auth() {
        let runner = test_runner().await;
        let resp = handle_request(
            &runner,
            req_with_token("nope", Some("secret")),
            Some("secret"),
        )
        .await;
        assert_eq!(resp.status, "error");
        assert_eq!(resp.message, "Unknown action");
    }

    #[tokio::test]
    async fn test_handle_request_no_auth_configured() {
        let runner = test_runner().await;
        let resp = handle_request(&runner, req_with_token("nope", None), None).await;
        assert_eq!(resp.message, "Unknown action");
    }
}
