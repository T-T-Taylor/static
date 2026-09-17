//! Local API server for the Static node
//!
//! Provides a simple JSON API over TCP for the CLI to interact
//! with the running node (e.g., publishing and retrieving content).

use anyhow::Result;
use serde::{Serialize, Deserialize};
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use crate::runner::NodeRunner;

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

/// Start the local API server
pub async fn start_api_server(runner: Arc<NodeRunner>, addr: String) -> Result<()> {
    let listener = TcpListener::bind(&addr).await?;
    tracing::info!("Local API listening on {}", addr);

    loop {
        let (mut socket, _) = listener.accept().await?;
        let runner = runner.clone();

        tokio::spawn(async move {
            let mut buf = vec![0u8; 1024 * 1024]; // 1MB buffer for file data
            let n = match socket.read(&mut buf).await {
                Ok(n) if n > 0 => n,
                _ => return,
            };

            let request: ApiRequest = match serde_json::from_slice(&buf[..n]) {
                Ok(r) => r,
                Err(e) => {
                    let resp = ApiResponse {
                        status: "error".into(),
                        message: format!("Invalid request: {}", e),
                        ..Default::default()
                    };
                    let _ = socket.write_all(&serde_json::to_vec(&resp).unwrap()).await;
                    return;
                }
            };

            let response = handle_request(&runner, request).await;
            let _ = socket.write_all(&serde_json::to_vec(&response).unwrap()).await;
        });
    }
}

async fn handle_request(runner: &NodeRunner, request: ApiRequest) -> ApiResponse {
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
                Some(ticker) => {
                    match static_storage::compute::Currency::from_str(ticker) {
                        Some(c) => c,
                        None => {
                            return api_error(format!(
                                "Unsupported currency '{}' (accepted: xmr, dark, nav)",
                                ticker
                            ))
                        }
                    }
                }
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
                    message: "Payment confirmation sent; waiting for blockchain confirmation".into(),
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
    (0..data.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&data[i..i+2], 16).map_err(|e| anyhow::anyhow!("Hex decode error: {}", e)))
        .collect()
}
