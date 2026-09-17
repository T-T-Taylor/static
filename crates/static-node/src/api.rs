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
    /// The action to perform ("publish", "retrieve", "compute" or
    /// "compute_result")
    pub action: String,
    /// Hex encoded file data (for publish), input data (for compute), or
    /// request ID (for compute_result)
    pub data: Option<String>,
    /// Hex encoded content public key (for retrieve/compute)
    pub content_pub_key: Option<String>,
    /// Fee offer in bytes of storage credit (for compute)
    pub compute_fee: Option<u64>,
}

/// A response from the local API
#[derive(Serialize, Deserialize, Debug)]
pub struct ApiResponse {
    /// Status ("ok", "pending", or "error")
    pub status: String,
    /// Message (error details or info)
    pub message: String,
    /// Content ID (for publish response)
    pub content_id: Option<String>,
    /// Content manifest (for publish response)
    pub manifest: Option<static_storage::ContentManifest>,
    /// Hex encoded file/output data (for retrieve/compute_result response)
    pub data: Option<String>,
    /// Hex encoded content public key (for publish response)
    pub content_pub_key: Option<String>,
    /// Compute request ID (for compute response)
    pub request_id: Option<String>,
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
                    let resp = ApiResponse { status: "error".into(), message: format!("Invalid request: {}", e), content_id: None, manifest: None, data: None, content_pub_key: None, request_id: None };
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
                    ApiResponse { status: "ok".into(), message: "Published".into(), content_id: Some(id_hex), manifest: Some(manifest), data: None, content_pub_key: Some(key_hex), request_id: None }
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
                    ApiResponse { status: "ok".into(), message: "Retrieved".into(), content_id: None, manifest: None, data: Some(data_hex), content_pub_key: None, request_id: None }
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
            let fee = request.compute_fee.unwrap_or(10240);

            match runner
                .submit_compute_request(&key_arr, input, fee)
                .await
            {
                Ok(request_id) => ApiResponse {
                    status: "ok".into(),
                    message: "Compute request submitted".into(),
                    content_id: None,
                    manifest: None,
                    data: None,
                    content_pub_key: None,
                    request_id: Some(hex_encode(&request_id)),
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
                    content_id: None,
                    manifest: None,
                    data: Some(hex_encode(&result.output_data)),
                    content_pub_key: None,
                    request_id: Some(hex_encode(&result.request_id)),
                },
                Some(result) => ApiResponse {
                    status: "ok".into(),
                    message: "failed".into(),
                    content_id: None,
                    manifest: None,
                    data: Some(result.error.unwrap_or_else(|| "unknown error".into())),
                    content_pub_key: None,
                    request_id: Some(hex_encode(&result.request_id)),
                },
                None => ApiResponse {
                    status: "pending".into(),
                    message: "Result not ready".into(),
                    content_id: None,
                    manifest: None,
                    data: None,
                    content_pub_key: None,
                    request_id: Some(hex_encode(&id_arr)),
                },
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
        content_id: None,
        manifest: None,
        data: None,
        content_pub_key: None,
        request_id: None,
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
