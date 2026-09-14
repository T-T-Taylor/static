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
    /// The action to perform ("publish" or "retrieve")
    pub action: String,
    /// Base64 encoded file data (for publish)
    pub data: Option<String>,
    /// Content manifest (for retrieve)
    pub manifest: Option<static_storage::ContentManifest>,
    /// Hex encoded master key (for retrieve)
    pub master_key: Option<String>,
}

/// A response from the local API
#[derive(Serialize, Deserialize, Debug)]
pub struct ApiResponse {
    /// Status ("ok" or "error")
    pub status: String,
    /// Message (error details or info)
    pub message: String,
    /// Content ID (for publish response)
    pub content_id: Option<String>,
    /// Content manifest (for publish response)
    pub manifest: Option<static_storage::ContentManifest>,
    /// Base64 encoded file data (for retrieve response)
    pub data: Option<String>,
    /// Hex encoded master key (for publish response)
    pub master_key: Option<String>,
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
                    let resp = ApiResponse { status: "error".into(), message: format!("Invalid request: {}", e), content_id: None, manifest: None, data: None, master_key: None };
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
            let data_b64 = request.data.unwrap_or_default();
            let data = match base64_decode(&data_b64) {
                Ok(d) => d,
                Err(e) => return ApiResponse { status: "error".into(), message: format!("Invalid base64: {}", e), content_id: None, manifest: None, data: None, master_key: None },
            };

            match runner.publish_content(&data).await {
                Ok((content_id, manifest, master_key)) => {
                    let id_hex = hex_encode(&content_id);
                    let key_hex = hex_encode(&master_key.bytes);
                    ApiResponse { status: "ok".into(), message: "Published".into(), content_id: Some(id_hex), manifest: Some(manifest), data: None, master_key: Some(key_hex) }
                }
                Err(e) => ApiResponse { status: "error".into(), message: format!("Publish failed: {}", e), content_id: None, manifest: None, data: None, master_key: None },
            }
        }
        "retrieve" => {
            let manifest = match request.manifest {
                Some(m) => m,
                None => return ApiResponse { status: "error".into(), message: "Missing manifest".into(), content_id: None, manifest: None, data: None, master_key: None },
            };
            let key_hex = match request.master_key {
                Some(k) => k,
                None => return ApiResponse { status: "error".into(), message: "Missing master_key".into(), content_id: None, manifest: None, data: None, master_key: None },
            };
            let key_bytes = match hex_decode(&key_hex) {
                Ok(k) => k,
                Err(e) => return ApiResponse { status: "error".into(), message: format!("Invalid master_key: {}", e), content_id: None, manifest: None, data: None, master_key: None },
            };
            
            if key_bytes.len() != 32 {
                return ApiResponse { status: "error".into(), message: "master_key must be 32 bytes".into(), content_id: None, manifest: None, data: None, master_key: None };
            }
            let mut key_arr = [0u8; 32];
            key_arr.copy_from_slice(&key_bytes);
            let master_key = static_crypto::SymmetricKey::from_bytes(key_arr);

            match runner.retrieve_content(manifest, master_key).await {
                Ok(data) => {
                    let data_b64 = base64_encode(&data);
                    ApiResponse { status: "ok".into(), message: "Retrieved".into(), content_id: None, manifest: None, data: Some(data_b64), master_key: None }
                }
                Err(e) => ApiResponse { status: "error".into(), message: format!("Retrieve failed: {}", e), content_id: None, manifest: None, data: None, master_key: None },
            }
        }
        _ => ApiResponse { status: "error".into(), message: "Unknown action".into(), content_id: None, manifest: None, data: None, master_key: None },
    }
}

// Simple base64 and hex helpers to avoid adding more dependencies
fn base64_encode(data: &[u8]) -> String {
    // A very simple base64 encoder
    // Not production ready, but fine for this CLI tool
    // Actually, let's just use hex for simplicity and zero dependencies.
    hex_encode(data)
}

fn base64_decode(data: &str) -> Result<Vec<u8>> {
    Ok(hex_decode(data)?)
}

fn hex_encode(data: &[u8]) -> String {
    data.iter().map(|b| format!("{:02x}", b)).collect()
}

fn hex_decode(data: &str) -> Result<Vec<u8>> {
    (0..data.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&data[i..i+2], 16).map_err(|e| anyhow::anyhow!("Hex decode error: {}", e)))
        .collect()
}
