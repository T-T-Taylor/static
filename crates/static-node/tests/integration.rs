use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use static_mesh::transport::{
    TransportState, InboundMessage, create_transport_state,
    start_listener, connect_to_peer, send_sphinx,
};
use static_storage::swap::{StorageCapacity, SwapState};
use static_mesh::retrieval::{create_anonymous_request_hybrid, RetrievalManager};
use static_mesh::wire::WireMessage;
use static_mesh::CoverTrafficConfig;
use static_sphinx::{
    MixNode, Route, RouteHop, random_node_id,
};
use rand::RngCore;

async fn setup_node(port: u16) -> (Arc<TransportState>, mpsc::Receiver<InboundMessage>) {
    let node_id = random_node_id();
    let mix_node = MixNode::new();
    let cover_config = CoverTrafficConfig { enabled: false, ..Default::default() };
    let capacity = Arc::new(tokio::sync::Mutex::new(StorageCapacity::new(
        10 * 1024 * 1024 * 1024,
    )));
    let (state, rx) = create_transport_state(
        node_id,
        mix_node,
        cover_config,
        capacity,
        Arc::new(tokio::sync::Mutex::new(SwapState::new())),
        None,
    );

    let addr: SocketAddr = format!("127.0.0.1:{}", port).parse().unwrap();
    let state_clone = state.clone();
    tokio::spawn(async move {
        let _ = start_listener(addr, state_clone).await;
    });

    tokio::time::sleep(Duration::from_millis(100)).await;
    (state, rx)
}

#[tokio::test]
async fn test_anonymous_retrieval_over_tcp() {
    // Setup two nodes
    let (node_a, _rx_a) = setup_node(9005).await;
    let (node_b, mut rx_b) = setup_node(9006).await;

    // Connect Node B to Node A
    let addr_a: SocketAddr = "127.0.0.1:9005".parse().unwrap();
    connect_to_peer(addr_a, node_b.clone()).await.unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Add a chunk to Node A
    let mut chunk_id = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut chunk_id);
    let chunk_data = b"integration test chunk data".to_vec();
    {
        let mut holder = node_a.chunk_holder.lock().await;
        holder.add_chunk(chunk_id, chunk_data.clone(), [0u8; 32]);
    }

    // Get node info for routing (hybrid-only: A must advertise KEM key)
    let a_pubkey = node_a.mix_node.lock().await.public_key;
    let a_kem = node_a.kem.lock().await.public_bytes();
    let a_node_id = node_a.node_id;
    let b_node_id = node_b.node_id;
    let b_pubkey = node_b.mix_node.lock().await.public_key;

    // Node B builds hybrid forward route to Node A
    let hybrid_forward = static_sphinx::HybridRoute {
        hops: vec![static_sphinx::HybridRouteHop {
            node_id: a_node_id,
            classical_public_key: a_pubkey,
            kem_public_key: a_kem,
        }],
        destination: a_node_id,
    };

    // Node B builds return route to itself
    let return_route = Route {
        hops: vec![RouteHop { public_key: b_pubkey, node_id: b_node_id }],
        destination: b_node_id,
    };

    // Create anonymous request (hybrid v1 — classical rejected since Phase 0)
    let request_packet = create_anonymous_request_hybrid(chunk_id, &return_route, &hybrid_forward).unwrap();

    // Send request to Node A
    send_sphinx(&node_b, a_node_id, request_packet).await.unwrap();

    // Wait for response to arrive at Node B
    let mut manager = RetrievalManager::new();
    manager.start_retrieval(chunk_id);

    let timeout = tokio::time::sleep(Duration::from_secs(5));
    tokio::pin!(timeout);

    loop {
        tokio::select! {
            Some(inbound) = rx_b.recv() => {
                if let WireMessage::Sphinx(pkt) = inbound.message {
                    match manager.process_fragment(&pkt.body) {
                        Ok(Some(response)) => {
                            assert!(response.found);
                            assert_eq!(response.chunk_data, chunk_data);
                            return;
                        }
                        Ok(None) => {}
                        Err(_) => {}
                    }
                }
            }
            _ = &mut timeout => {
                panic!("Timeout waiting for response");
            }
        }
    }
}
