# AI Agent Guidelines

This project was built with significant assistance from AI agents (OpenCode, Claude, GPT-4). 
Future agents working on this codebase should follow these guidelines:

## Core Constraints
- `#![forbid(unsafe_code)]` — no unsafe Rust, ever
- `#![deny(missing_docs)]` — all public items must have doc comments
- No new crate dependencies without explicit approval
- Never hold two `Mutex` guards simultaneously (deadlock prevention)
- All network communication must be Sphinx-wrapped (no clear-text wire messages for sensitive data)
- All Sphinx packets are hybrid (X25519 + ML-KEM-768) — no classical fallback

## Architecture Overview
- `static-crypto` — Crypto primitives (X25519, ChaCha20-Poly1305, ML-KEM, Ed25519)
- `static-sphinx` — Sphinx packet format, SURBs, multi-hop routing
- `static-storage` — Chunk encryption, erasure coding, swap barter, lease/heartbeat, retrieval, hidden service, repair, verification, compute, gossip
- `static-accounting` — Proof of Space-Time, tit-for-tat, per-peer credit, Sybil resistance
- `static-mesh` — Cover traffic, wire protocol, TCP transport (abstracted), routing tables, gossip, anonymous retrieval, fragmentation
- `static-node` — Node lifecycle, config persistence, async runner, local API server, CLI, WASM compute, blockchain payment

## Key Design Decisions
- Content ID = blake3(public_key) — acts as a .onion address
- 1:1 storage barter with 2-phase atomic swaps
- Compute uses cryptocurrency prepayment (Monero/Darkfi/Navio)
- Cover traffic uses a per-node token bucket shaper
- Heartbeats are Ed25519-signed by the content owner
- Chunk integrity verified via segment challenges
- Content integrity verified via Merkle proofs on swap

## Testing
- 402+ tests across 6 crates
- Run `cargo test --workspace` after every change
- Zero warnings required: `cargo build --release -p static-node`
- Phase 7 wire protocol: Handshake (Hello/Welcome/AuthIdentity, encrypted,
  padded) + Sphinx only; all maintenance Sphinx-wrapped (body bytes
  0x12-0x19); MIN_HOPS=3 routes; AEAD bodies; fixed 5440-byte KEM block;
  no backward compatibility with Phase 6.
