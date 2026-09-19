# Static

A privacy network where traffic is indistinguishable from noise.

Static is a pure darknet — there is no clearnet exit, no central directory, and no blockchain for storage. It provides anonymous, censorship-resistant storage and compute by wrapping all communication in a post-quantum Sphinx mixnet with constant-rate cover traffic.

## Status

Pre-alpha. The protocol is feature-complete and undergoing hardening.

## Features

**Anonymity & Privacy**
- **Post-Quantum Hybrid Sphinx**: All packets use X25519 + ML-KEM-768 (Kyber) hybrid key agreement. Quantum-resistant against "harvest now, decrypt later" attacks.
- **Constant-Rate Cover Traffic**: A per-node token bucket shaper queues real traffic and fills remaining bandwidth with cover packets. An observer cannot distinguish real traffic from cover traffic.
- **Hidden Service Discovery**: Content IDs are derived from X25519 public keys (like Tor .onion addresses). Content is hidden by default; only those who know the public key can find it.
- **No Metadata Leakage**: Bandwidth tiers are not transmitted in handshakes. All wire messages are padded to a uniform size.
- **Transport Abstraction**: The network layer is abstracted via a `Transport` trait. TCP is implemented, with Bluetooth mesh and WebSocket planned.

**Storage & Lifecycle**
- **1:1 Atomic Swap Barter**: Nodes exchange storage capacity via a 2-phase commit atomic swap protocol. The 1:1 ratio is cryptographically enforced and crash-proof.
- **Erasure Coding**: Content is split into 1 MiB chunks and erasure-coded (10 data + 5 parity shards). Content survives the loss of up to 5 nodes.
- **Self-Healing Repair**: A background loop checks content health and reconstructs missing shards from the erasure-coded parity data.
- **Freenet-Style Hot Rotation**: 10% of chunks migrate to different nodes every 24 hours. No node holds the same chunks indefinitely, improving deniability and load balancing.
- **Request-Driven Caching**: Retrieved chunks are cached locally, pushing popular content to the edges of the network.

**Compute & Payment**
- **WASM Compute Execution**: Nodes can execute WASM modules in a sandboxed `wasmtime` environment with strict CPU and memory limits.
- **Cryptocurrency Prepayment**: Compute providers are paid in Monero (XMR), Darkfi (DARK), or Navio (NAV) via a prepayment model. Providers generate a new receive address for each request and watch the blockchain via view keys.
- **Provider-Set Pricing**: Providers set their own prices for compute resources.

**Economics & Resilience**
- **Local P2P Accounting**: No blockchain for storage. Each node tracks its own barter credits and peer trust locally.
- **Chunk Integrity Verification**: Nodes periodically challenge their peers to prove they still hold the chunk data they claim to store. Failed challenges reduce trust and lead to deprioritization.
- **Network Partition Handling**: Accounting states are reconciled using last-write-wins when partitioned peers reconnect.
- **Sybil Resistance**: Seed-only nodes must stake prepayment and are rate-limited.

**Node Modes**
- **Full**: Hosts, retrieves, rotates, challenges, runs cover traffic.
- **Seed-only**: Pre-pays a sponsor to host content on its behalf. Rate-limited, Sybil-resistant.
- **Backup-only**: Remains dormant until the primary content owner fails, then activates.
- **Client**: Relay-only at a reduced bandwidth rate (like a Tor client).

## Getting Started

### Prerequisites
- Rust (stable)
- A Monero daemon (for compute payments, optional)

### Build
```bash
cargo build --release -p static-node

Run

# Start a full node
./target/release/static-node start

# Start a low-bandwidth client node
./target/release/static-node --tier low start

# Start a seed-only node
./target/release/static-node --mode seed --sponsor 127.0.0.1:9001 start

CLI Commands
start: Start the node and connect to the network.
status: Show node configuration and status.
gen-id: Generate a new node identity.
info: Show architecture and version info.
publish <file>: Publish a file to the network.
retrieve <key> <output>: Retrieve a file from the network using its content public key.
compute <module_key> <input>: Submit a WASM compute request.
Architecture
The project is a Rust workspace consisting of 6 crates:

static-crypto: Crypto primitives (X25519, ChaCha20-Poly1305, ML-KEM, Ed25519)
static-sphinx: Sphinx packet format, SURBs, multi-hop routing
static-storage: Chunk encryption, erasure coding, swap barter, lease/heartbeat, retrieval, hidden service, repair, verification, compute, gossip
static-accounting: Proof of Space-Time, tit-for-tat, per-peer credit, Sybil resistance
static-mesh: Cover traffic, wire protocol, TCP transport (abstracted), routing tables, gossip, anonymous retrieval, fragmentation
static-node: Node lifecycle, config persistence, async runner, local API server, CLI, WASM compute, blockchain payment

Testing
The network is extensively tested with 393+ tests across all crates.

cargo test --workspace

License
GNU Affero General Public License v3.0 (AGPL-3.0-or-later)

Contributing
See CONTRIBUTING.md for privacy and OpSec guidelines for contributors.

See AGENTS.md for guidelines for AI agents working on this codebase.
