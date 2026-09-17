# Static Network - Mainnet TODO

## High Priority (MVP Blockers)

### 1. Tiered Bandwidth Modes ✅ DONE
- Add Low (50 KB/s), Standard (500 KB/s), High (5 MB/s) modes
- User picks tier at startup; switching requires restart (preserves deniability)
- Higher tiers get priority in tit-for-tat accounting
- Extend CoverTrafficConfig with a `mode` enum
- Update accounting `should_serve()` to factor in tier

### 2. Content Discovery via Hidden Services ✅ DONE
- Content ID IS the hidden service address
- Retriever builds Sphinx route to content ID, sends request
- Node holding the chunk responds via return route
- No DHT needed — the mixnet is the discovery mechanism
- Seed-only nodes (or their sponsors) act as introduction points by holding manifests

### 3. Chunk Repair Protocol ✅ DONE
- When nodes leave, their chunks need re-replication
- Detect chunk loss via erasure coding threshold
- Trigger re-replication from remaining shards
- Leases with heartbeats already track node availability
- Add repair logic to the lease expiration loop

### 4. Sybil Resistance for Seed-Only Nodes ✅ DONE
- Seed-only nodes must stake or prove reputation to prevent network flooding
- Stake = prepaid bytes to sponsor node
- Sponsor node validates stake before accepting hosting commitment
- Rate limit seed-only nodes to only sending seed packages (heartbeats/funding) when requested

### 5. Network Partition Handling for Accounting ✅ DONE
- Local accounting may diverge during partitions
- On partition heal, nodes exchange accounting state
- Reconcile discrepancies (last-write-wins or timestamp-based)
- Document expected behavior during partition

## Medium Priority (Privacy Enhancements)

### 6. Hot Storage Rotation (Freenet-style) ✅ DONE
- Periodic re-encryption and re-distribution of a percentage of chunks per epoch
- Request-driven migration: nodes that request chunks cache copies
- Chunks naturally migrate toward demand (like Freenet)
- New encryption keys per rotation cycle (breaks linkability)
- No global "rotate everything" — just a percentage each cycle
- Improves deniability (no node holds same chunks long-term)
- Enables load balancing and self-healing

### 7. Post-Quantum Hybrid Crypto ✅ DONE
- Current: X25519 (NOT post-quantum), ChaCha20-Poly1305 (quantum-resistant)
- Add ML-KEM (Kyber) alongside X25519 for hybrid key agreement
- Security against both classical and quantum attackers
- Sphinx packet size increases (~800 bytes for Kyber public key)
- Version the Sphinx packet format to support both classical and hybrid
- Protects against "harvest now, decrypt later" attacks

### 8. Transport Abstraction Trait ✅ DONE
- Define a `Transport` trait in static-mesh
- TCP transport implements the trait (existing code)
- Enables future Bluetooth mesh, WebSocket, or other transports
- Each transport handles its own connection management
- Cover traffic rate enforcement stays in the trait

### 9. Seed-Only Node Mode with Prepayment ✅ DONE
- Node mode: Full, SeedOnly, BackupOnly
- Seed-only node pays ONE sponsor node (avoids double-spend)
- Sponsor distributes chunks across its existing peer relationships
- 1:1 rule: `stored_bytes <= local_hosted + prepaid_hosted`
- Sponsor must have excess capacity (its own 1:1 satisfied with surplus)
- Prepayment recorded in accounting as `prepaid_bytes`
- Seed-only nodes only send seed packages when requested (rate limited)

### 10. Backup-Only Node Mode with Health Checks ✅ DONE
- Dormant node that doesn't serve chunks
- Maintains heartbeats and monitors primary node
- Detects primary failure via missed heartbeats
- On failure: activates and begins serving
- On recovery: deactivates or takes over permanently
- Health check via routing layer (gossip-based)

## Long-Term Goals (Post-MVP)

### 11. Bluetooth Mesh Transport
- Requires transport abstraction (item 8)
- Sphinx packet fragmentation for low-MTU transports
- Modified privacy model (cover traffic infeasible on Bluetooth)
- Bridge mode: Bluetooth node connects to TCP node for cover traffic
- Store-and-forward instead of constant-rate

### 12. Content Integrity Verification Tags
- Hosting nodes verify they hold valid chunks without learning content
- Erasure coding verification tags
- Prevents nodes from claiming to store chunks they don't have

### 13. Withdrawal/Exit Protocol for Seed-Only Nodes
- When seed-only node stops funding, content retires via lease expiry
- Or content transfers to another sponsor
- Clear lifecycle: fund → host → withdraw/transfer → retire

### 14. Chunk Integrity Verification
- Nodes must prove they hold chunks without revealing content
- ZK proof of storage (Proof of Space-Time already exists)
- Extend to include content integrity checks

## Core Architecture (Future Discussions)

### 15. Compute Network & Dynamic Hidden Services ✅ DONE
- Current state: Static is an anonymous *storage* network. Compute stays local.
- Goal: Allow nodes to offer both storage AND compute (for higher fees/priority).
- Proposed mechanics:
  - Compute requests (WASM payloads + data) routed via Sphinx mixnet.
  - Sandbox execution (e.g., Wasmtime) on provider nodes.
  - Results returned via Sphinx SURBs (Single-Use Reply Blocks).
  - Compute providers earn higher accounting credit/tier.
  - Confidentiality options: Trusted Execution Environments (TEEs) or Homomorphic Encryption if the compute provider shouldn't see the data.
   - Routing logic for compute requests vs. storage requests.
- Implementation: WASM via `wasmtime` (fuel CPU cap + resource-limiter memory cap,
  no WASI). `ComputeRequest`/`ComputeResponse` are Sphinx-body messages
  (`static-storage/src/compute.rs`, type bytes 0x03/0x04), fragmented like chunk
  responses and reassembled at the destination — indistinguishable from cover
  traffic, never direct wire messages. Providers advertise
  `compute_enabled`/`compute_capacity` in handshakes (propagated via gossip);
  requesters route to the most capable compute peer. Modules are fetched through
  the normal retrieval protocol and cached. Fees: (input+output) x multiplier
  (default 10x storage credit). Results poll via the `compute_result` API
  action / `static-node compute --wait`. Confidentiality: trust-based for MVP;
  response/request types carry the metadata a TEE provider needs later.

## Technical Debt

### 16. StorageCapacity Reconciliation ✅ DONE
- Unified the dual `StorageCapacity` counters (runner + transport) into one shared `Arc`
- `reconcile()` snaps the counter to `ChunkHolder::total_bytes()` before swap decisions and every 60 s
- Publish, lease expiry, cache insert/evict paths maintain the counter incrementally
- Swap accept/reject paths store nothing, so need no counter updates

### 17. Cryptocurrency Payment for Compute ✅ DONE
- Replaced compute barter entirely: `fee_offer`, `fee_charged`,
  `fee_multiplier`, `MIN_COMPUTE_FEE` and the compute credit bookkeeping
  (`record_served`/`record_received` call sites) are gone. Storage barter
  (1:1 tit-for-tat) is unchanged.
- Providers set their own pricing via CLI (`--compute-price`,
  `--compute-currencies`, `--compute-confirmations`): per-execution flat
  rate, per-CPU-second and per-MB rates (worst-case quote uses the
  execution caps). All-zero pricing = free tier (immediate execution,
  no payment round-trip).
- Supported currencies: Monero (XMR), Darkfi (DARK), Navio (NAV). Wire
  types (`Currency`, `PaymentRequest`, `PaymentConfirmation`, type bytes
  0x05/0x06) live in `static-storage/src/compute.rs` as Sphinx-body
  messages, indistinguishable from cover traffic.
- Provider generates a fresh receive address per request (`create_address`
  via monero-wallet-rpc) and watches the blockchain through daemon RPC
  (`MoneroWatcher` reference implementation; Darkfi/Navio are stubs
  returning `UnsupportedCurrency` until their RPC APIs stabilize).
- Flow: `ComputeRequest` -> provider quotes `PaymentRequest` (0x05) ->
  requester pays from their own wallet (outside Static) and sends
  `PaymentConfirmation` (0x06) via a fresh 1-hop Sphinx message ->
  provider's payment-watch loop (15 s tick) verifies confirmations
  on-chain -> executes -> `ComputeResponse`. Unpaid quotes time out after
  1 h with a courtesy error response carrying the original quote.
- Requester-side API: `compute` returns a request ID; `compute_result`
  surfaces `payment_required`/`payment_currency`/`payment_address`/
  `payment_amount` while awaiting payment; new `compute_confirm` action
  and CLI `compute-confirm` / `compute-result` subcommands.
