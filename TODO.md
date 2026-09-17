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

### 5. Network Partition Handling for Accounting
- Local accounting may diverge during partitions
- On partition heal, nodes exchange accounting state
- Reconcile discrepancies (last-write-wins or timestamp-based)
- Document expected behavior during partition

## Medium Priority (Privacy Enhancements)

### 6. Hot Storage Rotation (Freenet-style)
- Periodic re-encryption and re-distribution of a percentage of chunks per epoch
- Request-driven migration: nodes that request chunks cache copies
- Chunks naturally migrate toward demand (like Freenet)
- New encryption keys per rotation cycle (breaks linkability)
- No global "rotate everything" — just a percentage each cycle
- Improves deniability (no node holds same chunks long-term)
- Enables load balancing and self-healing

### 7. Post-Quantum Hybrid Crypto
- Current: X25519 (NOT post-quantum), ChaCha20-Poly1305 (quantum-resistant)
- Add ML-KEM (Kyber) alongside X25519 for hybrid key agreement
- Security against both classical and quantum attackers
- Sphinx packet size increases (~800 bytes for Kyber public key)
- Version the Sphinx packet format to support both classical and hybrid
- Protects against "harvest now, decrypt later" attacks

### 8. Transport Abstraction Trait
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

### 10. Backup-Only Node Mode with Health Checks
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

### 15. Compute Network & Dynamic Hidden Services
- Current state: Static is an anonymous *storage* network. Compute stays local.
- Goal: Allow nodes to offer both storage AND compute (for higher fees/priority).
- Proposed mechanics:
  - Compute requests (WASM payloads + data) routed via Sphinx mixnet.
  - Sandbox execution (e.g., Wasmtime) on provider nodes.
  - Results returned via Sphinx SURBs (Single-Use Reply Blocks).
  - Compute providers earn higher accounting credit/tier.
  - Confidentiality options: Trusted Execution Environments (TEEs) or Homomorphic Encryption if the compute provider shouldn't see the data.
  - Routing logic for compute requests vs. storage requests.
