# Static Network - Mainnet TODO

> Phase 0 audit (2026-09-18): items 1-4, 9 marked PARTIAL (see notes).
> Only Darkfi/Navio/Bluetooth/TEE are external blockers (Items 11, 17-stubs, 18).

## High Priority (MVP Blockers)

### 1. Tiered Bandwidth Modes ⚠️ PARTIAL (Phase 0)
- Add Low (50 KB/s), Standard (500 KB/s), High (5 MB/s) modes
- User picks tier at startup; switching requires restart (preserves deniability)
- Tier REMOVED from Handshake (Phase 0 privacy: peers infer from observed rate)
- Higher tiers get priority in tit-for-tat accounting — NOT DONE (`should_serve` is tier-agnostic AND-gate)
- Extend CoverTrafficConfig with a `mode` enum
- Per-node TokenBucket shaper DONE, `--no-cover` removed, Client mode added

### 2. Content Discovery via Hidden Services ⚠️ PARTIAL (Phase 0)
- Content ID IS the hidden service address
- Retriever builds Sphinx route to content ID, sends request
- Node holding the chunk responds via return route
- No DHT needed — the mixnet is the discovery mechanism
- Phase 0: try ALL known peers (hybrid-only, Sphinx-wrapped, no cache per Item 18)
- Seed-only sponsor-as-intro-point: NOT DONE (sponsor never stores manifest)

### 3. Chunk Repair Protocol ✅ DONE (Phase 1)
- When nodes leave, their chunks need re-replication
- Detect chunk loss via erasure coding threshold
- Trigger re-replication from remaining shards
- Leases with heartbeats already track node availability
- Phase 1 DONE: repair loop reconstructs (health from holder + swap registry +
  HostBuffer → HostBuffer reseed first, original `created_at` preserved →
  missing-chunk gossip (0x09, Sphinx-wrapped) → shard fetch via the standard
  retrieval protocol → `erasure_decode` reconstruction → capacity-gated store)
- Redistribution to new nodes rides the existing rotation barter loop
- Known limit: copy counts are local estimates (holder + swap registry), not
  network-wide quorum queries

### 4. Sybil Resistance for Seed-Only Nodes ⚠️ PARTIAL (Phase 0)
- Seed-only nodes must stake or prove reputation to prevent network flooding
- Stake = prepaid bytes to sponsor node
- Sponsor node validates stake before accepting hosting commitment
- Rate limit seed-only nodes to only sending seed packages (heartbeats/funding) when requested
- Phase 0 DONE: real Ed25519 prepay sigs + sender binding + 1h rate-limit + 5-slot cap + excess-capacity gate
- NOT DONE: stake >= content-size verification (sponsor never sees chunks to verify)

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

### 9. Seed-Only Node Mode with Prepayment ⚠️ PARTIAL (Phase 0)
- Node mode: Full, SeedOnly, BackupOnly, Client (NEW: relay-only, reduced cover)
- Seed-only node pays ONE sponsor node (avoids double-spend)
- Sponsor distributes chunks across its existing peer relationships — NOT DONE (sponsor stores nothing)
- 1:1 rule: `stored_bytes <= local_hosted + prepaid_hosted`
- Sponsor must have excess capacity (its own 1:1 satisfied with surplus)
- Prepayment recorded in accounting as `prepaid_bytes` (real sigs DONE)
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

### 12. Content Integrity Verification Tags ✅ DONE
- Hosting nodes verify they hold valid chunks without learning content
- Erasure coding verification tags
- Prevents nodes from claiming to store chunks they don't have
- Implementation: Merkle tree over the encrypted chunks (data + parity)
  built at publish time (`static-storage/src/integrity.rs`, blake3:
  leaf = blake3(data), node = blake3(l||r), Bitcoin-style odd-node
  duplication). The publisher stores the root + per-chunk proofs;
  `SwapProposal` carries `content_root` + `merkle_proof` and
  `validate_swap_proposal` verifies the offered chunk, rejecting garbage
  with `InvalidIntegrityTag` (= 4). Verified end-to-end at the transport
  layer (tampered chunks are never materialized by dormant backups).
  Limitations: the manifest chunk is intentionally unproven (stays with
  the publisher, never rotates); proofs live for the node's lifetime
  (bounded by published content); leaf/node hashes are not
  domain-separated yet (future hardening: 0x00/0x01 tag bytes).

### 13. Withdrawal/Exit Protocol for Seed-Only Nodes (Phase 2)
- When seed-only node stops funding, content retires via lease expiry
- Or content transfers to another sponsor
- Clear lifecycle: fund → host → withdraw/transfer → retire
- Phase 1 note: local lease refresh + remote heartbeat propagation (0x0A) are
  live; a full exit/transfer protocol (sponsor hand-off, signed release) is
  Phase 2

### 14. Chunk Integrity Verification ✅ DONE
- Implementation: segment-based challenge/response. Each 1 MiB chunk is
  divided into 4 KiB segments; publish-time `blake3(segment)` hashes are
  stored in the manifest (`ContentManifest::segment_hashes`) and ride
  inside the encrypted manifest — only nodes with the content public key
  can challenge. Any manifest holder can challenge any claimed holder via
  Sphinx bodies 0x07 (challenge) / 0x08 (response), fragmented like
  compute traffic — indistinguishable from cover traffic. Challenges are
  targeted at swap-accepted claims only (`SwapState.active_swaps`), so
  peers are never punished for chunks they never agreed to hold. Results
  feed `PeerCredit::successful_challenges`/`failed_challenges` via
  `AccountingState::record_challenge_success/failure`; `should_serve`
  hard-gates peers with >10 challenges and <50% success. Unanswered
  challenges (10 min timeout) count as failures. Full nodes only run the
  challenger loop (default 30 min, `--verification-enabled`/
  `--verification-interval`); dormant backups answer nothing (existing
  dormant gate). Encrypted chunks carry a 16-byte AEAD tail, so full
  chunks have 257 segments (last = 16 bytes); hash comparison is
  length-agnostic. Limitations: only swap-accepted claims are verifiable
  (retrieval-cached copies are not tracked); segment hashes grow the
  manifest ~32 KiB per chunk (MVP).

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

### 18. Privacy-Preserving Content Discovery (Research — EXTERNAL, do not implement)
- Current: Ask all known peers (Sphinx-wrapped, no cache)
- Problem: Doesn't scale past ~100 nodes efficiently
- Research needed: Find a discovery mechanism that:
  - Does NOT store chunk locations in memory (anti-seizure)
  - Does NOT leak timing information (constant-time)
  - Does NOT allow cache poisoning
  - Does NOT reveal network topology
  - Preserves the anonymity properties of the Sphinx mixnet
- Possible approaches: Oblivious RAM, private information retrieval,
  blind storage, or a novel protocol designed specifically for Static
- This is an open research problem — do NOT implement until solved

## Phase 0 Audit Notes (2026-09-18)

External blockers only (waiting outside codebase):
- Darkfi watcher: blocked on `darkfid` wallet RPC stabilization (`payment.rs` stubs)
- Navio watcher: blocked on `navcoind` RPC access/stabilization
- Bluetooth transport (Item 11): needs radio env + privacy-model change
- TEE/HE compute confidentiality: trust-based MVP intentional
- Item 18 discovery research above

Internal stubs fixed in Phase 0 (not external):
- Ed25519 handshake/prepay/swap/reconcile/gossip auth, tier removed from wire
- Per-node TokenBucket cover shaper, hybrid-only + HYBRID_MAX padding
- Publish erasure + manifest master/nonce, heartbeat sender, try-all retrieval
- Strict 1:1 real-chunk swaps, 0600 config, API token, Client mode, bounds

## Phase 1 Notes (2026-09-18) — Lifecycle Completeness & Scale Hardening

Implemented (all Sphinx-wrapped, no clear JSON, no new dependencies):
- Repair reconstruction (Item 3 ✅): health from holder + swap registry +
  HostBuffer; HostBuffer reseed first (original `created_at`, no barter clock
  reset); missing shards gossiped + fetched via the standard retrieval
  protocol; `erasure_decode` reconstruction; capacity-gated local store;
  redistribution rides rotation barter.
- Missing-chunk gossip (type 0x09, `static-storage/src/gossip.rs`): sent on
  `found:false` responses and by the repair loop; source-side dedup
  (10 min TTL, 1024 entries); host reseeds from HostBuffer and answers with
  a hybrid `ChunkResponse` via the reporter's return route.
- Heartbeat propagation (type 0x0A, `MSG_HEARTBEAT` wire framing): every
  30 min the owner sends heartbeats to swap-registered holders; holders
  refresh via token-checked `process_heartbeat_upsert` (bounded expiry,
  held-chunks-only). Known trade-off (approved): upsert trusts the
  Sphinx-wrapped heartbeat for chunks already held; future hardening =
  Ed25519 signature by the content owner.
- HostBuffer: already LRU-evicting (Phase 0); reseed/repair store helper
  preserves original `created_at`; buffer copies count toward repair
  recoverability.
- `fetch_shards()` extracted from `fetch_and_assemble` — returns
  `Vec<Option<EncryptedChunk>>` in manifest order (direct `erasure_decode`
  input); repair processes ≤1 content per 60s tick and skips while a user
  retrieval is in flight (shared ContentRetriever).

Phase 2 (deferred, per plan):
- True atomic 2-phase swap commit
- Withdrawal/exit + sponsor hand-off protocol (Item 13)
- Darkfi/Navio watchers (external blockers unchanged)
- Signed heartbeats (Ed25519 content-owner signature closing the upsert
  trade-off)
- Network-wide health quorum queries (current copy counts are local estimates)

## Phase 2 Hotfix Notes (2026-09-18) — Hybrid Packet Migration

All five Sphinx-body paths (retrieval, compute, verification, payment,
gossip/heartbeat) now emit hybrid (v1) packets only — the last classical
emitters are gone:
- `build_fragment_packets` (runner.rs) deleted; its 4 call sites migrated to
  `create_hybrid_payload_packets`: verification challenge + response,
  payment request, payment confirmation.
- Two additional classical emitters the audit missed, both in the compute
  path, also migrated: `build_request_packets`/`build_response_packets`
  (compute.rs) now delegate to the mesh hybrid helper with a `kem_lookup`
  param. Without them compute REQUESTS and RESPONSES were dropped too.
- Missing-KEM policy: hybrid builds fail at the source (the helper returns
  an error, no classical fallback). `submit_compute_request` and
  `confirm_compute_payment` bail with a clear error; responder paths warn
  and drop. Never send a packet known to be dropped in transit.
- Dead classical code removed: `create_anonymous_request` (retrieval.rs,
  zero callers) and `provider_mix_key` (replaced by a routing-table lookup
  that errors instead of defaulting to `[0u8; 32]`).
- Shared helpers: `NodeRunner::hybrid_kem_map` (routing-table KEM snapshot)
  and `single_peer_kem_lookup`; all 9 hybrid send paths use them.
- 3 new loopback-TCP tests through `handle_inbound` prove the migrated
  paths end to end: compute request/response (echo module),
  verification challenge/response (accounting credit), payment quote
  (pending_payment). Suite: 372 tests, release build zero warnings.
