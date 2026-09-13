# Static

> A pure darknet where traffic is indistinguishable from noise.

## What Is Static?

Static is a privacy-first overlay network designed to make surveillance impossible by architectural design, not by policy. Every packet on the network looks like random bytes. Every node sends and receives at a constant rate, always. There is no metadata to collect, no timing to correlate, and no logs that contain useful information even if a node is seized.

The name comes from radio static: constant, uniform noise. An adversary observing the network sees static. They cannot distinguish signal from noise. They cannot tell which nodes are hosting content, which are relaying, or which are idle. The network always runs hot, there is no such thing as idle traffic because cover traffic fills every gap.

## Why Static Exists

The current internet has fundamental privacy flaws:

- IP addresses are identity. Your ISP can log every destination you connect to. Even with HTTPS and encrypted DNS, the destination IP reveals where you are going.
- ISPs are centralized choke points. They sit between you and everything. They can throttle, surveil, block, and report.
- Existing darknets leak. Tor hidden services can be located through traffic correlation. I2P has similar weaknesses under sustained observation. Both leak timing and volume metadata.
- Hosting dark services is dangerous. The person running a hidden service has an IP address, and that IP can be found. The threat of seizure limits what people are willing to host.
- "We do not log" is a promise, not a guarantee. Every privacy network that relies on node operators choosing not to log is one breach away from disaster. Static makes useful logging impossible by architecture.

Static is designed to fix these problems at the protocol level. Privacy is not a setting, it is a property of the network.

## Core Design Principles

### 1. Architectural Privacy, Not Policy Privacy

Privacy comes from mathematics and protocol design, not from trusting node operators. A Static node operator who wants to log everything cannot produce useful logs because:

- Sphinx packets are indistinguishable from random bytes at every layer
- Mixnodes batch, shuffle, and re-encrypt, they cannot link inputs to outputs
- Cover traffic fills the network at a constant rate, real traffic is hidden in noise
- Nodes do not maintain persistent storage beyond what is needed for the current batch

### 2. Constant-Rate Traffic - Always Hot

Every node sends and receives at a fixed rate regardless of actual activity. Whether a node is serving 100 requests per second or zero, its traffic looks identical. This eliminates:

- Timing analysis (no burst patterns to correlate)
- Volume analysis (no "this node sent more data at 3pm" signals)
- Idle detection (no way to tell if a node is actively serving or just humming)
- Uptime/offline detection for services (because content is distributed, not centralized)

Plausible deniability is not an excuse, it is the architectural reality. Every node is always doing something because the cover traffic never stops.

### 3. No Clearnet - Pure Darknet

Static does not connect to the regular internet. There are no exit nodes. There are no gateways. All services are hidden services addressed by cryptographic keys, not IP addresses.

If you need to access clearnet content, that is a different system. Static is the antidote to the clearnet flaws, not a bridge to it.

### 4. Distributed Storage with Owner Control

Content is encrypted, split into uniform-size chunks, and distributed across the network using a reciprocal storage swap model:

- 1:1 barter: To host N GB, you must contribute N GB of storage to the network
- Uniform chunks: Every chunk is the same size and encrypted, no node can identify what it is storing
- Swapped storage: Your node holds N GB of chunks, but most belong to other people, you have swapped
- Owner control: Leases with encrypted heartbeats allow content owners to turn services on and off
- Seed nodes: Content owners can run multiple nodes (some seed-only) for redundancy, if one node is seized, the content persists
- Erasure coding: Chunks are Reed-Solomon encoded, any K of K+M chunks reconstructs the file, providing resilience without full replication

### 5. No Single Server to Find

There is no server with an IP address that can be located. Content is distributed across many nodes, none of which know what they hold. To take down a service, an adversary would need to:

1. Identify which nodes hold the content (impossible remotely, chunks are encrypted and uniform)
2. Seize enough nodes simultaneously to exceed the erasure coding threshold (requires coordinating physical raids across multiple jurisdictions)
3. Break the encryption on the seized chunks (practically infeasible)

Even if some nodes are seized, the content owner seed nodes (which look identical to every other node) keep the content alive. There is no offline server timing signature because the content is distributed.

### 6. RAM Safety - Never Full File in Memory

Files are never decrypted in full. Decryption uses a streaming key derivation chain:

- Each chunk decryption key is derived from the previous chunk key via a one-way function (HKDF)
- Only one chunk is ever in RAM at a time
- After a chunk is consumed, it is zeroized from memory before the next chunk is decrypted
- A RAM dump at any moment reveals only the current chunk, not the full file
- Master keys are split via Shamir Secret Sharing across nodes and assembled momentarily only when needed

### 7. No Blockchain - Local Peer-to-Peer Accounting

Static has no blockchain. There is no global ledger, no chain to store, no consensus to participate in. Economic accounting is local:

- Each node tracks its own contribution ratios (storage served vs. storage used)
- Proof of Space-Time challenges verify that nodes actually store what they claim
- Tit-for-tat credit system (inspired by BitTorrent), serve to others, get priority in return
- Freeloaders are deprioritized locally without any global authority

This keeps the system decentralized and removes the chain as both an attack surface and a metadata source.

### 8. Adaptive Replication - Content Migrates to Demand

When content is frequently requested from a region, chunks replicate to nodes in that region, reducing latency without exposing the hoster. This works because:

- Each node only sees local request volume (the mixnet hides global patterns)
- Nodes cache locally in response to local demand
- No node knows whether a chunk is original or a cached replica
- The content owner identity and location remain hidden

## Architecture Overview

    +-----------------------------------------------------------+
    |                    Application Layer                      |
    |    Hidden services, file hosting, messaging, etc.         |
    |    Addressed by cryptographic keys, not IP addresses      |
    +-----------------------------------------------------------+
    |                    Service Layer                          |
    |    Content-addressed storage retrieval                    |
    |    Requests indistinguishable from cover traffic          |
    +-----------------------------------------------------------+
    |                    Storage Layer                          |
    |    Encrypted uniform chunks (1 MiB)                       |
    |    Erasure coding (K=10, M=5 by default)                  |
    |    1:1 storage swap barter                                |
    |    Leases with encrypted heartbeats                       |
    |    Seed nodes for redundancy                              |
    +-----------------------------------------------------------+
    |                    Mix Layer                              |
    |    Sphinx packets (indistinguishable from random bytes)   |
    |    Batch, shuffle, forward                                |
    |    No persistent storage, no useful logs                  |
    +-----------------------------------------------------------+
    |                   Transport Layer                         |
    |    Constant-rate cover traffic                            |
    |    Every node always hot                                  |
    |    Real traffic hidden in noise                           |
    +-----------------------------------------------------------+
    |                   Physical Layer                          |
    |    Mesh (wifi/fiber) or overlay tunnels                   |
    |    IP exists but carries no meaningful identity           |
    +-----------------------------------------------------------+

## Crate Structure

| Crate | Responsibility |
|-------|---------------|
| static-crypto | Shared crypto: key derivation, encryption, Shamir Secret Sharing, zeroization |
| static-sphinx | Sphinx packet format: construction, per-layer encryption, replay detection |
| static-mesh | Overlay/mesh transport: peer discovery, connection management |
| static-storage | Chunk encryption, erasure coding, storage swap, leases, heartbeats |
| static-accounting | Local credit tracking, Proof of Space-Time challenges, tit-for-tat |
| static-node | Main binary: ties everything together, CLI interface |

## What Static Is Not

- Not an ISP replacement, it does not run physical infrastructure, it runs as an overlay
- Not a clearnet proxy, there are no exit nodes, it does not let you access the regular internet
- Not a blockchain, there is no ledger, no tokens, no consensus, no chain
- Not Tor/I2P, no exit nodes, constant-rate traffic, distributed hosting, no single server to locate
- Not a Filecoin/Storj competitor, no commercial storage market, no payment, barter-based

## What Static Is

- A pure darknet where every packet looks like noise
- A network where hosting is deniable and seizure-resistant
- A system where privacy comes from protocol design, not trust
- A barter-based storage network with owner control
- A constant-rate mixnet that defeats traffic analysis by construction

## Goals

1. Untraceable communication. An adversary observing the network cannot determine who is talking to whom, what is being sent, where content is hosted, or whether a node is active or idle.

2. Seizure-resistant hosting. People can host hidden services from their homes with confidence that their identity cannot be determined through network analysis. Content persists even if individual nodes are seized.

3. Architectural deniability. Every node operator can truthfully say "I do not know what I am storing or relaying" and this is true by design, not by choice.

4. No useful logs. Even if a node is seized and forensically analyzed, the data on disk is encrypted chunks (unidentifiable), Sphinx packets in transit (random bytes), and local accounting data (no link to content or other nodes).

5. Plausible deniability for all participants. Because the network always runs hot, there is no behavioral difference between a node serving 1000 requests and a node serving zero. The cover traffic is the alibi.

6. Owner sovereignty. Content owners can turn their services on and off, run seed nodes for redundancy, and revoke content, all without revealing which nodes are theirs.

## Non-Goals

- High throughput / low latency (privacy is prioritized over speed)
- Clearnet access (Static is a darknet, not a proxy)
- Real-time applications (voice/video), the mixnet adds seconds to minutes of latency
- Mass adoption optimization, the design assumes users who accept the tradeoffs
- Mobile support as a full node (cover traffic bandwidth is too high for mobile)

## License

AGPL-3.0-or-later. Static is copyleft to ensure derivatives remain open.

## Status

Pre-alpha. Nothing works yet. This is a design document and scaffold.

The architecture is specified. The crates are scaffolded. The next steps are implementing the Sphinx packet format and the storage swap protocol.

## Development

Build the workspace:

    cargo build --release

Run the node binary (does nothing useful yet):

    cargo run --release -p static-node

## Threat Model

Static is designed to protect against:

- Global passive adversary: an entity that can observe all traffic on the network (ISPs, nation-states). Cover traffic and Sphinx mixing make traffic analysis infeasible.
- Malicious node operators: nodes that try to log, correlate, or de-anonymize. The architecture makes useful logging impossible.
- Physical seizure of nodes: forensics on a seized node yield encrypted chunks (unidentifiable) and no logs linking to content or users.
- Timing attacks: constant-rate traffic eliminates timing signatures.
- Service location attacks: distributed hosting with no single server IP means there is no target to locate.

Static does NOT protect against:

- Endpoint compromise: if your machine is compromised, the adversary sees content before encryption.
- Physical coercion: if someone tortures you for your keys, no protocol can help.
- Active attacks at scale: an adversary who can inject, delay, or drop traffic globally can attempt DoS and some correlation attacks (mitigated but not eliminated by Sphinx defenses).
- Sybil attacks without mitigation: a flood of malicious nodes could theoretically observe partial traffic patterns. Proof of Space-Time and the barter requirement raise the cost of this.

## Acknowledgments

Static draws on research and ideas from:

- Sphinx (Danezis, Goldberg) - the packet format that makes indistinguishable routing possible
- Loopix (Piotrowska et al.) - the mixnet design with cover traffic
- Nym - the practical implementation of Sphinx mixnets
- Freenet - distributed storage with adaptive caching
- Tahoe-LAFS - encrypted erasure-coded storage grids
- BitTorrent - tit-for-tat reciprocal economics
- Tor / I2P - the darknet pioneers who proved the concept
- Darkfi - anonymous contracts and ZK proofs in practice
