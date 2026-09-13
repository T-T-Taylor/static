# Storage Swap Protocol

To be written. Will cover:

- Chunk encryption (uniform 1 MiB chunks, strong encryption)
- Swap negotiation (barter of opaque storage slots over Sphinx)
- Lease/heartbeat mechanism for owner control
- Erasure coding parameters (K=10, M=5 default)
- Seed node redundancy
- Revocation on heartbeat expiry
- Repopulation when nodes go offline
- RAM safety (streaming decryption, key chains, never full file in memory)
