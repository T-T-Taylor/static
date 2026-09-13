# Lease and Heartbeat Protocol

To be written. Will cover:

- Lease structure (chunk ID, expiration time, renewal token)
- Heartbeat packets (Sphinx-formatted, indistinguishable from cover traffic)
- Refresh mechanism (owner sends heartbeat, chunks get new expiry)
- Expiry handling (chunks overwritten via swap mechanism when heartbeat stops)
- Seed node heartbeats (multiple nodes can send heartbeats for same content)
- Timing considerations (heartbeat interval vs. lease expiry window)
