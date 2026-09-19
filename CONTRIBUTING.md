# Contributing to Static

## Privacy and OpSec Guidelines

Static is a privacy network. Contributors should follow these guidelines to protect their own privacy and the privacy of users:

1. **Do not commit personal data**: Never commit IP addresses, personal email addresses, or real names to the repository.
2. **Use pseudonymous identities**: Create a dedicated GitHub account for contributing to Static. Do not link it to your personal identity.
3. **Do not log sensitive data**: If you add logging statements, ensure they do not log node IDs, content IDs, IP addresses, or payment details.
4. **Use Tor/VPNs**: If you are running a node or testing the network, use Tor or a VPN to protect your IP address.

## Development Setup

1. Install Rust (stable)
2. Clone the repository
3. Run `cargo build --release -p static-node`
4. Run `cargo test --workspace`

## Code Style

- We use `#![forbid(unsafe_code)]` and `#![deny(missing_docs)]`
- All public items must have doc comments
- Run `cargo fmt` and `cargo clippy` before submitting PRs
