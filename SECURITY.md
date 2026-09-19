# Security Policy

The Static network is a privacy-focused darknet. We take security vulnerabilities very seriously.

## Reporting a Vulnerability

**DO NOT open public GitHub issues or pull requests for security vulnerabilities.**

To report a vulnerability securely and privately, use one of the following methods:

### Method 1: GitHub Private Reporting (Clearnet)
Go to the [Security tab](https://github.com/T-T-Taylor/static/security/advisories/new) of our GitHub repository and click "Report a vulnerability". This creates a private advisory visible only to repository maintainers.

### Method 2: SimpleX Chat (Privacy-Preserving)
Contact us via SimpleX Chat — a privacy-focused messaging platform with no user IDs and no metadata stored:
- **SimpleX Link**: https://smp16.simplex.im/a#omGAQARaW3UxgZ81UKFEPy0QRIrOHaaj08lmvoUhJk0

### Method 3: Static Network (Coming Soon)
We are developing a hidden service on the Static network itself for anonymous vulnerability reporting. This will allow researchers to submit reports through the privacy network, end-to-end encrypted, with no third-party involvement.

## What to Include

- Detailed description of the vulnerability
- Steps to reproduce
- Potential impact assessment
- Suggested fix (if any)

## Response Timeline

- **Acknowledgment**: Within 48 hours
- **Initial Assessment**: Within 5 business days
- **Disclosure**: Coordinated public disclosure after patch is released

## Secure Development Practices

- All code is compiled with `#![forbid(unsafe_code)]` and `#![deny(missing_docs)]`
- The network mandates post-quantum hybrid cryptography (X25519 + ML-KEM-768) for all Sphinx packets
- No sensitive data (private keys, IP addresses) is logged by the node software
