# Security Policy

## Reporting a Vulnerability

We take security seriously. If you discover a security vulnerability in zk-id, please report it responsibly.

### How to Report

**Use GitHub's private vulnerability reporting:**

1. Go to the [Security tab](https://github.com/star7js/zk-id/security) of this repository
2. Click "Report a vulnerability"
3. Provide details about the vulnerability

Alternatively, you can open a security advisory directly.

### What to Include

Please include as much of the following information as possible:

- Type of vulnerability (e.g., cryptographic issue, circuit soundness, credential forgery)
- Step-by-step instructions to reproduce the issue
- Potential impact of the vulnerability
- Any suggested fixes or mitigations

### Scope

**In scope:**
- Cryptographic vulnerabilities in circuits or protocols
- Circuit soundness issues that could allow invalid proofs
- Credential forgery or unauthorized credential operations
- SDK security bypasses or vulnerabilities
- Authentication/authorization issues in the issuer

**Out of scope:**
- Issues in demo applications or examples (not production systems)
- Social engineering attacks
- Denial of service (DoS) attacks
- Issues requiring physical access to user systems

## Response Timeline

- **Acknowledgment**: We aim to acknowledge vulnerability reports within 72 hours
- **Updates**: We will provide regular updates on the status of your report
- **Resolution**: We aim to fix critical vulnerabilities promptly and will coordinate disclosure timing with you

## Recognition

We appreciate security researchers who help keep zk-id safe. With your permission, we will:

- Credit you in release notes when the vulnerability is fixed
- Acknowledge your contribution in our security advisories

Thank you for helping keep zk-id and its users secure!
