---
title: 'Security Policy'
description: 'We take security seriously. If you discover a security vulnerability in zk-id, please report it responsibly.'
category: 'Security'
order: 20
---

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

## Supported Versions

| Version | Supported                                    |
| ------- | -------------------------------------------- |
| 1.1.x   | Current development — security fixes applied |
| 1.0.x   | Supported — security fixes applied           |
| < 1.0   | No longer supported                          |

Only the latest release on the `main` branch receives security updates.
Pre-release (`-draft`) protocol versions may change without notice.

## Security Hardening Checklist

Before deploying any zk-id component to a non-demo environment, review the
following:

1. **Key management** — Never embed private keys in source code or environment
   variables. Use a hardware security module (HSM) or cloud KMS
   (e.g., AWS KMS, GCP Cloud HSM). The `IssuerKeyManager` interface supports
   this pattern.
2. **Issuer registry** — Populate the registry from a trusted, versioned source
   (config file, database, or remote registry). Validate `validFrom`/`validTo`
   windows and enforce `status` checks.
3. **Nonce storage** — Replace `InMemoryNonceStore` with a durable store
   (Redis, database) that enforces TTL-based expiry to prevent replay attacks.
4. **Rate limiting** — Replace `SimpleRateLimiter` with a production-grade
   solution (token-bucket or sliding-window backed by Redis).
5. **Revocation root freshness** — Set `maxRevocationRootAgeMs` to reject
   stale roots. Monitor `expiresAt` in client-side caching.
6. **Audit logging** — Configure an `AuditLogger` implementation that writes
   to a tamper-evident log (append-only database, SIEM, or cloud audit trail).
7. **TLS** — All endpoints must use HTTPS. The `X-ZkId-Protocol-Version`
   header is sent in plaintext; ensure transport encryption.
8. **CORS** — Restrict allowed origins. The custom protocol header triggers
   preflight requests; configure `Access-Control-Allow-Headers` narrowly.
9. **Payload validation** — Enable `validatePayloads: true` in server config
   to reject malformed requests before cryptographic verification.
10. **Circuit artifact integrity** — All circuit build artifacts (WASM, ZKEY,
    verification keys) are tracked via SHA-256 hashes in `docs/circuit-hashes.json`.
    Verify integrity with `npm run verify:hashes` before deployment. See
    [docs/VERIFICATION_KEYS.md](docs/VERIFICATION_KEYS.md) for build reproducibility
    and trusted setup details.

## Dependency Security

### Transitive Dependency Mitigation

Several security vulnerabilities in transitive dependencies (dependencies of third-party packages) are mitigated via npm overrides in the root `package.json`:

```json
{
  "overrides": {
    "elliptic": "github:drzippie/elliptic#99a867d",
    "lodash": "^4.17.23",
    "tmp": "^0.2.4",
    "cookie": "^0.7.2",
    "undici": "^6.23.0"
  }
}
```

These overrides ensure that patched versions are installed at build time, even when transitive dependencies specify vulnerable versions.

### Why npm overrides?

These vulnerabilities exist in dependencies of packages we depend on (e.g., hardhat, ethers.js, circomlibjs). We cannot directly update these transitive dependencies because we don't control the version constraints in the parent packages. npm overrides force the use of patched versions throughout the entire dependency tree.

### Verification

To verify that patched versions are installed after running `npm install`:

```bash
npm ls lodash tmp cookie elliptic undici
```

Expected versions:

- **lodash**: `4.17.23` or higher (fixes prototype pollution, [GHSA-29mw-wpgm-hmr9](https://github.com/advisories/GHSA-29mw-wpgm-hmr9))
- **tmp**: `0.2.4` or higher (fixes symlink vulnerability, [GHSA-7p7h-4mm5-852v](https://github.com/advisories/GHSA-7p7h-4mm5-852v))
- **cookie**: `0.7.0` or higher (fixes out-of-bounds characters, [GHSA-pxg6-pf52-xh8x](https://github.com/advisories/GHSA-pxg6-pf52-xh8x))
- **elliptic**: `6.6.1` from `github:drzippie/elliptic#99a867d` (fixes risky implementation, [GHSA-848j-6mx2-7j84](https://github.com/advisories/GHSA-848j-6mx2-7j84))
- **undici**: `6.23.0` or higher (fixes decompression DoS, [GHSA-f5x3-32g6-xq36](https://github.com/advisories/GHSA-f5x3-32g6-xq36))

### Known Issues with Security Scanners

#### Dependabot Alerts

GitHub Dependabot may show open alerts for the above packages because:

1. Dependabot's static analysis scans `package-lock.json` before overrides are applied
2. The vulnerable versions are present in the dependency tree as transitive dependencies
3. npm overrides are applied at install time, not visible to static analysis tools

**These alerts can be safely dismissed** as the overrides ensure patched versions are used at runtime.

#### npm audit Warnings

Running `npm audit` may show warnings for these packages. This is expected:

- The audit system doesn't recognize GitHub sources (like our patched elliptic) as fixes
- Overridden versions may not match the semver range required by dependencies (shown as "invalid")
- Despite warnings, the patched versions are correctly installed and used

To verify the actual installed versions, check `node_modules/<package>/package.json` or use `npm ls <package>`.
