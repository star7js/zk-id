# Known Limitations

Date: 2026-02-08

- **Not production hardened**: key management, monitoring, and incident response are not implemented. Audit logging has a pluggable `AuditLogger` interface but only ships with an in-memory/console implementation.
- **Issuer trust requires configuration**: verifier must be configured with trusted issuer public keys.
- **Revocation privacy tradeoffs**: demo Merkle accumulator is in-memory and not wired into circuits or proofs yet.
- **Operational security**: no built-in protection against device compromise or malware on clients.
- **Rate limiting**: demo rate limiter is not sufficient for production.
- **Demo/Examples**: examples are for illustration and are not secure deployments.
