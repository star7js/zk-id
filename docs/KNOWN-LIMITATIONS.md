# Known Limitations

Date: 2026-02-10

- **Not production hardened**: key management, monitoring, and incident response are not implemented. Audit logging has a pluggable `AuditLogger` interface but only ships with an in-memory/console implementation.
- **Issuer trust requires configuration**: verifier must be configured with trusted issuer public keys.
- **Revocation privacy tradeoffs**: Merkle revocation IS wired into circuits (`age-verify-revocable.circom`) with Postgres and Redis implementations, but the demo uses in-memory trees.
- **Operational security**: no built-in protection against device compromise or malware on clients.
- **Rate limiting**: demo uses IP-based rate limiting (60 req/min via `express-rate-limit`), which can be bypassed by changing IPs. Production should use authenticated session-based rate limiting with token buckets or sliding windows.
- **On-chain verifier limitations**: On-chain verifier (`@zk-id/contracts`) is for Groth16 only; PLONK/BBS proofs cannot be verified on-chain yet.
- **W3C VC interoperability**: W3C VC interop covers basic format conversion (`toW3CVerifiableCredential`, `fromW3CVerifiableCredential`) but does not pass full VC validator suites.
- **Circuit artifact hashes**: Circuit artifact hashes are platform-dependent (macOS vs Linux produce different hashes due to build environment differences).
- **Demo/Examples**: examples are for illustration and are not secure deployments.
