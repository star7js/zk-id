# ZK-ID Roadmap

This roadmap focuses on security, interoperability, and production readiness. Dates are estimates.

## Current State (Completed)

- ✅ Multi-attribute credentials (birthYear, nationality)
- ✅ Groth16 circuits for age + nationality
- ✅ Signed credentials (Ed25519) with issuer verification
- ✅ Signed-circuit option (BabyJub EdDSA in-circuit)
- ✅ Nonce + timestamp binding in circuits
- ✅ Server-issued challenge flow (nonce + timestamp)
- ✅ Issuer registry (trusted issuers, status, validity)
- ✅ Revocation store (commitment-based)
- ✅ Merkle revocation accumulator scaffold (in-memory demo)
- ✅ **Revocation proofs in circuit** (Merkle inclusion for valid-set)
- ✅ **Revocation SDK integration** (TypeScript prover/verifier for revocable credentials)
- ✅ Batch verification
- ✅ Telemetry hooks
- ✅ Demo web app with signed and unsigned flows
- ✅ OpenAPI schema (`docs/openapi.yaml`)
- ✅ Protocol versioning (core + SDK + demo)
- ✅ Revocation root metadata helpers + demo endpoint
- ✅ Postgres valid-credential tree (reference implementation)
- ✅ Demo rate limiting for verification endpoints
- ✅ v0.4.1 patch: stable valid-credential tree indexing, merkle-root freshness guard, added regression tests

## Now (Next 2–6 Weeks)

1. **Revocation Root Distribution (MVP)**
   - Define root versioning + TTL policy.
   - Document witness refresh rules for clients/verifiers.
   - Standardize a public root info endpoint and caching guidance.

2. **Security Readiness**
   - Maintain security policy and disclosure process.
   - Expand threat model and limitations with concrete mitigations.
   - Add circuit artifact hashes and integrity checks.
   - Reproducible circuit builds and verification-key provenance (signing + CI checks).

3. **Issuer Trust & Key Lifecycle**
   - Formalize issuer registry spec (rotation, validity windows, suspension).
   - Add issuer metadata (jurisdiction, attestation policy, audit references).
   - Document issuer onboarding and deactivation workflow.

4. **API & Protocol Clarity**
   - Finalize REST contracts for verification flows.
   - Add JSON schema or OpenAPI for SDK inputs.
   - ✅ Add versioned protocol identifiers and compatibility notes.

## Near Term (Q2 2026)

1. **Revocation Lifecycle & Root Distribution**
   - Root versioning and witness refresh policy.
   - Root dissemination channel and expiry strategy.
   - Production storage for Merkle tree state and witness generation.
   - Distributed tree state management and root synchronization.

2. **Production Storage & Reliability**
   - ✅ Reference implementation for Postgres valid-credential tree.
   - Reference implementation for Redis store.
   - ✅ Rate limiting + abuse prevention modules (demo server).
   - Audit log adapter interface.

3. **Wallet Integration**
   - Define client-side wallet flow.
   - Minimal browser wallet prototype for proof generation.
   - Credential backup and recovery strategy.

4. **Performance & Compatibility**
   - Proof generation/verification benchmarks with targets.
   - Protocol versioning and deprecation policy.
   - Interop tests for SDK input schemas.

## Mid Term (Q3 2026)

1. **Standards Alignment**
   - Optional mappings to ISO 18013-5/7 and related age-verification standards.
   - Formalize external credential formats and conversions.

2. **Cryptography Improvements**
   - Recursive proofs or multi-claim proofs.
   - Optional universal setup (PLONK).

3. **Operational Tooling**
   - Issuer dashboard prototype.
   - Key rotation helpers and policy enforcement.

## Long Term (Q4 2026+)

1. **Formal Verification + Audits**
   - Third-party audit of circuits and SDK.
   - Formal verification of core constraints.

2. **Multi-Issuer Trust Framework**
   - Trust scoring, federation, and cross-jurisdiction policies.
   - Multi-issuer credentials and threshold issuance.

3. **Enterprise Scale**
   - SLA-grade monitoring, alerts, and compliance tooling.
   - Hardware acceleration options.

## Open Questions

- ~~Should revocation be exclusion proof (non-membership) or inclusion proof of revoked list?~~ **Resolved**: Valid-set inclusion for v0.3.0 (simple Merkle tree). Sparse Merkle exclusion proofs deferred to future version for better scalability.
- Should issuer identity be a DID or a more constrained identifier?
- Which universal setup should be supported first (PLONK, Marlin, or Halo2)?
- What privacy budget is acceptable for metadata leakage (issuer, issuance time)?
- When should we migrate from valid-set inclusion to revocation-list exclusion proofs?

## Version Targets (Tentative)

- **v0.2.x**: Challenge flow + issuer registry + signed circuits (done)
- **v0.3.0**: Revocation proofs in circuit (Merkle inclusion) (done)
- **v0.4.0**: Revocation SDK integration (done)
- **v0.4.1**: Revocation-tree stability + Merkle root freshness guard (done)
- **v0.4.2**: Protocol versioning, revocation root helpers, Postgres tree, demo rate limiting (done)
- **v0.5.0**: Wallet prototype + production storage
- **v0.6.0**: KMS/HSM integration examples + issuer policy tooling
- **v1.0.0**: Audit-ready release

---

Last updated: 2026-02-08
