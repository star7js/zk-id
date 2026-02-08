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
- ✅ Batch verification
- ✅ Telemetry hooks
- ✅ Demo web app with signed and unsigned flows
- ✅ OpenAPI schema (`docs/openapi.yaml`)

## Now (Next 2–6 Weeks)

1. **API & Protocol Clarity**
   - Finalize REST contracts for verification flows.
   - Add JSON schema or OpenAPI for SDK inputs.
   - Add versioned protocol identifiers and compatibility notes.

2. **Issuer Trust & Key Lifecycle**
   - Formalize issuer registry spec (rotation, validity windows, suspension).
   - Add issuer metadata (jurisdiction, attestation policy, audit references).
   - Document issuer onboarding and deactivation workflow.

3. **Security Readiness**
   - Publish security policy and disclosure process.
   - Expand threat model and limitations with concrete mitigations.
   - Add circuit artifact hashes and integrity checks.

## Near Term (Q2 2026)

1. **Revocation Proofs in Circuit**
   - Define revocation witness format (Merkle path or accumulator).
   - Add circuit constraints for membership/exclusion proofs.
   - Add proof generation + verification paths.

2. **Wallet Integration**
   - Define client-side wallet flow.
   - Minimal browser wallet prototype for proof generation.
   - Credential backup and recovery strategy.

3. **Production Storage**
   - Reference implementations for Redis/Postgres stores.
   - Rate limiting + abuse prevention modules.
   - Audit log adapter interface.

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

- Should revocation be exclusion proof (non-membership) or inclusion proof of revoked list?
- Should issuer identity be a DID or a more constrained identifier?
- Which universal setup should be supported first (PLONK, Marlin, or Halo2)?
- What privacy budget is acceptable for metadata leakage (issuer, issuance time)?

## Version Targets (Tentative)

- **v0.3.x**: Challenge flow + issuer registry + signed circuits (done)
- **v0.4.0**: Revocation proofs in circuit + wallet prototype
- **v0.5.0**: KMS/HSM integration examples + issuer policy tooling
- **v1.0.0**: Audit-ready release

---

Last updated: 2026-02-08
