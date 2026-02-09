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
- ✅ Revocation root distribution MVP (TTL policy, freshness guards, witness refresh rules, endpoint caching guidance)
- ✅ Issuer trust & key lifecycle (registry metadata, key rotation, suspension/deactivation workflows)
- ✅ API & protocol clarity (JSON schemas for SDK inputs, OpenAPI completion, payload validation)
- ✅ Security policy hardening (expanded threat model with mitigations, hardening checklist)
- ✅ Audit log adapter interface (`AuditLogger`, `InMemoryAuditLogger`, wired into issuer + SDK server)
- ✅ JSON schema interop tests (ajv-based validation of TS objects against published schemas)
- ✅ Distributed tree sync (`SyncedValidCredentialTree` + `RedisTreeSyncChannel` in `@zk-id/redis`)
- ✅ Browser wallet prototype (`BrowserWallet`, `CredentialStore`, `IndexedDBCredentialStore` in `@zk-id/sdk`)
- ✅ Performance benchmarks with targets (`BenchmarkResult`, `PERFORMANCE_TARGETS`, `runBenchmark` in `@zk-id/core`)
- ✅ Protocol deprecation policy (`DEPRECATION_SCHEDULE`, `getVersionStatus`, `isVersionDeprecated`, `buildDeprecationHeaders`)
- ✅ KMS/HSM integration examples (`EnvelopeKeyManager`, `FileKeyManager` in `@zk-id/issuer`)
- ✅ Issuer policy tooling (`IssuerPolicy`, `checkKeyRotation`, `validateIssuerPolicy`, `generateRotationPlan` in `@zk-id/issuer`)
- ✅ Issuer dashboard prototype (`IssuerDashboard`, `DashboardStats`, `IssuerSummary` in `@zk-id/sdk`)
- ✅ ISO 18013-5/7 standards mapping (`toMdlElements`, `createAgeOverAttestation`, `STANDARDS_MAPPINGS` in `@zk-id/issuer`)
- ✅ Multi-claim proof types (`MultiClaimRequest`, `createMultiClaimRequest`, `expandMultiClaimRequest` in `@zk-id/core`)
- ✅ Proving system abstraction (`ProvingSystem`, `Groth16ProvingSystem`, `PLONKProvingSystem`, pluggable registry)
- ✅ Nullifier system for sybil resistance (`computeNullifier`, `createNullifierScope`, `NullifierStore`)
- ✅ Recursive proof aggregation scaffold (`RecursiveAggregator`, `LogicalAggregator`, `AggregatedProof`)
- ✅ v1.0.0 audit checklist (`docs/AUDIT.md`)
- ✅ BBS selective disclosure (`generateBBSKeyPair`, `deriveBBSDisclosureProof`, `verifyBBSDisclosureProof` in `@zk-id/core`)
- ✅ BBS credential issuer (`BBSCredentialIssuer` in `@zk-id/issuer`)
- ✅ Unified revocation manager (`UnifiedRevocationManager` with three-store architecture: tree + issued index + audit logger)
- ✅ `IssuedCredentialIndex` interface and `InMemoryIssuedCredentialIndex` (append-only, distinguishes revoked from never-issued)
- ✅ Proof type discriminators (`ZkProof` discriminated union, `proofType` on all proof interfaces)
- ✅ Input validation module and `any` type elimination across all packages
- ✅ Sparse Merkle tree (`SparseMerkleTree` with hash-addressed leaves, O(n×depth) storage, non-membership proofs)
- ✅ Boundary and concurrency tests (tree edge cases, concurrent operations, Poseidon hash boundaries)

## Now (Next 2–6 Weeks)

1. **Revocation Root Distribution (MVP)**
   - ✅ Define root versioning + TTL policy.
   - ✅ Document witness refresh rules for clients/verifiers.
   - ✅ Standardize a public root info endpoint and caching guidance.

2. **Security Readiness**
   - ✅ Maintain security policy and disclosure process.
   - ✅ Expand threat model and limitations with concrete mitigations.
   - ✅ Add circuit artifact hashes and integrity checks.
   - ✅ Reproducible circuit builds and verification-key provenance (signing + CI checks).

3. **Issuer Trust & Key Lifecycle**
   - ✅ Formalize issuer registry spec (rotation, validity windows, suspension).
   - ✅ Add issuer metadata (jurisdiction, attestation policy, audit references).
   - ✅ Document issuer onboarding and deactivation workflow.

4. **API & Protocol Clarity**
   - ✅ Finalize REST contracts for verification flows.
   - ✅ Add JSON schema or OpenAPI for SDK inputs.
   - ✅ Add versioned protocol identifiers and compatibility notes.

## Near Term (Q2 2026)

1. **Revocation Lifecycle & Root Distribution**
   - ✅ Root versioning and witness refresh policy.
   - ✅ Root dissemination channel and expiry strategy.
   - ✅ Production storage for Merkle tree state and witness generation (incremental tree optimization).
   - ✅ Incremental Merkle tree updates (O(depth) mutations, O(1) reads).
   - ✅ Witness freshness helper (`isWitnessFresh()`) for client-side staleness checks.
   - ✅ Distributed tree state management and root synchronization (`SyncedValidCredentialTree` + `RedisTreeSyncChannel`).

2. **Production Storage & Reliability**
   - ✅ Reference implementation for Postgres valid-credential tree (with layer caching).
   - ✅ Reference implementation for Redis store (@zk-id/redis package).
   - ✅ Rate limiting + abuse prevention modules (demo server).
   - ✅ Audit log adapter interface.

3. **Wallet Integration**
   - ✅ Define client-side wallet flow (`WalletConnector`, `CredentialStore`, `BrowserWallet`).
   - ✅ Minimal browser wallet prototype for proof generation (`BrowserWallet` in `@zk-id/sdk`).
   - ✅ Credential backup and recovery strategy (JSON export/import for single + bulk credentials).

4. **Performance & Compatibility**
   - ✅ Proof generation/verification benchmarks with targets.
   - ✅ Protocol versioning and deprecation policy.
   - ✅ Interop tests for SDK input schemas.

## Mid Term (Q3 2026)

1. **Standards Alignment**
   - ✅ Optional mappings to ISO 18013-5/7 and related age-verification standards.
   - ✅ Formalize external credential formats and conversions.

2. **Cryptography Improvements**
   - ✅ Multi-claim proof types and request/response bundling.
   - ✅ Proving system abstraction layer (Groth16 + PLONK scaffold).
   - ✅ Recursive proof aggregation scaffold (LogicalAggregator + RecursiveAggregator interface).
   - ✅ Nullifier system for sybil resistance (Poseidon-based, scope-isolated).
   - ✅ BBS selective disclosure (BLS12-381-SHA-256, per IETF draft-irtf-cfrg-bbs-signatures).
   - ✅ BBS credential issuer (field-level BBS signing for per-field disclosure).
   - ✅ Sparse Merkle tree with non-membership proofs (hash-addressed, O(n×depth) storage).
   - Recursive proofs: actual circuit implementation (Groth16-in-Groth16, Nova, or Halo2).
   - Non-membership circuit: Circom circuit verifying sparse Merkle non-membership witness inside SNARK.
   - PLONK: generate universal SRS and PLONK-compatible zkeys for all circuits.
   - BBS+SNARK hybrid: prove predicates (age >= 18) over BBS-signed messages inside a SNARK circuit.

3. **Operational Tooling**
   - ✅ Issuer dashboard prototype.
   - ✅ Key rotation helpers and policy enforcement.
   - ✅ KMS/HSM integration examples (envelope encryption, file-based keys).

## Long Term (Q4 2026+)

1. **Formal Verification + Audits**
   - Third-party audit of circuits and SDK (see `docs/AUDIT.md` for scope).
   - Formal verification of core constraints.
   - Trusted setup ceremony for production Groth16 keys.

2. **Nullifier Circuit**
   - Circom circuit that computes `Poseidon(commitment, scopeHash)` and exposes the nullifier as a public signal.
   - Integrate nullifier proof with age/nationality verification (combined circuit).
   - On-chain nullifier set for trustless sybil detection.

3. **Multi-Issuer Trust Framework**
   - Trust scoring, federation, and cross-jurisdiction policies.
   - Multi-issuer credentials and threshold issuance.
   - W3C Verifiable Credentials Data Model alignment.
   - DID method for issuer identifiers.

4. **Enterprise Scale**
   - SLA-grade monitoring, alerts, and compliance tooling.
   - Hardware acceleration options (rapidsnark, GPU proving).
   - Mobile SDK (React Native / Flutter) for proof generation.

## Open Questions

- ~~Should revocation be exclusion proof (non-membership) or inclusion proof of revoked list?~~ **Resolved**: Valid-set inclusion for v0.3.0 (dense Merkle tree). `SparseMerkleTree` added in v0.6.0 with `getNonMembershipWitness()` for exclusion proofs. Circuit integration (non-membership verification inside SNARK) is next.
- Should issuer identity be a DID or a more constrained identifier? **Leaning DID**: W3C DID Core is a recommendation; `did:web` or `did:key` would provide interop with the VC ecosystem.
- ~~Which universal setup should be supported first (PLONK, Marlin, or Halo2)?~~ **Resolved**: PLONK (via snarkjs) is scaffolded first since it shares the BN128 curve and circom toolchain. Halo2 deferred to post-v1.0 due to circuit rewrite requirements.
- What privacy budget is acceptable for metadata leakage (issuer, issuance time)?
- ~~When should we migrate from valid-set inclusion to revocation-list exclusion proofs?~~ **Resolved**: `SparseMerkleTree` supports both models. Valid-set inclusion remains the primary approach; non-membership proofs are available for scenarios that need exclusion proof (e.g., proving a revoked credential is no longer valid). Circuit integration is the remaining step.

## Version Targets (Tentative)

- **v0.2.x**: Challenge flow + issuer registry + signed circuits (done)
- **v0.3.0**: Revocation proofs in circuit (Merkle inclusion) (done)
- **v0.4.0**: Revocation SDK integration (done)
- **v0.4.1**: Revocation-tree stability + Merkle root freshness guard (done)
- **v0.4.2**: Protocol versioning, revocation root helpers, Postgres tree, demo rate limiting (done)
- **v0.4.5**: Incremental Merkle tree optimization, witness freshness helper, Redis storage (done)
- **v0.5.0**: Wallet prototype + distributed tree synchronization + benchmarks + deprecation policy (done)
- **v0.6.0**: KMS/HSM + policy + dashboard + standards + multi-claim + proving abstraction + nullifiers + recursive scaffold + BBS selective disclosure + unified revocation + sparse Merkle tree + type safety (done)
- **v1.0.0**: Audit-ready release

---

Last updated: 2026-02-09
