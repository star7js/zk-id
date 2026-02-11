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
- ✅ Unified revocation manager (`UnifiedRevocationManager` with two-store architecture: tree + issued index)
- ✅ `IssuedCredentialIndex` interface and `InMemoryIssuedCredentialIndex` (append-only, distinguishes revoked from never-issued)
- ✅ Proof type discriminators (`ZkProof` discriminated union, `proofType` on all proof interfaces)
- ✅ Input validation module and `any` type elimination across all packages
- ✅ Sparse Merkle tree (`SparseMerkleTree` with hash-addressed leaves, O(n×depth) storage, non-membership proofs)
- ✅ Boundary and concurrency tests (tree edge cases, concurrent operations, Poseidon hash boundaries)
- ✅ On-chain Groth16 verifier (Solidity, `@zk-id/contracts`)
- ✅ W3C VC interoperability (`toW3CVerifiableCredential`, `fromW3CVerifiableCredential`, DID key support)
- ✅ v1.0.0 comprehensive documentation (threat model, circuit diagrams, deployment guide)
- ✅ Error sanitization and verbose error mode
- ✅ CI security hardening (pinned actions, minimal permissions, supply chain protections)

## Now (Next 2–6 Weeks)

**All current "Now" items are complete!** The next focus area is Q2 2026 Near Term work.

**Previous "Now" items (completed)**

- ✅ Compliance Regulation Mapping: UK OSA, EU DSA, eIDAS 2.0 documentation with known gaps and deployment checklists

- ✅ Revocation Root Distribution (MVP): root versioning, TTL policy, witness refresh rules, endpoint caching
- ✅ Security Readiness: security policy, threat model, circuit artifact hashes, reproducible builds
- ✅ Issuer Trust & Key Lifecycle: registry spec, metadata, onboarding/deactivation workflow
- ✅ API & Protocol Clarity: REST contracts, JSON schemas, OpenAPI, protocol versioning

## Near Term (Q2 2026)

**Mobile & Cross-Platform (Moved up from Q4+)**

1. **Mobile SDK (React Native)**
   - React Native wrapper around core TypeScript libraries
   - Proof generation on iOS and Android
   - Secure credential storage (Keychain/Keystore integration)
   - Example mobile app demonstrating age verification flow

2. **Credential Exchange Protocol**
   - DIF Presentation Exchange v2.0 support
   - OpenID4VP (OpenID for Verifiable Presentations) integration
   - Standardized request/response flow for wallets
   - Interoperability with existing VC/VP ecosystems

3. **Developer Portal & Playground**
   - Interactive documentation and tutorials
   - "Verify your first proof in 5 minutes" quick start
   - Live sandbox environment for testing
   - API reference with code examples in multiple languages

**Previous Near Term items (completed)**

- ✅ Revocation Lifecycle & Root Distribution: versioning, dissemination, incremental tree optimization, distributed sync
- ✅ Production Storage & Reliability: Postgres tree, Redis store, rate limiting, audit logging
- ✅ Wallet Integration: browser wallet prototype, credential backup/recovery
- ✅ Performance & Compatibility: benchmarks, protocol versioning, interop tests

## Mid Term (Q3 2026)

1. **Multi-Language SDK Support**
   - Python SDK for server-side verification
   - Go SDK for enterprise backends
   - Java/.NET consideration for regulated industries
   - Consistent API surface across languages

2. **Trusted Setup Ceremony Service**
   - Hosted, auditable trusted setup ceremonies
   - Multi-party computation (MPC) for production Groth16 parameters
   - Transparency logs and public verification
   - Integration with ceremony coordination tools (e.g., perpetual powers of tau)

**Previous Mid Term items (completed or deprioritized)**

- ✅ Standards Alignment: ISO 18013-5/7 mappings, external credential formats
- ✅ Completed cryptography: Multi-claim proofs, proving system abstraction, nullifiers, BBS disclosure, sparse Merkle tree
- ✅ Operational Tooling: issuer dashboard, key rotation, KMS/HSM examples

**Deprioritized (moved to Long Term or deferred)**

- Recursive proof circuit implementation (Groth16-in-Groth16 / Nova / Halo2) - interesting but low near-term impact
- PLONK SRS generation - flexibility improvement, not critical for current use cases
- BBS+SNARK hybrid - niche cryptography, defer until demand proven
- Non-membership circuit - sparse Merkle tree is complete, circuit integration can wait

## Long Term (Q4 2026+)

1. **Formal Verification + Audits**
   - Third-party audit of circuits and SDK (see `docs/AUDIT.md` for scope)
   - Formal verification of core constraints
   - Production-ready trusted setup (coordinated via MPC ceremony)

2. **Nullifier Circuit Integration** ✅ _Partially Complete (v0.6.0)_
   - ✅ Circom circuit that computes `Poseidon(commitment, scopeHash)` and exposes the nullifier as a public signal
   - Integrate nullifier proof with age/nationality verification (combined circuit)
   - On-chain nullifier set for trustless sybil detection (now more feasible with `@zk-id/contracts`)

3. **Multi-Issuer Trust Framework**
   - Trust scoring, federation, and cross-jurisdiction policies
   - Multi-issuer credentials and threshold issuance
   - Cross-border identity verification agreements

4. **Advanced W3C VC/DID Interoperability** ✅ _Initial items complete (v1.1.0)_
   - ✅ Basic W3C VC conversion: `toW3CVerifiableCredential`, `fromW3CVerifiableCredential` in `@zk-id/core`
   - ✅ DID key support: `ed25519PublicKeyToDidKey`, `didKeyToEd25519PublicKey` utilities
   - **Full W3C VC v2.0 compliance:** Credential envelope passes VC validators (not yet complete)
   - **JSON-LD `@context` alignment:** Embed zk-id-specific context URL
   - **VC Data Integrity proof suite:** Define `zkProof2026` proof type with Groth16 verification method
   - **DID resolution:** Support `did:web`, `did:key`, and `did:ion` for issuer identifiers
   - **Interoperability testing:** Participate in W3C VC-WG interop events
   - **Cross-ecosystem integration:** Wallets supporting both traditional VCs and zk-id ZK proofs

5. **Enterprise Scale & Acceleration**
   - SLA-grade monitoring, alerts, and compliance tooling
   - Hardware acceleration options (rapidsnark, GPU proving)
   - Cloud-native deployment patterns (Kubernetes, serverless)
   - Enterprise support and training programs

6. **Advanced Cryptography** (Deprioritized from Q3)
   - Recursive proof aggregation: actual circuit implementation (Groth16-in-Groth16 / Nova / Halo2)
   - Non-membership circuit: Circom circuit verifying sparse Merkle non-membership witness inside SNARK
   - PLONK: generate universal SRS and PLONK-compatible zkeys for all circuits
   - BBS+SNARK hybrid: prove predicates (age >= 18) over BBS-signed messages inside a SNARK circuit

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
- **v0.7.0** (completed): On-chain verifier + W3C VC interoperability + compliance regulation mapping
- **v0.8.0** (Q3 2026): Mobile SDK + credential exchange protocol + developer portal
- **v1.0.0** (Q4 2026): Audit-ready release + multi-language SDKs + trusted setup ceremony
- **v2.0.0** (2027+): Full W3C VC compliance + third-party audit + advanced cryptography + enterprise scale

---

**Priority Strategy Notes (February 2026):**

The roadmap has been reordered to prioritize **ecosystem integration** over **cryptographic enhancements**. Rationale:

1. **On-chain verification** is table stakes for Web3 adoption. Without it, zk-id cannot compete with Polygon ID, Semaphore, or Worldcoin in the DeFi/DAO space.

2. **W3C VC compliance** (moved from 2027 to now) is required for enterprise and government adoption. The "envelope formatting is not a security concern" argument is technically correct but strategically wrong — interoperability drives adoption.

3. **Mobile SDK** is critical for real-world identity use cases. Desktop-only verification limits applicability to a shrinking market.

4. **Compliance documentation** (UK/EU regulations) transforms zk-id from a "tech project" to a "compliance solution" — this drives enterprise demand.

Advanced cryptography (recursive proofs, PLONK, BBS+SNARK hybrid) has been deprioritized to Q4 2026+ because:

- Current Groth16 implementation works well for the core use case
- Ecosystem gaps (on-chain, mobile, W3C) are more critical than marginal cryptographic improvements
- Resources are better spent on adoption (developer experience, standards compliance) than optimization

**Competitive positioning:** The gap between zk-id and funded competitors (Polygon ID, Worldcoin) is not in cryptography — it's in ecosystem integration. Closing that gap is the strategic priority for 2026.

---

Last updated: 2026-02-10
