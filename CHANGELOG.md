# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.6.0] - 2026-02-09

### Added
- **KMS/HSM integration** — `EnvelopeKeyManager`, `FileKeyManager` in `@zk-id/issuer`
  - `EnvelopeKeyManager`: AES-256-GCM envelope encryption for Ed25519 private keys with seal/unseal workflow
  - `FileKeyManager`: PEM file-based key loading with `fromPemFiles()` and `fromPemStrings()` constructors
  - Both implement `IssuerKeyManager` and work with `ManagedCredentialIssuer`
- **Issuer policy tooling** — `IssuerPolicy`, `checkKeyRotation`, `validateIssuerPolicy`, `generateRotationPlan` in `@zk-id/issuer`
  - `IssuerPolicy` interface with configurable key age limits, rotation windows, credential caps, and metadata requirements
  - `DEFAULT_ISSUER_POLICY` (365-day keys) and `STRICT_ISSUER_POLICY` (180-day keys, metadata required)
  - `checkKeyRotation()` returns rotation status with days-until-expiry and human-readable messages
  - `validateIssuerPolicy()` checks issuer records against policy with violations and warnings
  - `generateRotationPlan()` produces a 4-step rotation schedule with ISO 8601 dates
- **Issuer dashboard prototype** — `IssuerDashboard`, `DashboardStats`, `IssuerSummary` in `@zk-id/sdk`
  - `IssuerDashboard` aggregates stats from registry, audit log, and revocation store
  - Per-issuer summaries: status, key count, credentials issued/revoked, last issuance, jurisdiction
  - Aggregate stats: active/suspended/revoked issuers, total credentials, revocation counts
  - `trackIssuer()`/`untrackIssuer()` for scoped monitoring
- **ISO 18013-5/7 standards alignment** — country code conversion, mDL element mapping, age-over attestation in `@zk-id/issuer`
  - `ISO_3166_NUMERIC_TO_ALPHA2` / `ISO_3166_ALPHA2_TO_NUMERIC` bidirectional country code tables
  - `toMdlElements()` converts a `SignedCredential` to ISO 18013-5 mDL data elements
  - `createAgeOverAttestation()` produces ISO 18013-7 `age_over_NN` attestation objects
  - `STANDARDS_MAPPINGS` array documenting full zk-id ↔ ISO 18013-5/7 concept mapping
  - `MDL_NAMESPACE`, `MDL_ELEMENTS` constants for programmatic access
- **Multi-claim proof API** — `createMultiClaimRequest`, `expandMultiClaimRequest`, `aggregateVerificationResults` in `@zk-id/core`
  - `MultiClaimRequest` bundles multiple claim specs (age, nationality) with a shared nonce
  - `expandMultiClaimRequest()` converts to individual proof requests for parallel proving
  - `aggregateVerificationResults()` combines per-claim results into an overall pass/fail
  - Supports `age`, `nationality`, and `age-revocable` claim types
- **Proving system abstraction** — `ProvingSystem`, `Groth16ProvingSystem`, `PLONKProvingSystem` in `@zk-id/core`
  - Unified `ProvingSystem` interface decoupling from Groth16-specific snarkjs API
  - Pluggable proving system registry with `registerProvingSystem()` / `getProvingSystem()`
  - `PROVING_SYSTEM_COMPARISON` documenting tradeoffs (trusted setup, proof size, verification time)
  - PLONK scaffold ready for universal SRS setup (no per-circuit ceremony)
- **Nullifier system for sybil resistance** — `computeNullifier`, `createNullifierScope`, `consumeNullifier`, `InMemoryNullifierStore` in `@zk-id/core`
  - Deterministic nullifier computation: `Poseidon(commitment, scopeHash)` prevents double-use per scope
  - Scope-based isolation: actions are unlinkable across different scopes
  - `NullifierStore` interface for pluggable backend (in-memory, Redis, Postgres)
  - Follows same pattern as Worldcoin/Semaphore for sybil-resistant anonymous actions
- **Recursive proof aggregation scaffold** — `LogicalAggregator`, `RecursiveAggregator`, `AggregatedProof` in `@zk-id/core`
  - `RecursiveAggregator` interface for pluggable recursive proof backends
  - `LogicalAggregator` pass-through implementation (bundles proofs without recursion)
  - `RECURSIVE_PROOF_STATUS` documenting implementation state for Groth16-in-Groth16, Nova, and Halo2
  - Helpers: `createAggregateInput()`, `isRecursiveProof()`, `getConstituentPublicSignals()`
- **BBS selective disclosure** — `generateBBSKeyPair`, `signBBSMessages`, `deriveBBSDisclosureProof`, `verifyBBSDisclosureProof` in `@zk-id/core`
  - BBS signatures (BLS12-381-SHA-256 ciphersuite) per IETF draft-irtf-cfrg-bbs-signatures
  - Credential fields signed as individual BBS messages enabling per-field selective disclosure
  - `credentialFieldsToBBSMessages()` encodes credential fields in canonical order
  - `serializeBBSProof()` / `deserializeBBSProof()` for JSON-safe transport
  - `getDisclosedFields()` extracts revealed field values from a disclosure proof
  - Complementary to ZK-SNARK predicates: BBS for "reveal field X", SNARKs for "prove age >= 18"
- **BBS credential issuer** — `BBSCredentialIssuer` in `@zk-id/issuer`
  - Issues credentials with BBS signatures (BLS12-381) instead of Ed25519
  - Each credential field (id, birthYear, nationality, salt, issuedAt, issuer) is a separate BBS message
  - Holders can derive selective disclosure proofs without issuer interaction
  - Full audit logging with signature scheme metadata
- **v1.0.0 audit checklist** — `docs/AUDIT.md` covering circuits, crypto primitives, API security, code quality
- `docs/STANDARDS.md` documenting ISO 18013-5/7 mapping, privacy comparison, and architectural differences
- 100+ new tests across all new modules

### Security
- **Fixed credential signature binding** — `credentialSignaturePayload` now includes issuer identity and issuance timestamp in the signed payload, preventing issuer substitution attacks where an attacker could swap the `issuer` field on a `SignedCredential` without invalidating the signature

### Changed
- Bumped all package versions from 0.5.0 to 0.6.0

## [0.5.0] - 2026-02-09

### Added
- **Distributed tree sync** — `RedisTreeSyncChannel` and `SyncedValidCredentialTree` in `@zk-id/redis`
  - Redis pub/sub channel for broadcasting tree mutation events across server nodes
  - `SyncedValidCredentialTree` wrapper that publishes root updates on `add()`/`remove()` and notifies on remote changes
  - Self-notification deduplication via per-node `nodeId`
  - `onRemoteUpdate` callback for cache invalidation when remote nodes mutate the tree
- **Browser wallet** — `BrowserWallet`, `CredentialStore`, `IndexedDBCredentialStore`, `InMemoryCredentialStore` in `@zk-id/sdk`
  - `CredentialStore` interface for pluggable persistent credential storage
  - `IndexedDBCredentialStore` for real browser environments
  - `InMemoryCredentialStore` for testing and Node.js
  - `BrowserWallet` implementing `WalletConnector` with credential lifecycle management (add, remove, list, get)
  - Auto-select most recently issued credential, or user-provided `onProofRequest` callback for consent UI
  - JSON export/import for single credential backup and full wallet backup/restore
  - Support for age, nationality, and age-revocable proof generation
- 43 new tests (15 for distributed tree sync, 28 for browser wallet)
- **Performance benchmarks** — `runBenchmark`, `checkTarget`, `formatResult`, `PERFORMANCE_TARGETS` in `@zk-id/core`
  - Lightweight benchmark runner with warmup, per-iteration timing, and statistical aggregation (avg, median, p95, min, max, ops/s)
  - 16 predefined performance targets covering Poseidon hashing, credential creation, Merkle tree operations, constraint validation, proof generation, and proof verification
  - `checkTarget()` for automated pass/fail checks against performance targets
  - `formatResult()` for human-readable benchmark output
  - Benchmark test suite validating Poseidon hash, credential creation, Merkle tree, and constraint validation against targets
  - `docs/BENCHMARKS.md` documenting all targets, methodology, and browser considerations
- **Protocol deprecation policy** — `DEPRECATION_SCHEDULE`, `DEPRECATION_POLICY`, `getVersionStatus`, `isVersionDeprecated`, `isVersionSunset`, `buildDeprecationHeaders` in `@zk-id/core`
  - Three-stage lifecycle: Active → Deprecated → Sunset
  - 90-day minimum deprecation window with 60-day recommended migration lead time
  - Machine-readable `DEPRECATION_SCHEDULE` for programmatic enforcement
  - `buildDeprecationHeaders()` for RFC 8594 compliant `Deprecation`, `Sunset`, and `Link` HTTP headers
  - Protocol specification updated with deprecation rules and HTTP signaling documentation
- 28 new tests (10 for benchmarks, 18 for deprecation policy)

## [0.4.5] - 2026-02-09

### Added
- `isWitnessFresh()` helper method to `ZkIdClient` for checking witness staleness against current root
- Incremental Merkle tree optimization for `InMemoryValidCredentialTree` with cached layers and path-only updates
- Layer caching with invalidation to `PostgresValidCredentialTree` for improved read performance
- Pre-computed zero hashes for efficient tree initialization

### Changed
- Optimized `InMemoryValidCredentialTree` from O(2^depth) per query to O(depth) per mutation and O(1) per read
- Optimized `PostgresValidCredentialTree` with in-memory layer cache (first query loads, mutations update incrementally)
- Workspace build order now sequential to prevent race conditions in CI

### Removed
- Dead `RevocationAccumulator` scaffold code (unused interface and implementation)
- Old `buildLayers()` method from `PostgresValidCredentialTree` (replaced by `rebuildCache()`)

### Performance
- At depth 10: `getRoot()` reduced from 2047 Poseidon hashes to 0 (cached)
- At depth 10: `add()/remove()` now performs 10 Poseidon hashes (incremental path update)
- At depth 10: `getWitness()` reduced from 2047 Poseidon hashes to 0 (array lookups)

### Docs
- Updated ARCHITECTURE.md with comprehensive revocation system documentation
- Clarified two-layer revocation model (blacklist + ZK Merkle whitelist)
- Documented circuit integration, root distribution, and privacy properties

## [0.4.4] - 2026-02-08

### Removed
- Legacy server-side demo endpoints for proof generation (client-side generation is now the default)
- Dead imports and unused circuit path constants from web app server
- Signed circuit setup from build process (superseded by revocable proofs)

### Docs
- Updated README to clarify client-side proof generation workflow
- Removed references to server-side proof endpoints from OpenAPI spec

## [0.4.3] - 2026-02-08

### Added
- Browser-side ZK proof generation using snarkjs and WASM
- Client-side proof generation UI with progress indicators
- Circuit artifact streaming via CDN for in-browser proof generation

### Changed
- Web demo now generates all proofs client-side (browser) instead of server-side

## [0.4.2] - 2026-02-08

### Added
- Protocol version parsing + compatibility helpers in core with SDK enforcement policies
- Server-side protocol enforcement in SDK (strict/warn/off) and demo server header handling
- Revocation root metadata helpers (`getRevocationRootInfo` / `fetchRevocationRootInfo`) and demo endpoint
- Postgres-backed valid-credential tree implementation (`PostgresValidCredentialTree`)
- Demo API rate limiting (express-rate-limit)
- Issue templates, PR template, and CODEOWNERS

### Security
- Temporary mitigation for elliptic ECDSA issue via override to patched fork (pending upstream release)

### Docs
- Added protocol header CORS guidance and clarified supported vs. future use cases
- Expanded revocation/production storage examples

## [0.4.1] - 2026-02-08

### Fixed
- Stabilized valid-credential tree indexing to avoid witness invalidation on removals
- Normalized commitment keys in valid-credential tree lookups
- Enforced Merkle root freshness checks for revocable proofs even when expected root is `'0'`

### Tests
- Added coverage for commitment normalization in valid-credential tree
- Added revocable Merkle root mismatch coverage in core + SDK

## [0.4.0] - 2026-02-08

### Added
- `AgeProofRevocable` type and `ValidCredentialTree` interface in `@zk-id/core`
- `InMemoryValidCredentialTree` class (Poseidon Merkle tree with valid-set semantics)
- `generateAgeProofRevocable` and `generateAgeProofRevocableAuto` prover functions
- `verifyAgeProofRevocable` and `validateAgeProofRevocableConstraints` verifier functions
- `verifyBatch()` support for `'age-revocable'` proof type
- SDK server: revocable verification key config, policy enforcement, Merkle root freshness check
- SDK client: `verifyAgeRevocable()` method and revocable circuit path config
- Web app: credential lifecycle hooks and `POST /api/demo/verify-age-revocable` endpoint
- 17 new tests across core and SDK packages

## [0.3.0] - 2026-02-07

### Added
- Merkle inclusion circuit (`age-verify-revocable`) for credential validity (non-revocation)
- In-memory Merkle revocation accumulator scaffold
- CI/CD workflow for circuit building and GitHub releases
- Stub test scripts in examples to fix CI

### Fixed
- CI circom installation by disabling strict rustflags
- Mocha `--exit` flag to prevent CI hangs

## [0.2.0] - 2026-02-07

### Added
- CHANGELOG.md following Keep a Changelog format
- Package metadata for npm publishing (license, repository, files, exports) to all packages
- Build step to CI pipeline before tests
- `.nvmrc` file specifying Node 20
- TODO comment in `.gitignore` about tracked circuit build artifacts
- Author field in root package.json

### Changed
- Bumped all package versions from 0.1.0 to 0.2.0
- Updated internal dependency ranges to ^0.2.0

### Removed
- Internal security review notes (findings already addressed in code)

## [0.1.1] - 2025-01-XX

### Fixed
- High-severity snarkjs vulnerability (CVE-2024-45811) by upgrading to 0.7.6
- Nonce generation for signed credentials now uses BigInt to handle values > Number.MAX_SAFE_INTEGER
- Revocation logic for signed credentials (issuer secret was incorrectly included in proof)

### Security
- Upgraded snarkjs from 0.7.0 to 0.7.6 to address critical security vulnerability

## [0.1.0] - 2025-01-XX

### Added
- Initial release of zk-id system
- `@zk-id/core` - Core cryptographic primitives and proof generation
- `@zk-id/sdk` - Client-side SDK for web integration
- `@zk-id/issuer` - Credential issuance service
- `@zk-id/circuits` - Zero-knowledge circuits for identity verification
- Age verification circuit with range proofs
- Signed credential system with revocation support
- Poseidon hash-based commitments
- Example applications:
  - Age gate demo
  - Credential format comparison
  - Full web application with issuer and verifier
- Comprehensive documentation and README

[0.6.0]: https://github.com/star7js/zk-id/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/star7js/zk-id/compare/v0.4.5...v0.5.0
[0.4.5]: https://github.com/star7js/zk-id/compare/v0.4.4...v0.4.5
[0.4.4]: https://github.com/star7js/zk-id/compare/v0.4.3...v0.4.4
[0.4.3]: https://github.com/star7js/zk-id/compare/v0.4.2...v0.4.3
[0.4.2]: https://github.com/star7js/zk-id/compare/v0.4.1...v0.4.2
[0.4.1]: https://github.com/star7js/zk-id/compare/v0.4.0...v0.4.1
[0.4.0]: https://github.com/star7js/zk-id/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/star7js/zk-id/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/star7js/zk-id/compare/v0.1.1...v0.2.0
[0.1.1]: https://github.com/star7js/zk-id/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/star7js/zk-id/releases/tag/v0.1.0
