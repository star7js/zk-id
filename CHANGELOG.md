# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

[0.4.1]: https://github.com/star7js/zk-id/compare/v0.4.0...v0.4.1
[0.4.0]: https://github.com/star7js/zk-id/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/star7js/zk-id/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/star7js/zk-id/compare/v0.1.1...v0.2.0
[0.1.1]: https://github.com/star7js/zk-id/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/star7js/zk-id/releases/tag/v0.1.0
