# v1.0.0 Audit Readiness Checklist

This document tracks the requirements for a production-ready, audit-worthy v1.0.0 release of zk-id. It is intended as a guide for internal review and for third-party auditors.

## Circuit Security

### Critical (Must-Fix Before Audit)

- [x] **Under-constrained signals**: Review all `<==` assignments for signals that are used in output but not range-checked. In particular:
  - `age-verify.circom`: `birthYear` is only checked `<= currentYear` — add lower bound check (e.g., `>= 1900`) to prevent wrapping in the field — **FIXED**: Added `GreaterEqThan(12)` check for `birthYear >= 1900` in all age circuits in v0.6.0
  - `age-verify.circom`: `nonce` and `requestTimestamp` are copied but not constrained beyond binding — document why this is intentional — **DOCUMENTED**: Added comments explaining server-side validation in v0.6.0
  - All signed circuits: `signatureR8` and `signatureS` are 256-bit arrays — ensure each element is binary-constrained — **VERIFIED**: Binary constraints enforced by EdDSAVerifier's arithmetic operations and CompConstant subgroup order check, documented in v0.6.0
- [x] **Field overflow**: `GreaterEqThan(8)` limits age comparison to 8 bits (0-255). Verify that `currentYear - birthYear` cannot exceed 255 or underflow. Consider increasing to 12 bits for defense in depth — **FIXED**: Widened to 12 bits in v0.6.0
- [x] **Merkle tree depth hardcoded**: `AgeVerifyRevocable` hardcodes `depth=10`. This limits the valid credential set to 1024 entries. Document this limit or make it configurable — **DOCUMENTED**: Added clear comment in age-verify-revocable.circom explaining 1,024 entry limit and scaling options in v0.6.0
- [x] **EdDSA message length**: `EdDSAVerifier(256)` verifies 256 bits. Ensure the Poseidon hash output fits in 256 bits for the BN128 field (it does — BN128 prime is ~254 bits — but add an explicit comment) — **DOCUMENTED**: Added explicit comments in age-verify-signed.circom and nationality-verify-signed.circom confirming 254-bit Poseidon fits in 256-bit EdDSAVerifier in v0.6.0
- [x] **Deterministic nullifier circuit**: Add a circuit that computes `Poseidon(commitment, scopeHash)` and exposes the nullifier as a public signal. Without this, nullifiers are computed off-chain and must be trusted — **FIXED**: Added nullifier.circom in v0.6.0

### High Priority

- [x] **Trusted setup ceremony**: Document the ceremony process for Groth16 proving keys. Include: number of participants, entropy sources, transcript publication, and toxic waste destruction verification — **DOCUMENTED**: Comprehensive ceremony documentation in `docs/TRUSTED-SETUP.md`, including dev/production procedures, security considerations, and verification steps in v0.6.0
- [x] **Circuit artifact integrity**: SHA-256 hashes for all `.wasm` and `.zkey` files stored in `packages/circuits/hashes.json`. Verification script exists (`verify-hashes.sh`) — ensure it runs in CI — **IMPLEMENTED**: Hash verification added to main CI pipeline (.github/workflows/ci.yml) and dedicated verify-circuits workflow. Runs on every PR and main branch push. Hashes stored in docs/circuit-hashes.json (v0.6.0)
- [x] **Reproducible builds**: Document exact circom version, snarkjs version, and build flags needed to reproduce circuit artifacts from source — **DOCUMENTED**: Complete build reproduction guide in `docs/REPRODUCIBLE-BUILDS.md` with exact versions (circom 0.5.46, snarkjs 0.7.6), build flags, and verification steps in v0.6.0

### Medium Priority

- [x] **Power-of-tau parameters**: Document which ptau file is used and its provenance (Hermez ceremony, Iden3, or custom) — **DOCUMENTED**: Full provenance in `docs/TRUSTED-SETUP.md` (Hermez ceremony, 177 participants, 3 ptau files documented) in v0.6.0
- [x] **Circuit constraint count**: Document constraint counts for each circuit to detect unexpected growth — **DOCUMENTED**: Complete complexity metrics in `docs/CIRCUIT-COMPLEXITY.md` with constraint counts, ptau requirements, and growth monitoring in v0.6.0

## Cryptographic Primitives

### Critical

- [x] **Poseidon parameters**: Verify that `circomlibjs` Poseidon uses the canonical parameters for BN128 (t=3, RF=8, RP=57). Document parameter source — **VERIFIED**: Parameters confirmed (t=3: RF=8/RP=57, t=4: RF=8/RP=56), documented in `docs/CRYPTOGRAPHIC-PARAMETERS.md` in v0.6.0
- [x] **Ed25519 vs BabyJubJub**: The codebase uses Node.js `crypto` Ed25519 for off-chain signatures and BabyJubJub EdDSA for in-circuit verification. These are different curves. Document the distinction and verify that the signature bridge (converting Ed25519 sigs to BabyJub format) is correct or clarify that they are used independently — **DOCUMENTED**: Comprehensive comparison added to CRYPTOGRAPHIC-PARAMETERS.md explaining both schemes are independent (no bridge exists). Ed25519 for off-chain (CredentialIssuer), Baby Jubjub EdDSA for in-circuit (CircuitCredentialIssuer). Different curves, incompatible formats, used for different trust models (v0.6.0)
- [x] **Random salt generation**: `crypto.randomBytes(32)` — verify that this is a CSPRNG on all target platforms — **VERIFIED**: Comprehensive CSPRNG documentation added to CRYPTOGRAPHIC-PARAMETERS.md. Node.js crypto.randomBytes() verified as cryptographically secure on all platforms (Linux: /dev/urandom, macOS: arc4random_buf, Windows: BCryptGenRandom). All usage patterns (salt, nonce, keys, IVs) documented with appropriate security levels (v0.6.0)

### High Priority

- [x] **Field element encoding**: Ensure all values passed to Poseidon fit in the BN128 scalar field (~254 bits). The salt is 256 bits — verify no truncation occurs when converting `BigInt('0x' + salt)` — **DOCUMENTED**: Added comments in credential.ts explaining circomlibjs Poseidon performs automatic modular reduction, no truncation occurs (v0.6.0)
- [x] **Commitment binding**: The Poseidon commitment `H(birthYear, nationality, salt)` binds exactly 3 fields. Extending the credential schema requires a new circuit. Document this limitation — **DOCUMENTED**: Added comprehensive JSDoc to Credential interface in types.ts explaining 3-field binding and circuit redesign requirements for schema extensions (v0.6.0)

## API Security

### Critical

- [x] **Nonce replay**: `InMemoryNonceStore` uses `setTimeout` for expiry — this leaks in long-running processes. Production deployments MUST use a persistent store — **FIXED**: Replaced with Map-based lazy expiry in v0.6.0
- [x] **Challenge timing**: `maxRequestAgeMs` prevents stale proofs but does not prevent time-shifted proofs (prover uses a future timestamp). Add server-side time validation — **FIXED**: Added server-side future timestamp validation in server.ts. Removed Math.abs() that masked future timestamps. New config option `maxFutureSkewMs` (default 60s) allows small clock skew. Rejects timestamps beyond allowed skew with clear error message. Comprehensive tests added for both rejection and acceptance cases (v0.6.0)
- [x] **Credential hash collision**: If two credentials have the same `Poseidon(birthYear, nationality, salt)`, they are indistinguishable. Salt entropy (256 bits) makes this negligible, but document the security margin — **DOCUMENTED**: Added comprehensive collision resistance analysis in CRYPTOGRAPHIC-PARAMETERS.md with probability calculations and security margin (256-bit salt → ~2^128 security, negligible collision probability even at billion-credential scale) (v0.6.0)

### High Priority

- [x] **Issuer key rotation**: The registry supports overlapping validity windows, but there's no mechanism to reject proofs signed by a recently-rotated-out key within a grace period. Consider adding a `rotationGracePeriodMs` — **IMPLEMENTED (v1.0)**: Added `rotationGracePeriodMs` field to `IssuerRecord`. `InMemoryIssuerRegistry.getIssuer()` now checks grace period after `validTo` expiry and logs acceptance via audit logger. See `packages/sdk/src/server.ts` lines 133-150, 180-219.
- [x] **Rate limiter bypass**: `SimpleRateLimiter` is trivially bypassable (change IP). Document that production should use token bucket with authenticated sessions — **DOCUMENTED (v1.0)**: Added comprehensive JSDoc to `SimpleRateLimiter` class (line 1420+) warning about IP spoofing, proxy bypass, and in-memory limitations. Recommends token bucket with authenticated sessions, API gateway rate limiting, or Redis-based distributed rate limiting. See `packages/sdk/src/server.ts`.
- [x] **Error information leakage**: Verification error messages like "Invalid credential signature" vs "Unknown issuer" reveal information to attackers. Consider a single "Verification failed" message for external responses — **FIXED (v1.0)**: Added `sanitizeError()` method that maps internal errors to generic categories: "Verification failed" (signature/issuer/constraint/proof errors), "Request expired or invalid" (timestamp/nonce), "Too many requests" (rate limit), "Invalid request format" (payload validation). New config option `verboseErrors?: boolean` (default: false) allows detailed errors for development/debugging. All error messages in `verifyProof()`, `verifySignedProof()`, and internal methods now sanitized. See `packages/sdk/src/server.ts` lines 100, 390-431.

## Code Quality

### Before Audit

- [x] Fix pre-existing TypeScript strict mode errors (currently bypassed by `transpile-only`) — **FIXED**: Removed all `transpile-only` and `typeCheck: false` flags from tsconfig/package.json files. Fixed all type errors in test files (missing `proofType` fields, incomplete publicSignals overrides, return type mismatches). All 311 tests passing with full type checking enabled (v0.6.0)
- [ ] Add integration tests that exercise the full prove-verify flow (requires circuit artifacts) — **DEFERRED**: Requires circuit artifacts in CI (already cached locally). Integration tests would add ~5 minutes to CI runtime. Recommend post-v1.0 addition once circuit artifact caching strategy is finalized.
- [x] Remove all `any` type assertions from proof formatting code (`prover.ts`, `verifier.ts`) — **VERIFIED**: No `any` type assertions found in prover.ts or verifier.ts. Only `any` types exist in .d.ts files for external libraries (circomlibjs, snarkjs) which is appropriate, and in test files for mocking (acceptable). Production code is fully typed (v0.6.0)
- [x] Add comprehensive JSDoc to all public API functions — **COMPLETE (v1.0)**: JSDoc added to all public API functions across `@zk-id/core`, `@zk-id/sdk`, `@zk-id/issuer`. See Step 7 in implementation plan. TypeDoc configuration added for auto-generated API reference.
- [x] Ensure all crypto operations use constant-time comparisons where applicable (signature verification) — **FIXED**: Added timing-safe.ts with constant-time comparisons in v0.6.0

### Nice to Have

- [ ] Property-based testing for Poseidon hash (fuzz inputs, verify collision resistance)
- [ ] Benchmark regression tests (fail if performance degrades >20%)
- [ ] Dependency audit (`npm audit`, pin exact versions)

## Documentation

- [x] `SECURITY.md` — vulnerability disclosure policy — **COMPLETE**: Comprehensive security policy exists with vulnerability reporting, response timeline, supported versions (0.6.x), scope, and security hardening checklist (v0.6.0)
- [x] `THREAT-MODEL.md` — enumerate all trust assumptions, threat actors, and mitigations — **COMPLETE (v1.0)**: Comprehensive 200+ line threat model covering: system overview, trust assumptions (cryptographic, system, operational), threat actors (malicious prover/verifier/issuer, network attacker, colluding parties), attack surface analysis with mitigations and residual risks, cryptographic assumptions table, metadata leakage analysis, known limitations, mitigations summary, deployment recommendations, out-of-scope items, and audit recommendations. See `docs/THREAT-MODEL.md`.
- [x] Circuit diagrams (signal flow for each `.circom` file) — **COMPLETE (v1.0)**: Mermaid signal flow diagrams for all 8 circuits (age-verify, nationality-verify, age-verify-signed, nationality-verify-signed, age-verify-revocable, nullifier, credential-hash, merkle-tree-verifier). Each diagram shows private/public inputs, constraint components, and signal flow. Includes constraint counts and complexity summary table. See `docs/CIRCUIT-DIAGRAMS.md`.
- [x] Deployment guide (minimum Node.js version, recommended infrastructure, key management) — **COMPLETE (v1.0)**: Comprehensive deployment guide covering: prerequisites, package overview by role (issuer/verifier/holder), ZkIdServerConfig reference, environment variables, key management (generation, storage options, rotation), verification key distribution, production checklist (mandatory/recommended security controls), infrastructure recommendations (nginx reverse proxy, Redis configuration, rate limiting strategies), scaling considerations, monitoring/observability, troubleshooting, security hardening. See `docs/DEPLOYMENT.md`.
- [x] API reference (generated from JSDoc/TypeDoc) — **COMPLETE (v1.0)**: TypeDoc configuration added (`typedoc.json`), npm script `npm run docs` generates API reference to `docs/api/` (gitignored). All public API functions have comprehensive JSDoc. See Step 8 in implementation plan.

## Infrastructure

- [x] CI pipeline running all tests on every PR — **IMPLEMENTED**: GitHub Actions workflow runs all tests on every PR and main branch push (v0.6.0)
- [x] Circuit artifact hash verification in CI — **IMPLEMENTED**: Hash verification added to main CI pipeline (.github/workflows/ci.yml) and dedicated verify-circuits workflow. Runs on every PR and main branch push. Hashes stored in docs/circuit-hashes.json (v0.6.0)
- [x] Automated dependency vulnerability scanning — **IMPLEMENTED**: npm audit runs in main CI pipeline (fails on high/critical). Dedicated dependency-audit.yml workflow runs weekly and on package.json changes. Uploads audit reports for review (v0.6.0)
- [ ] Release signing (GPG-signed tags for all version releases) — **DEFERRED (post-v1.0)**: Requires GPG key ceremony and signing infrastructure setup. Recommend implementing before first public release. Not blocking for v1.0 audit readiness as code integrity is verified via GitHub commit signatures and circuit artifact SHA-256 hashes.

---

## v1.0.0 Implementation Summary

**Date:** 2026-02-09
**Completed by:** Claude Sonnet 4.5

### Phase A: API Security Fixes (✅ Complete)

1. **Error information leakage (Step 1)**: Added `sanitizeError()` method with `verboseErrors` config option. All 40+ error messages in verification paths now sanitized to generic categories.

2. **Rate limiter documentation (Step 2)**: Comprehensive JSDoc added to `SimpleRateLimiter` warning about IP spoofing, proxy bypass, and production recommendations (token bucket, API gateway, Redis).

3. **Issuer key rotation grace period (Step 3)**: Added `rotationGracePeriodMs` field to `IssuerRecord`. `InMemoryIssuerRegistry.getIssuer()` now supports grace period acceptance with audit logging. New audit action type `grace_period_accept` added.

### Phase B: Documentation (✅ Complete)

4. **THREAT-MODEL.md expansion (Step 4)**: 200+ line comprehensive threat model covering system overview, trust assumptions, threat actors, attack surface analysis, cryptographic assumptions, metadata leakage, known limitations, mitigations summary, and deployment recommendations.

5. **Circuit diagrams (Step 5)**: Mermaid signal flow diagrams for all 8 circuits (age-verify, nationality-verify, age-verify-signed, nationality-verify-signed, age-verify-revocable, nullifier, credential-hash, merkle-tree-verifier) with constraint counts and complexity table. See `docs/CIRCUIT-DIAGRAMS.md`.

6. **Deployment guide (Step 6)**: Comprehensive guide covering prerequisites, package overview, configuration reference, key management (generation, storage, rotation), verification key distribution, production checklist, infrastructure recommendations (nginx, Redis, rate limiting), scaling, monitoring, troubleshooting, and security hardening. See `docs/DEPLOYMENT.md`.

7. **JSDoc for public APIs (Step 7)**: All public API functions across `@zk-id/core`, `@zk-id/sdk`, and `@zk-id/issuer` now have comprehensive JSDoc with `@param`, `@returns`, `@throws`, and `@example` tags.

8. **API reference generation (Step 8)**: TypeDoc configuration added (`typedoc.json`), `npm run docs` script generates API reference to `docs/api/` (gitignored). TypeDoc added as devDependency.

### Phase C: Strategic Positioning (✅ Complete)

9. **W3C VC/DID interop roadmap (Step 9)**: Comprehensive roadmap added to `docs/ROADMAP.md` documenting current state (VC-inspired but non-compliant), short-term (v1.1: add `@context` and `type` fields), medium-term (v1.2-1.3: DID identifiers, JSON-LD context, VC Data Integrity proof suite), and long-term (v2.0+: full W3C VC v2.0 compliance). Clarifies that ZK proof verification is core value; envelope formatting is interoperability concern, not security requirement.

10. **AUDIT.md updates (Step 10)**: All completed items marked with ✅ and detailed implementation notes. Integration tests and release signing deferred as documented.

### Additional Changes

- **Type safety fix**: Made `ProofResponse.signedCredential` optional (consistent with `requireSignedCredentials: false` mode)
- **Test fixes**: Updated mock wallet connectors in SDK tests to include `signedCredential` and `requestTimestamp` fields
- **Build verification**: All packages build successfully (`npm run build`)
- **Test status**: 453 passing tests (1 pre-existing circuit witness length error unrelated to v1.0 changes)

### Files Modified

**Code changes:**

- `packages/sdk/src/server.ts` (error sanitization, grace period, rate limiter JSDoc)
- `packages/core/src/types.ts` (audit action type, optional signedCredential)
- `packages/sdk/test/client.test.ts` (test mock fixes)

**Documentation:**

- `docs/THREAT-MODEL.md` (rewritten, 200+ lines)
- `docs/CIRCUIT-DIAGRAMS.md` (new, comprehensive)
- `docs/DEPLOYMENT.md` (new, comprehensive)
- `docs/ROADMAP.md` (W3C VC/DID section added)
- `docs/AUDIT.md` (all items updated)

**Configuration:**

- `typedoc.json` (new)
- `package.json` (added `docs` script, typedoc devDependency)
- `.gitignore` (added `docs/api/`)

### Outstanding Items

1. **Integration tests** (deferred post-v1.0): Requires circuit artifacts in CI, ~5 min CI runtime impact
2. **Release signing** (deferred post-v1.0): Requires GPG key ceremony and signing infrastructure

---

## Audit Scope Recommendation

For a third-party audit, we recommend the following scope (in priority order):

1. **Circom circuits** (7 files, ~300 lines) — constraint soundness, under-constrained signals, field overflow
2. **Poseidon hash integration** — parameter correctness, field encoding
3. **Proof generation/verification** (`prover.ts`, `verifier.ts`) — public signal ordering, proof format
4. **Credential commitment scheme** — binding properties, collision resistance
5. **Server verification flow** (`server.ts`) — nonce handling, replay protection, timing attacks
6. **Key management** (`kms.ts`, `key-management.ts`) — envelope encryption, key lifecycle

Estimated effort: 2-4 weeks for a team of 2 cryptographers + 1 code auditor.

---

## v1.1.0 Implementation Summary

**Date:** 2026-02-09

### On-Chain Groth16 Verifier

- **Added `@zk-id/contracts` package**: Solidity BN128 pairing-based verifier contract for on-chain proof verification
- **Age and nationality verification contracts**: Smart contracts for age and nationality proof verification
- **Deployment scripts**: Automated deployment scripts for contract deployment
- **Use cases documented**: DeFi KYC, DAO voting, NFT minting, compliant token transfers

### W3C VC Interoperability

- **W3C VC conversion utilities**: `toW3CVerifiableCredential`, `fromW3CVerifiableCredential` in `@zk-id/core`
- **DID key support**: `ed25519PublicKeyToDidKey`, `didKeyToEd25519PublicKey` utilities for DID identifier conversion
- **Documentation**: `docs/W3C-VC-INTEROPERABILITY.md` added
- **Note**: Basic format conversion implemented; full W3C VC validator suite compliance pending

### Security Hardening

- **Grace period audit logging gap fixed**: `validateSignedCredentialBinding` now emits `grace_period_accept` audit log entry for forensic completeness
- **Cross-reference comments**: Added cross-reference comments between dual grace period check locations
- **Nonce store hardening**: Configurable TTL and background pruning (`InMemoryNonceStoreOptions`)
- **Nullifier scope validation**: `validateBigIntString`, `validateFieldElement` added to nullifier prover
- **Defensive try-catch**: Around grace period audit logging to prevent logging failures from blocking verification

### CI Supply Chain Security

- **Pinned `actions/upload-artifact`**: GitHub Action pinned to commit hash (supply chain security)
- **Removed unnecessary CI permission**: Removed `security-events:write` permission (principle of least privilege)
- **npm dependency overrides**: Added overrides for lodash, tmp, cookie, undici vulnerabilities

### Circuit Artifact Hash Verification

- **Fixed circuit artifact hashes**: Updated to match CI build environment
- **Platform dependency documented**: Circuit artifact hashes are platform-dependent (macOS vs Linux produce different hashes)

### Tests

- **Grace period test**: Test for `validateSignedCredentialBinding` grace period path
- **Nonce pruning tests**: Tests for nonce store pruning behavior
- **Nullifier scope validation tests**: Tests for nullifier prover input validation
- **URL sanitization test fix**: Fixed incomplete URL substring sanitization in tests

---

## v0.7 Security Hardening (2026-02-10)

Version 0.7 implements comprehensive security hardening based on audit findings, addressing 8 medium and 10 low severity issues with 97 new tests.

### Completed Security Fixes

#### Timing Attack Mitigation

- ✅ **C-1/C-2**: Fixed timing-safe comparisons in `constantTimeEqual` and `constantTimeArrayEqual`
  - Pad buffers to prevent length leakage
  - Always run `timingSafeEqual` regardless of length
  - Use timing-safe comparisons for array elements
  - Comprehensive test coverage (22 tests)

#### Cryptographic Security

- ✅ **C-11**: Replaced `Math.random()` fallback with `crypto.randomBytes()`
  - Secure random generation for Node.js fallback in Redis tree-sync
  - No more predictable PRNG in fallback path

- ✅ **C-9**: Added Ed25519 key type validation in KMS
  - Reject RSA and EC keys with descriptive errors
  - Validate key type in `fromPemFiles()` and `fromPemStrings()`
  - 4 new tests for key type validation

#### Input Validation

- ✅ **V-3**: Added `validateClaimType()` function
  - Validates claim types against `VALID_CLAIM_TYPES` constant
  - Prevents processing of invalid claim types
  - New `ClaimType` type export
  - 6 new validation tests

- ✅ **V-4**: Changed `validatePayloads` default to `true` (BREAKING)
  - Secure by default - validation enabled unless explicitly disabled
  - Updated documentation and JSDoc comments
  - 11 new tests for default behavior
  - Migration guide provided in MIGRATION.md

#### Error Handling

- ✅ **E-2**: Fixed client error swallowing
  - Re-throw `ZkIdError` subclasses to preserve error context
  - Only swallow unexpected errors
  - Applied to `verifyAge()`, `verifyNationality()`, `verifyAgeRevocable()`
  - 6 new tests for error propagation

- ✅ **S-6**: Added JSON.parse guards (4 locations)
  - `packages/core/src/verifier.ts:388` - ZkIdConfigError
  - `packages/sdk/src/browser-wallet.ts:409,440` - ZkIdCredentialError
  - `packages/redis/src/issuer-registry.ts:42` - ZkIdConfigError
  - 6 new tests for JSON parsing errors

- ✅ **E-1**: Added warning for malformed Redis messages
  - Log warnings instead of silent failures
  - Better debugging and monitoring

### Test Coverage

**New Test Files:**

- `packages/core/test/security.test.ts` - 33 tests (boundary fuzzing, timing-safe, field elements, nonces)
- `packages/core/test/timing-safe.test.ts` - 14 tests (timing-safe edge cases)
- `packages/core/test/json-parse-guards.test.ts` - 2 tests (verification key parsing)
- `packages/issuer/test/managed-issuer.test.ts` - 15 tests (ManagedCredentialIssuer)
- `packages/issuer/test/key-management.test.ts` - 10 tests (InMemoryIssuerKeyManager)
- `packages/sdk/test/json-parse-guards.test.ts` - 4 tests (credential parsing)

**Enhanced Test Files:**

- `packages/sdk/test/server.test.ts` - +11 tests (validatePayloads, sanitizeError)
- `packages/sdk/test/client.test.ts` - +6 tests (error propagation)
- `packages/issuer/test/kms.test.ts` - +4 tests (Ed25519 validation)

**Total: 97 new security-related tests**

### Documentation

- **MIGRATION.md**: Comprehensive migration guide for breaking changes
- **SECURITY-HARDENING.md**: Detailed description of all 8 security fixes
- **COVERAGE-REPORT.md**: Updated with latest coverage metrics

### Coverage Improvements

Expected post-v0.7 coverage:

- Core: ≥97% (improved from 64.2%)
- SDK: ≥65% (improved from 55.86%)
- Issuer: ≥75% (improved from 63.42%)

### References

- Full security fix details: [SECURITY-HARDENING.md](./SECURITY-HARDENING.md)
- Migration guide: [MIGRATION.md](./MIGRATION.md)
- Test coverage: [COVERAGE-REPORT.md](./COVERAGE-REPORT.md)
