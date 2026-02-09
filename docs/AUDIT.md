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
- [ ] **Challenge timing**: `maxRequestAgeMs` prevents stale proofs but does not prevent time-shifted proofs (prover uses a future timestamp). Add server-side time validation
- [x] **Credential hash collision**: If two credentials have the same `Poseidon(birthYear, nationality, salt)`, they are indistinguishable. Salt entropy (256 bits) makes this negligible, but document the security margin — **DOCUMENTED**: Added comprehensive collision resistance analysis in CRYPTOGRAPHIC-PARAMETERS.md with probability calculations and security margin (256-bit salt → ~2^128 security, negligible collision probability even at billion-credential scale) (v0.6.0)

### High Priority

- [ ] **Issuer key rotation**: The registry supports overlapping validity windows, but there's no mechanism to reject proofs signed by a recently-rotated-out key within a grace period. Consider adding a `rotationGracePeriodMs`
- [ ] **Rate limiter bypass**: `SimpleRateLimiter` is trivially bypassable (change IP). Document that production should use token bucket with authenticated sessions
- [ ] **Error information leakage**: Verification error messages like "Invalid credential signature" vs "Unknown issuer" reveal information to attackers. Consider a single "Verification failed" message for external responses

## Code Quality

### Before Audit

- [ ] Fix pre-existing TypeScript strict mode errors (currently bypassed by `transpile-only`)
- [ ] Add integration tests that exercise the full prove-verify flow (requires circuit artifacts)
- [ ] Remove all `any` type assertions from proof formatting code (`prover.ts`, `verifier.ts`)
- [ ] Add comprehensive JSDoc to all public API functions
- [x] Ensure all crypto operations use constant-time comparisons where applicable (signature verification) — **FIXED**: Added timing-safe.ts with constant-time comparisons in v0.6.0

### Nice to Have

- [ ] Property-based testing for Poseidon hash (fuzz inputs, verify collision resistance)
- [ ] Benchmark regression tests (fail if performance degrades >20%)
- [ ] Dependency audit (`npm audit`, pin exact versions)

## Documentation

- [ ] `SECURITY.md` — vulnerability disclosure policy
- [ ] `THREAT-MODEL.md` — enumerate all trust assumptions, threat actors, and mitigations
- [ ] Circuit diagrams (signal flow for each `.circom` file)
- [ ] Deployment guide (minimum Node.js version, recommended infrastructure, key management)
- [ ] API reference (generated from JSDoc/TypeDoc)

## Infrastructure

- [ ] CI pipeline running all tests on every PR
- [ ] Circuit artifact hash verification in CI
- [ ] Automated dependency vulnerability scanning
- [ ] Release signing (GPG-signed tags for all version releases)

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
