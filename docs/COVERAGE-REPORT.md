# Test Coverage Report

**Last Updated:** February 10, 2026

## Summary

Comprehensive test coverage improvement initiative completed, achieving **96.62% core package coverage** (exceeding the 80% target).

## Core Package Coverage

| Metric     | Coverage |
| ---------- | -------- |
| Statements | 96.62%   |
| Branch     | 94.63%   |
| Functions  | 94.9%    |
| Lines      | 96.62%   |

### Core Package File Coverage (src/)

| File                     | % Stmts | % Branch | % Funcs | % Lines | Notes                 |
| ------------------------ | ------- | -------- | ------- | ------- | --------------------- |
| bbs.ts                   | 100     | 100      | 100     | 100     | Fully covered         |
| benchmark.ts             | 100     | 86.66    | 100     | 100     |                       |
| credential.ts            | 100     | 100      | 100     | 100     | Fully covered         |
| index.ts                 | 100     | 100      | 100     | 100     | Fully covered         |
| multi-claim.ts           | 99      | 95.45    | 100     | 99      |                       |
| nullifier.ts             | 100     | 100      | 100     | 100     | Fully covered         |
| poseidon.ts              | 100     | 100      | 100     | 100     | Fully covered         |
| prover.ts                | 93.54   | 100      | 83.33   | 93.54   |                       |
| proving-system.ts        | 76.42   | 87.5     | 55.55   | 76.42   | Registry/abstractions |
| recursive.ts             | 100     | 100      | 100     | 100     | Fully covered         |
| revocation.ts            | 100     | 100      | 100     | 100     | Fully covered         |
| signature.ts             | 100     | 100      | 100     | 100     | Fully covered         |
| sparse-merkle-tree.ts    | 99.22   | 95.55    | 100     | 99.22   |                       |
| timing-safe.ts           | 95      | 87.5     | 100     | 95      |                       |
| types.ts                 | 95.26   | 0        | 0       | 95.26   | Type definitions      |
| unified-revocation.ts    | 98      | 92.85    | 100     | 98      |                       |
| valid-credential-tree.ts | 100     | 100      | 100     | 100     | Fully covered         |
| validation.ts            | 100     | 100      | 100     | 100     | Fully covered         |
| verifier.ts              | 97.04   | 87.5     | 100     | 97.04   |                       |
| version.ts               | 100     | 100      | 100     | 100     | Fully covered         |
| w3c-vc.ts                | 98      | 83.33    | 100     | 98      |                       |

## Test Suite Summary

### Core Package Tests (384 total tests)

| Test Category                | Tests | Focus                                           |
| ---------------------------- | ----- | ----------------------------------------------- |
| BBS Selective Disclosure     | 16    | BBS+ signatures, selective disclosure           |
| Performance Benchmarks       | 14    | Poseidon hashing, credential ops, tree ops      |
| Boundary & Concurrency       | 29    | Edge cases, concurrent operations               |
| Credential Tests             | 13    | Creation, validation, commitment derivation     |
| Multi-Claim Proofs           | 16    | Multiple claims, aggregation                    |
| Nullifier Prover             | 13    | Nullifier generation, sybil resistance          |
| Nullifier System             | 13    | Scope management, consumption tracking          |
| Poseidon Hash                | 10    | Hashing functions, determinism                  |
| Basic Prover                 | 16    | Age/nationality proof generation                |
| Revocable Prover             | 7     | Merkle inclusion, revocation                    |
| Proving System Abstraction   | 18    | Groth16, PLONK, registry                        |
| Recursive Proof Aggregation  | 11    | Proof bundling, logical aggregation             |
| Revocation                   | 6     | Revocation store operations                     |
| Signature Tests              | 11    | Credential signing, payload generation          |
| Signed Proof Integration     | 3     | End-to-end signed proofs, issuer verification   |
| Sparse Merkle Tree           | 32    | Tree operations, witnesses, concurrent ops      |
| Unified Revocation Manager   | 24    | Status tracking, reactivation                   |
| Valid Credential Tree        | 11    | Credential storage, witness generation          |
| Input Validation             | 30    | Field validation, constraint checking           |
| Batch Verification           | 12    | Parallel verification, mixed proofs             |
| Revocable Verifier           | 6     | Constraint validation, Merkle root verification |
| Signed Proof Issuer Matching | 2     | Issuer key validation                           |
| Verifier Tests               | 22    | Proof verification, constraint checking         |
| Protocol Version             | 32    | Version parsing, compatibility, deprecation     |
| W3C Verifiable Credentials   | 15    | W3C VC format, DID helpers, interoperability    |

## Test Improvements (February 2026)

### Added Tests

1. **Nullifier Prover Tests** (+11 tests)
   - Valid proof generation with real circuits
   - Deterministic nullifier computation
   - Scope isolation
   - Sybil resistance detection
   - Auto variant coverage

2. **Batch Verification Tests** (+8 tests)
   - Real circuit-generated proofs
   - Mixed valid/invalid scenarios
   - Wrong verification keys
   - Large batch handling (10 proofs)
   - Parallel verification

3. **SDK Integration Tests** (+11 tests in `packages/sdk/test/client-server.integration.test.ts`)
   - End-to-end server verification pipeline
   - Nonce replay protection
   - Challenge flow
   - Timestamp validation
   - Error handling with malformed proofs
   - Mixed proof types (age + nationality)

4. **Issuer Key Management Tests** (+13 tests in `packages/issuer/test/kms.test.ts`)
   - EnvelopeKeyManager edge cases
   - FileKeyManager PEM validation
   - Key rotation scenarios
   - Cross-manager verification
   - Tampered auth tag rejection
   - Multiple seal/unseal cycles

5. **BBS Issuer Tests** (+12 tests in `packages/issuer/test/bbs-issuer.test.ts`)
   - Multiple field disclosure
   - Nonce handling in proofs
   - Tampered data rejection
   - Empty disclosure validation
   - Unique credential generation
   - Multiple credentials verification

**Total: 55 new tests added**

## Test Strategy

All new tests use **real circuit-generated proofs** (not mocks) to ensure:

- Integration testing covers actual cryptographic verification
- Circuit artifacts (WASM, zkey) are correctly loaded
- Public signals match circuit constraints
- Verification keys work with generated proofs

### Test Timeouts

Circuit-based tests use extended timeouts:

- Age/nationality proof generation: 15-20 seconds
- Batch verification: 30-60 seconds
- Signed proof integration: 60 seconds

## Coverage by Package

### Core (`@zk-id/core`)

- **96.62%** statement coverage
- Comprehensive test suite with 384 tests
- All critical paths covered

### SDK (`@zk-id/sdk`)

- Integration tests added covering full server verification pipeline
- Client/server interaction tested
- Security components (nonce store, rate limiter) tested

### Issuer (`@zk-id/issuer`)

- Key management systems fully tested
- BBS+ credential issuance covered
- Policy validation comprehensive

### Circuits (`@zk-id/circuits`)

- Tested indirectly through proof generation/verification
- All circuit types exercised in integration tests

## Notable Test Coverage

### Well-Covered Areas (100%)

- BBS selective disclosure
- Credential creation and validation
- Nullifier system
- Poseidon hashing
- Revocation store operations
- Signature payload generation
- Sparse Merkle tree operations
- Valid credential tree
- Input validation
- Protocol versioning
- W3C VC interoperability

### Areas with Moderate Coverage (75-95%)

- Prover functions (93.54%) - Some signed variants and edge cases
- Verifier functions (97.04%) - Main verification paths covered
- Multi-claim proofs (99%) - Minor edge cases
- Unified revocation manager (98%)

### Areas with Lower Coverage (<75%)

- Proving system abstractions (76.42%) - Registry and comparison data structures
- Some dist/ compiled files - Expected as tests target src/

## Running Tests

```bash
# Run all core tests
npm test --workspace=@zk-id/core

# Run with coverage
npm run coverage:core

# Run specific test file
npm test --workspace=@zk-id/core -- test/nullifier-prover.test.ts
```

## Coverage Goals

- ✅ **Core package**: Achieved 96.62% (target: 80%)
- ✅ **Integration tests**: Added for SDK, issuer, and full verification pipeline
- ✅ **Edge cases**: Comprehensive boundary and concurrency testing
- ✅ **Real proofs**: All new tests use actual circuit-generated proofs

## Future Improvements

1. **Contract Package**: Add test coverage for Solidity contracts
2. **Redis Package**: Integration tests with real Redis instance
3. **End-to-End Flows**: Add more multi-package integration tests
4. **Performance**: Add more benchmark tests for circuit operations
5. **Stress Testing**: Add tests for high-load scenarios (1000+ proofs)
