# Test Coverage Report

Generated: 2026-02-10

## Summary

| Package           | Lines  | Branches | Functions | Statements |
| ----------------- | ------ | -------- | --------- | ---------- |
| **@zk-id/core**   | 64.2%  | 84.58%   | 55.01%    | 64.2%      |
| **@zk-id/sdk**    | 55.86% | 75.35%   | 52.38%    | 55.86%     |
| **@zk-id/issuer** | 63.42% | 80.88%   | 48.02%    | 63.42%     |

## Coverage Goals

- **Critical paths**: 90%+ (credential creation, proof generation/verification)
- **Core functionality**: 80%+ (most business logic)
- **Utility functions**: 70%+ (helpers, formatters)
- **Error paths**: 60%+ (error handling, edge cases)

## Priority Gaps (@zk-id/core)

### 🔴 Critical (Need Immediate Attention)

**prover.ts** - 39.47% lines, 16.66% functions

- Missing: Signed proof generation (`generateAgeProofSigned`, `generateNationalityProofSigned`)
- Missing: Revocable proof generation (`generateAgeProofRevocable`)
- Missing: Nullifier proof generation (`generateNullifierProof`)
- Missing: `*Auto` variants that auto-resolve circuit paths
- **Impact**: These are core features used in production

**signature.ts** - 43.24% lines, 0% functions

- Missing: All circuit signature functions
- Missing: `circuitSignatureInputs`, `verifyCircuitSignature`
- **Impact**: Required for in-circuit EdDSA signature verification

### 🟡 Important (Should Be Added)

**proving-system.ts** - 76.42% lines, 55.55% functions

- Missing: Batch proof generation
- Missing: Proof system abstraction methods
- Missing: Error handling paths

**verifier.ts** - 78.34% lines, 84.61% functions

- Missing: Batch verification functions
- Missing: Some signed verifier variants
- Missing: Edge case handling

**timing-safe.ts** - 90% lines, 71.42% branches

- Missing: Some timing attack mitigation branches
- **Impact**: Security-sensitive code

### 🟢 Good Coverage (Minor Gaps)

- **credential.ts** - 100% ✓
- **nullifier.ts** - 100% ✓
- **poseidon.ts** - 100% ✓
- **revocation.ts** - 100% ✓
- **validation.ts** - 100% ✓
- **version.ts** - 100% ✓
- **valid-credential-tree.ts** - 100% ✓
- **bbs.ts** - 100% ✓
- **benchmark.ts** - 100% ✓
- **sparse-merkle-tree.ts** - 99.22% ✓
- **multi-claim.ts** - 99% ✓
- **unified-revocation.ts** - 98% ✓
- **w3c-vc.ts** - 98% ✓

## Files Needing Tests

### Core Package (packages/core/test/)

**High Priority:**

1. **prover-signed.test.ts** (NEW)
   - Test `generateAgeProofSigned`
   - Test `generateNationalityProofSigned`
   - Test auto variants
   - Test error cases (invalid signature, wrong issuer key)

2. **prover-revocable.test.ts** (NEW)
   - Test `generateAgeProofRevocable`
   - Test with valid Merkle proofs
   - Test error cases (invalid path, wrong root)

3. **prover-nullifier.test.ts** (NEW)
   - Test `generateNullifierProof`
   - Test different scopes
   - Test deterministic nullifier generation

4. **signature.test.ts** (NEW)
   - Test `circuitSignatureInputs`
   - Test `verifyCircuitSignature`
   - Test with real EdDSA signatures

**Medium Priority:**

5. **verifier-batch.test.ts** (ENHANCE)
   - Add tests for batch verification
   - Test mixed proof types
   - Test failure handling

6. **proving-system.test.ts** (NEW)
   - Test proof system abstraction
   - Test error handling

### SDK Package (packages/sdk/test/)

Coverage: 55.86% - Needs improvement

**High Priority:**

1. **client.test.ts** (ENHANCE)
   - Test all verification methods
   - Test revocation root fetching
   - Test error handling

2. **server-signed.test.ts** (NEW)
   - Test signed credential verification
   - Test issuer registry integration
   - Test key rotation

3. **browser-wallet.test.ts** (NEW)
   - Test IndexedDB storage
   - Test backup/restore
   - Test credential listing

### Issuer Package (packages/issuer/test/)

Coverage: 63.42% - Needs improvement

**High Priority:**

1. **issuer.test.ts** (ENHANCE)
   - Test revocation
   - Test signature verification
   - Test audit logging

2. **kms.test.ts** (NEW)
   - Test EnvelopeKeyManager seal/unseal
   - Test FileKeyManager
   - Test key rotation

3. **bbs-issuer.test.ts** (NEW)
   - Test BBS credential issuance
   - Test selective disclosure
   - Test BBS signature verification

4. **policy.test.ts** (NEW)
   - Test policy validation
   - Test key rotation checks
   - Test rotation plan generation

## Running Coverage Reports

```bash
# All packages
npm run coverage

# Specific package
npm run coverage:core
npm run coverage:sdk
npm run coverage:issuer

# HTML report (open in browser)
npm run coverage
open coverage/index.html
```

## Coverage Commands

The following commands are available:

```bash
# Generate coverage reports
npm run coverage              # All packages, HTML + text + lcov
npm run coverage:core         # Core package only, text output
npm run coverage:sdk          # SDK package only, text output
npm run coverage:issuer       # Issuer package only, text output
```

## Next Steps

1. ✅ Set up c8 coverage tooling
2. ✅ Add coverage scripts to package.json
3. ✅ Generate initial coverage reports
4. ⏳ Add missing tests for critical paths (prover.ts, signature.ts)
5. ⏳ Add missing tests for SDK and issuer packages
6. ⏳ Set up CI/CD coverage reporting (Codecov or Coveralls)
7. ⏳ Add coverage badges to README
8. ⏳ Set minimum coverage thresholds in CI

## Notes

- Circuit tests are not included in coverage (Circom, not TypeScript)
- Contract tests use Hardhat's built-in coverage (separate tool)
- Example web app has no tests (intentional, it's a demo)
- Dist/ files show up in coverage but are generated code (ignore them)

## Coverage Trends

Target for v1.0:

- Core: 80%+ lines, 90%+ for critical paths
- SDK: 75%+ lines
- Issuer: 75%+ lines

---

Last updated: 2026-02-10
