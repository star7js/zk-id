# Security Hardening

This document describes security improvements implemented in v0.7, addressing findings from the security audit.

## Summary

Version 0.7 implements 8 security fixes addressing 8 medium and 10 low severity findings:

- **Timing-safe comparisons**: Fixed potential timing attacks
- **Random number generation**: Replaced insecure fallback
- **Input validation**: Added claim type validation
- **Error handling**: Improved error propagation and JSON parsing
- **Key management**: Added Ed25519 key type validation
- **Message handling**: Added logging for malformed messages

All fixes are covered by comprehensive security test suites.

---

## Security Fixes

### C-1/C-2: Fix Timing-Safe Comparisons

**Severity**: Medium
**Component**: `packages/core/src/timing-safe.ts`

#### Issue

The `constantTimeEqual` function had timing vulnerabilities:

- Early return on length mismatch leaked timing information
- Direct length check before comparison was vulnerable to timing attacks
- `constantTimeArrayEqual` used JavaScript `===` operator, not timing-safe

#### Fix

```typescript
// BEFORE: Early return leaks timing information
export function constantTimeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) {
    return false; // ❌ Timing leak
  }
  const bufA = Buffer.from(a, 'utf8');
  const bufB = Buffer.from(b, 'utf8');
  return timingSafeEqual(bufA, bufB);
}

// AFTER: Always runs timingSafeEqual, combines results
export function constantTimeEqual(a: string, b: string): boolean {
  const bufA = Buffer.from(a, 'utf8');
  const bufB = Buffer.from(b, 'utf8');

  // Pad shorter buffer to prevent length leakage
  const maxLength = Math.max(bufA.length, bufB.length);
  const paddedA = Buffer.alloc(maxLength);
  const paddedB = Buffer.alloc(maxLength);
  bufA.copy(paddedA);
  bufB.copy(paddedB);

  // Always run timingSafeEqual regardless of length
  const buffersEqual = timingSafeEqual(paddedA, paddedB);

  // Combine with length check
  return buffersEqual && a.length === b.length;
}
```

Array comparison also updated:

```typescript
// BEFORE: JavaScript === operator
result |= a[i] === b[i] ? 0 : 1; // ❌ Not timing-safe

// AFTER: Use constantTimeEqual for each element
result |= constantTimeEqual(a[i], b[i]) ? 0 : 1; // ✅ Timing-safe
```

#### Testing

- `packages/core/test/security.test.ts`: 8 timing-safe tests
- `packages/core/test/timing-safe.test.ts`: 14 dedicated tests
- Covers equal/unequal, different lengths, unicode, null bytes, very long strings

---

### C-11: Replace Math.random() Fallback

**Severity**: Medium
**Component**: `packages/redis/src/tree-sync.ts`

#### Issue

Fallback for older Node.js used cryptographically insecure `Math.random()`:

```typescript
// BEFORE: Insecure randomness
for (let i = 0; i < bytes; i++) {
  arr[i] = Math.floor(Math.random() * 256); // ❌ Predictable
}
```

#### Fix

```typescript
// AFTER: Use crypto.randomBytes for Node.js fallback
if (typeof globalThis !== 'undefined' && globalThis.crypto && globalThis.crypto.getRandomValues) {
  globalThis.crypto.getRandomValues(arr); // Browser
} else {
  const { randomBytes } = require('crypto');
  const buf = randomBytes(bytes);
  buf.copy(arr); // ✅ Cryptographically secure
}
```

#### Testing

- Covered by existing tree-sync tests
- Validates Redis pub/sub message generation

---

### V-3: Add validateClaimType()

**Severity**: Medium
**Component**: `packages/core/src/validation.ts`

#### Issue

No validation of claim types, allowing invalid types to be processed.

#### Fix

```typescript
/** Valid claim types for ZK identity proofs. */
export const VALID_CLAIM_TYPES = ['age', 'nationality', 'age-revocable'] as const;

/** Type representing valid claim types. */
export type ClaimType = (typeof VALID_CLAIM_TYPES)[number];

/**
 * Validate that a claim type is one of the recognized types.
 * @throws ZkIdValidationError if claim type is not valid
 */
export function validateClaimType(claimType: string): void {
  if (!VALID_CLAIM_TYPES.includes(claimType as ClaimType)) {
    throw new ZkIdValidationError(
      `Invalid claim type: ${claimType}. Must be one of: ${VALID_CLAIM_TYPES.join(', ')}`,
      'claimType',
    );
  }
}
```

#### Testing

- `packages/core/test/security.test.ts`: 6 validateClaimType tests
- Tests valid types, rejects unknown, empty, and similar-but-incorrect types

---

### V-4: Change validatePayloads Default (BREAKING CHANGE)

**Severity**: Medium
**Component**: `packages/sdk/src/server.ts`

#### Issue

Payload validation was opt-in (`default: false`), leaving servers vulnerable by default.

#### Fix

```typescript
// BEFORE: Opt-in validation (insecure by default)
if (this.config.validatePayloads) {
  // validate...
}

// AFTER: Opt-out validation (secure by default)
if (this.config.validatePayloads !== false) {
  // validate...
}
```

**Documentation updated**:

```typescript
/** Enable strict payload validation before verification (default: true).
 *  Set to false to disable validation. */
validatePayloads?: boolean;
```

#### Testing

- `packages/sdk/test/server.test.ts`: +11 tests
- Tests default behavior, explicit true/false, undefined

#### Migration

See [MIGRATION.md](./MIGRATION.md#v06--v07) for migration guide.

---

### E-2: Fix Client Error Swallowing

**Severity**: Low
**Component**: `packages/sdk/src/client.ts`

#### Issue

All errors were swallowed, losing important error context:

```typescript
// BEFORE: All errors swallowed
try {
  const isValid = await this.submitProof(proofResponse);
  return isValid;
} catch (error) {
  console.error('[zk-id] Age verification failed:', error);
  return false; // ❌ Loses error context
}
```

#### Fix

```typescript
// AFTER: Re-throw ZkIdError subclasses
try {
  const isValid = await this.submitProof(proofResponse);
  return isValid;
} catch (error) {
  // Re-throw ZkIdError subclasses to preserve error context
  if (error instanceof ZkIdError) {
    throw error; // ✅ Propagate typed errors
  }
  console.error('[zk-id] Age verification failed:', error);
  return false; // Swallow unexpected errors
}
```

Applied to three methods:

- `verifyAge()`
- `verifyNationality()`
- `verifyAgeRevocable()`

#### Testing

- `packages/sdk/test/client.test.ts`: +6 tests
- Tests re-throwing `ZkIdConfigError`, `ZkIdCredentialError`, `ZkIdProofError`
- Verifies non-ZkIdError errors are still swallowed

---

### S-6: Guard JSON.parse Calls

**Severity**: Low
**Components**: 4 locations

#### Issue

`JSON.parse` calls without error handling could throw unhelpful errors.

#### Fix

Added try-catch guards with typed errors:

**1. `packages/core/src/verifier.ts:388`**

```typescript
try {
  return JSON.parse(data);
} catch (error) {
  throw new ZkIdConfigError(
    `Failed to parse verification key from ${path}: ${error instanceof Error ? error.message : String(error)}`,
  );
}
```

**2-3. `packages/sdk/src/browser-wallet.ts:409, 440`**

```typescript
let parsed: SignedCredential;
try {
  parsed = JSON.parse(json) as SignedCredential;
} catch (error) {
  throw new ZkIdCredentialError(
    `Failed to parse credential JSON: ${error instanceof Error ? error.message : String(error)}`,
    'INVALID_CREDENTIAL_FORMAT',
  );
}
```

**4. `packages/redis/src/issuer-registry.ts:42`**

```typescript
let stored: StoredIssuerRecord;
try {
  stored = JSON.parse(value) as StoredIssuerRecord;
} catch (error) {
  throw new ZkIdConfigError(
    `Failed to parse issuer record from Redis: ${error instanceof Error ? error.message : String(error)}`,
  );
}
```

#### Testing

- `packages/core/test/json-parse-guards.test.ts`: +2 tests
- `packages/sdk/test/json-parse-guards.test.ts`: +4 tests
- Tests invalid JSON, structural validation, error types

---

### E-1: Add Warning for Malformed Redis Messages

**Severity**: Low
**Component**: `packages/redis/src/tree-sync.ts`

#### Issue

Malformed messages were silently ignored with no logging:

```typescript
try {
  event = JSON.parse(raw) as TreeSyncEvent;
} catch {
  return; // ❌ Silent failure
}
```

#### Fix

```typescript
try {
  event = JSON.parse(raw) as TreeSyncEvent;
} catch {
  console.warn('[zk-id] ignoring malformed message:', raw); // ✅ Log warning
  return;
}
```

#### Testing

- Covered by existing Redis tree-sync tests
- Validates message handling and error cases

---

### C-9: Add Ed25519 Key Type Check

**Severity**: Low
**Component**: `packages/issuer/src/kms.ts`

#### Issue

No validation that loaded keys are Ed25519, could accept RSA/EC keys.

#### Fix

Added key type validation in `fromPemFiles()` and `fromPemStrings()`:

```typescript
// Validate key type
if (privateKey.asymmetricKeyType !== 'ed25519') {
  throw new ZkIdCryptoError(
    `Invalid key type: expected ed25519, got ${privateKey.asymmetricKeyType}`,
  );
}
```

#### Testing

- `packages/issuer/test/kms.test.ts`: +4 tests
- Tests reject RSA keys, reject EC keys, accept Ed25519, descriptive errors

---

## Test Coverage

All security fixes are covered by comprehensive test suites:

### New Test Files

1. **`packages/core/test/security.test.ts`** (33 tests)
   - Boundary fuzzing for all validators
   - Timing-safe comparison tests
   - Field element boundary tests
   - Nonce edge cases
   - validateClaimType validation

2. **`packages/core/test/timing-safe.test.ts`** (14 tests)
   - constantTimeEqual edge cases
   - constantTimeArrayEqual edge cases
   - Unicode, null bytes, very long strings

3. **`packages/core/test/json-parse-guards.test.ts`** (2 tests)
   - Verification key JSON parsing

4. **`packages/sdk/test/json-parse-guards.test.ts`** (4 tests)
   - Credential JSON parsing in browser wallet

### Enhanced Test Files

1. **`packages/sdk/test/server.test.ts`** (+11 tests)
   - validatePayloads default behavior
   - Additional sanitizeError paths

2. **`packages/sdk/test/client.test.ts`** (+6 tests)
   - Error propagation (E-2 fix)
   - ZkIdError re-throwing

3. **`packages/issuer/test/kms.test.ts`** (+4 tests)
   - Ed25519 key type validation (C-9 fix)

**Total**: 74 new security-related tests

---

## Verification

To verify security hardening:

```bash
# Run all tests
npm test

# Run security-specific tests
npm test -- packages/core/test/security.test.ts
npm test -- packages/core/test/timing-safe.test.ts

# Run coverage
npm run coverage

# Lint code
npm run lint
```

Expected results:

- All tests pass
- Core package: ≥97% coverage
- SDK package: ≥65% coverage
- Issuer package: ≥75% coverage

---

## Audit Status

### Completed (v0.7)

- ✅ **C-1/C-2**: Timing-safe comparisons
- ✅ **C-11**: Secure random generation
- ✅ **V-3**: Claim type validation
- ✅ **V-4**: validatePayloads default
- ✅ **E-2**: Client error propagation
- ✅ **S-6**: JSON.parse guards (4 locations)
- ✅ **E-1**: Malformed message logging
- ✅ **C-9**: Ed25519 key type validation

### Remaining

See [AUDIT.md](./AUDIT.md) for full audit status and remaining items.

---

## References

- [MIGRATION.md](./MIGRATION.md) - Migration guide for breaking changes
- [AUDIT.md](./AUDIT.md) - Full security audit report
- [ARCHITECTURE.md](./ARCHITECTURE.md) - Error handling architecture
- [CHANGELOG.md](../CHANGELOG.md) - Detailed release notes

---

Last updated: 2026-02-10
