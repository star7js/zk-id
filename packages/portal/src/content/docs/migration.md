---
title: 'Migration Guide'
description: 'This document describes breaking changes and migration steps between versions.'
category: 'Operations'
order: 32
---

# Migration Guide

This document describes breaking changes and migration steps between versions.

## Table of Contents

- [v0.6 → v0.7](#v06--v07)
- [v0.5 → v0.6](#v05--v06)

---

## v0.6 → v0.7

### Breaking Changes

#### 1. validatePayloads now defaults to true (V-4 Security Fix)

**Impact**: Medium - Affects ZkIdServer configuration

**What changed:**

- `validatePayloads` config option now defaults to `true` instead of `false`
- Strict payload validation is now enabled by default for security

**Migration:**

```typescript
// BEFORE (v0.6): Validation was opt-in
const server = new ZkIdServer({
  verificationKeys: keys,
  // validatePayloads: false by default
});

// AFTER (v0.7): Validation is enabled by default
const server = new ZkIdServer({
  verificationKeys: keys,
  // validatePayloads: true by default
});

// To preserve old behavior (not recommended):
const server = new ZkIdServer({
  verificationKeys: keys,
  validatePayloads: false, // Explicitly disable
});
```

**Recommendation**: Keep the new default (`true`) for better security. Only disable if you have a specific reason and handle validation elsewhere.

#### 2. Client error propagation improved (E-2 Security Fix)

**Impact**: Low - Affects error handling in client SDK

**What changed:**

- `ZkIdClient` methods now re-throw `ZkIdError` subclasses instead of swallowing them
- Only unexpected errors are caught and return `false`
- Better error context for debugging

**Migration:**

```typescript
// BEFORE (v0.6): All errors were swallowed
const isValid = await client.verifyAge(18);
// Always returns boolean, no exceptions

// AFTER (v0.7): ZkIdError subclasses are propagated
try {
  const isValid = await client.verifyAge(18);
  // Returns boolean for unexpected errors
} catch (error) {
  if (error instanceof ZkIdConfigError) {
    // Handle configuration errors
  } else if (error instanceof ZkIdCredentialError) {
    // Handle credential errors
  } else if (error instanceof ZkIdProofError) {
    // Handle proof generation errors
  }
}
```

**Recommendation**: Add try-catch blocks around client verification calls to handle `ZkIdError` subclasses appropriately.

### Non-Breaking Changes

#### 3. Security Hardening (8 fixes)

The following security improvements were added:

- **C-1/C-2**: Improved timing-safe comparisons to prevent timing attacks
- **C-11**: Replaced `Math.random()` with `crypto.randomBytes()` for secure randomness
- **V-3**: Added `validateClaimType()` function for claim type validation
- **S-6**: Added JSON.parse guards with error handling in 4 locations
- **E-1**: Added warnings for malformed Redis messages
- **C-9**: Added Ed25519 key type validation in KMS

These changes are backwards compatible and require no migration.

#### 4. New Validation Exports

**What's new:**

- `validateClaimType(claimType: string)` - Validates claim types
- `VALID_CLAIM_TYPES` constant - Array of valid claim types
- `ClaimType` type - TypeScript type for valid claim types

**Usage:**

```typescript
import { validateClaimType, VALID_CLAIM_TYPES, ClaimType } from '@zk-id/core';

// Validate claim type
validateClaimType('age'); // OK
validateClaimType('invalid'); // Throws ZkIdValidationError

// Use in type annotations
const claimType: ClaimType = 'age-revocable';
```

---

## v0.5 → v0.6

### Breaking Changes

None - v0.6 was a non-breaking release focused on quality improvements.

### Major Changes

#### 1. Custom Error Classes

**What changed:**

- Introduced typed error hierarchy for better error handling
- Replaced generic `Error` with specific error types

**New error classes:**

```typescript
import {
  ZkIdError, // Base class
  ZkIdConfigError, // Configuration errors
  ZkIdValidationError, // Input validation errors
  ZkIdCredentialError, // Credential-related errors
  ZkIdCryptoError, // Cryptographic errors
  ZkIdProofError, // Proof generation/verification errors
} from '@zk-id/core';
```

**Migration:**

```typescript
// BEFORE (v0.5): Generic error checking
try {
  await issuer.issueCredential(1990, 840);
} catch (error) {
  console.error('Error:', error.message);
}

// AFTER (v0.6): Typed error handling
try {
  await issuer.issueCredential(1990, 840);
} catch (error) {
  if (error instanceof ZkIdValidationError) {
    // Handle validation error
    console.error('Invalid input:', error.field, error.message);
  } else if (error instanceof ZkIdCryptoError) {
    // Handle crypto error
    console.error('Crypto error:', error.message);
  }
}
```

#### 2. Code Quality Automation

**What changed:**

- Added ESLint for code quality enforcement
- Added Prettier for consistent code formatting
- Configured automatic formatting on save

**For contributors:**

```bash
# Lint code
npm run lint

# Auto-fix linting issues
npm run lint:fix

# Format code
npm run format

# Check formatting without modifying
npm run format:check
```

**Migration:** No code changes required. If you're contributing, ensure your editor is configured to use the project's ESLint and Prettier settings.

---

## Migration Checklist

### v0.6 → v0.7

- [ ] Review `validatePayloads` usage in `ZkIdServer` config
- [ ] Add try-catch blocks around `ZkIdClient` verification calls
- [ ] Update error handling to catch `ZkIdError` subclasses
- [ ] Test error scenarios to verify new behavior
- [ ] Update tests if they relied on old error swallowing behavior

### v0.5 → v0.6

- [ ] Update error handling to use typed error classes
- [ ] Configure ESLint and Prettier in your editor (for contributors)
- [ ] Run `npm run lint` and `npm run format` to check code quality
- [ ] Update catch blocks to handle specific error types

---

## Getting Help

If you encounter issues during migration:

1. Check the [CHANGELOG](../CHANGELOG.md) for detailed release notes
2. Review the [API documentation](./API.md)
3. See examples in the [examples/](../examples/) directory
4. Open an issue on [GitHub](https://github.com/yourusername/zk-id/issues)

---

Last updated: 2026-02-10
