# @zk-id/core

**Core library for zero-knowledge identity verification**

This is the foundational package for the zk-id protocol. It provides credential creation, ZK proof generation/verification, revocation management, nullifiers, BBS selective disclosure, W3C VC interoperability, and all shared types. All other `@zk-id/*` packages depend on it.

## Features

### Credential Creation

- **createCredential** — Create Poseidon-based credentials binding birthYear, nationality, and salt
- **validateCredential** — Validate credential well-formedness
- **deriveCommitment** — Recompute credential commitment from components

### Proof Generation

- **generateAgeProof** — Prove age >= minAge without revealing birth year
- **generateNationalityProof** — Prove nationality match without revealing credential
- **generateAgeProofRevocable** — Age proof with Merkle tree inclusion check
- **generateNullifierProof** — Age proof with nullifier for sybil resistance
- **generateAgeProofAuto** / **generateNationalityProofAuto** — Auto-resolve circuit artifact paths
- **Signed variants** — `generateAgeProofSigned`, `generateNationalityProofSigned` for in-circuit signature verification

### Proof Verification

- **verifyAgeProof** — Verify age proofs off-chain
- **verifyNationalityProof** — Verify nationality proofs off-chain
- **verifyAgeProofRevocable** — Verify age proofs with revocation check
- **verifyBatch** — Batch verify multiple proofs efficiently
- **validateProofConstraints** — Validate proof public signals against constraints
- **Signed verifiers** — `verifyAgeProofSignedWithIssuer`, `verifyNationalityProofSignedWithIssuer`

### Revocation

- **InMemoryRevocationStore** — In-memory revocation tracking (testing only)
- **InMemoryValidCredentialTree** — Sparse Merkle tree for valid credentials
- **SparseMerkleTree** — Generic sparse Merkle tree implementation (depth 10, 1,024 leaves)
- **UnifiedRevocationManager** — Unified interface for revocation and validity tracking

### Nullifiers

- **computeNullifier** — Compute nullifier from credential and scope
- **createNullifierScope** — Create domain-specific nullifier scopes
- **consumeNullifier** — Mark nullifier as used (sybil resistance)
- **InMemoryNullifierStore** — In-memory nullifier tracking (testing only)

### BBS Selective Disclosure

- **generateBBSKeyPair** — Generate BBS+ key pairs for selective disclosure
- **deriveBBSDisclosureProof** — Create selective disclosure proofs
- **verifyBBSDisclosureProof** — Verify selective disclosure proofs

### W3C VC Interoperability

- **toW3CVerifiableCredential** — Convert zk-id credentials to W3C Verifiable Credentials
- **fromW3CVerifiableCredential** — Parse W3C VCs into zk-id format
- **ed25519PublicKeyToDidKey** — Convert Ed25519 public keys to DID key format

### Hashing

- **poseidonHash** — Poseidon hash function (ZK-friendly, 3-input)
- **poseidonHashHex** — Poseidon hash returning hex string

### Protocol Versioning

- **PROTOCOL_VERSION** — Current protocol version constant
- **isProtocolCompatible** — Check version compatibility
- **buildDeprecationHeaders** — Build HTTP headers for version deprecation

### Validation

- **validateBirthYear** — Validate birth year range (1900-current)
- **validateNationality** — Validate ISO 3166-1 numeric codes
- **validateFieldElement** — Validate field element bounds for BN128 curve
- **validateMinAge** / **validateNonce** / **validateRequestTimestamp** — Validate proof inputs

## Installation

```bash
npm install @zk-id/core
```

**Note:** Proof generation requires `@zk-id/circuits` for compiled circuit artifacts (WASM, zkey files).

## Quick Start

```typescript
import { createCredential, generateAgeProofAuto, verifyAgeProof } from '@zk-id/core';

// 1. Create a credential (private, stored in user's wallet)
const credential = await createCredential(1995, 840); // birth year, USA

// 2. Generate a proof (client-side, in browser)
const proof = await generateAgeProofAuto(
  credential,
  18, // minAge
  'nonce-123',
  Date.now(),
);

// 3. Verify the proof (server-side)
const isValid = await verifyAgeProof(proof, verificationKey);
console.log('Age verified:', isValid); // true, without revealing birth year
```

## Key Concepts

### Poseidon Commitments

Credentials use Poseidon hash to create a binding commitment to three fields: `birthYear`, `nationality`, and `salt`. This commitment is included as a public signal in all proofs, ensuring the proof corresponds to a specific credential without revealing its contents.

### Proof Types

- **age-verify** — Basic age proof (~653 constraints, ~0.3s proving)
- **nationality-verify** — Basic nationality proof (~608 constraints, ~0.3s proving)
- **age-verify-signed** — Age proof with EdDSA signature verification (~20k constraints, ~15s proving)
- **age-verify-revocable** — Age proof with Merkle inclusion check (~5.9k constraints, ~2.5s proving)
- **nullifier** — Nullifier computation for sybil resistance (~1.1k constraints, ~0.4s proving)

### Auto vs Manual Path Variants

- **`*Auto` functions** (e.g., `generateAgeProofAuto`) — Automatically resolve circuit artifact paths using `require.resolve`. Best for standard deployments.
- **Manual functions** (e.g., `generateAgeProof`) — Accept explicit `wasmPath` and `zkeyPath` parameters. Use for custom circuit locations or non-Node.js environments.

## Production Notes

- **In-memory stores are for testing only** — Use `@zk-id/redis` or Postgres-backed stores for production deployments. In-memory stores lose data on restart and don't scale horizontally.
- **BBS selective disclosure** — Requires `@digitalbazaar/bbs-signatures` (ESM module, loaded lazily). Not included as a direct dependency to keep bundle size small.
- **Recursive proof aggregation** — Currently scaffold-only. The `recursive.ts` module provides structure but aggregation circuits are not implemented.
- **EdDSA signed circuits** — Use BabyJub EdDSA, which is NOT compatible with standard Ed25519. Requires ~20k constraints per proof (~15s proving time).

## Testing

```bash
npm test
```

Tests cover all proof types, revocation, nullifiers, BBS disclosure, W3C VC conversion, and validation logic.

## Related Packages

- `@zk-id/circuits` — Circom circuits and compiled artifacts
- `@zk-id/sdk` — Client and server SDK for web applications
- `@zk-id/issuer` — Credential issuance with key management
- `@zk-id/contracts` — On-chain Solidity verifiers
- `@zk-id/redis` — Production-ready Redis stores

## License

Apache-2.0
