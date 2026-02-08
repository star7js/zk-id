# zk-id Protocol Specification

This document specifies the zk-id protocol for privacy-preserving identity verification.

## Version

**Protocol Version**: zk-id/1.0-draft
**Status**: Draft / Experimental
**Last Updated**: 2026-02-08

## Protocol Versioning

The zk-id protocol uses semantic versioning for wire-format compatibility, decoupled from npm package versions.

**Format**: `zk-id/<major>.<minor>[-suffix]`

**Version Components:**
- **Major version**: Incremented for breaking protocol changes (incompatible proof structures, public signals format changes)
- **Minor version**: Incremented for backward-compatible additions (new claim types, optional fields)
- **Suffix**: Pre-release indicators (`-draft`, `-rc1`, etc.)

**Compatibility Rules:**
- Implementations with the same major version MUST be compatible
- Minor version differences SHOULD be handled gracefully
- Clients and servers communicate protocol version via the `X-ZkId-Protocol-Version` HTTP header
- Browser clients should note that this custom header may trigger CORS preflight requests.
  - The SDK defaults to sending the header only for same-origin endpoints.
  - For cross-origin verification endpoints, either allow the header in CORS or set `protocolVersionHeader: "always"` in the SDK config.
- Servers may reject incompatible protocol versions with `400` (recommended for demo and strict deployments).
- Server SDKs can enforce this with `protocolVersionPolicy: "strict" | "warn" | "off"`.

**Compatibility Checking:**
```typescript
import { PROTOCOL_VERSION, isProtocolCompatible } from '@zk-id/core';

// Check if two versions are compatible
const compatible = isProtocolCompatible('zk-id/1.0-draft', 'zk-id/1.2');
// Returns true (same major version)
```

**Version History:**

| Version | Date | Changes |
|---------|------|---------|
| zk-id/1.0-draft | 2026-02-08 | Initial protocol specification with age, nationality, and age-revocable claim types |

## Goals

1. **Privacy**: Users prove eligibility without revealing personal data
2. **Security**: Proofs cannot be forged or reused maliciously
3. **Simplicity**: Easy integration for websites
4. **Performance**: Fast verification (<100ms)
5. **Decentralization**: No single point of failure or trust

## Actors

### Issuer

A trusted entity that verifies user identities and issues credentials.

**Examples**: Government identity services, banks, trusted identity providers

**Responsibilities:**
- Verify user identity through KYC/ID documents
- Issue signed credentials containing verified attributes with Ed25519 signatures
- Manage signing keys securely
- Maintain audit logs
- Handle credential revocation through revocation store

### User (Prover)

An individual who holds a credential and generates zero-knowledge proofs.

**Responsibilities:**
- Obtain credential from issuer
- Store credential securely
- Generate proofs when requested
- Protect private keys and salt values

### Verifier

A website or service that requests and verifies proofs.

**Responsibilities:**
- Request specific proofs (e.g., "prove age >= 18")
- Verify proofs cryptographically
- Implement replay protection
- Respect user privacy

## Data Structures

### Credential

```typescript
{
  id: string;              // Unique credential identifier (UUID)
  birthYear: number;       // Private: user's birth year (e.g., 1995)
  nationality: number;     // Private: ISO 3166-1 numeric code (e.g., 840 for USA)
  salt: string;            // Private: random 256-bit value (hex)
  commitment: string;      // Public: Poseidon(birthYear, nationality, salt)
  createdAt: string;       // ISO 8601 timestamp
}
```

**Privacy Properties:**
- `birthYear`, `nationality`, and `salt` are private, never shared
- `commitment` is public and can be shared freely
- `commitment` binds all credential attributes without revealing them
- Different proof circuits enable selective disclosure of attributes

### Signed Credential

```typescript
{
  credential: Credential;
  issuer: string;          // Issuer identifier (name or DID)
  signature: string;       // Issuer's Ed25519 signature over commitment
  issuedAt: string;        // ISO 8601 timestamp
}
```

**Signature**: Ed25519 (EdDSA) signatures provide production-grade asymmetric cryptography for credential authentication.

### Proof Request

```typescript
{
  claimType: 'age' | 'nationality' | 'age-revocable';  // Type of claim to prove
  minAge?: number;                    // For age claims (e.g., 18, 21)
  targetNationality?: number;         // For nationality claims (ISO 3166-1 code)
  nonce: string;                      // 128-bit random value (hex)
  timestamp: string;                  // ISO 8601 timestamp
}
```

**Replay Protection:**
- `nonce` must be unique and validated by verifier
- `timestamp` can be checked to reject old requests

### Age Proof

```typescript
{
  proof: {
    pi_a: string[];        // Groth16 proof component A
    pi_b: string[][];      // Groth16 proof component B
    pi_c: string[];        // Groth16 proof component C
    protocol: 'groth16';
    curve: 'bn128';
  };
  publicSignals: {
    currentYear: number;   // Year used in proof (e.g., 2024)
    minAge: number;        // Minimum age requirement (e.g., 18)
    credentialHash: string; // Public credential commitment
  };
}
```

**Selective Disclosure:** Nationality is included in the credential hash computation but not revealed in the proof.

### Nationality Proof

```typescript
{
  proof: {
    pi_a: string[];        // Groth16 proof component A
    pi_b: string[][];      // Groth16 proof component B
    pi_c: string[];        // Groth16 proof component C
    protocol: 'groth16';
    curve: 'bn128';
  };
  publicSignals: {
    targetNationality: number;  // Nationality being proven (ISO 3166-1 code)
    credentialHash: string;     // Public credential commitment
  };
}
```

**Selective Disclosure:** Birth year is included in the credential hash computation but not revealed in the proof.

### Age Proof (Revocable)

```typescript
{
  proof: {
    pi_a: string[];        // Groth16 proof component A
    pi_b: string[][];      // Groth16 proof component B
    pi_c: string[];        // Groth16 proof component C
    protocol: 'groth16';
    curve: 'bn128';
  };
  publicSignals: {
    currentYear: number;   // Year used in proof (e.g., 2026)
    minAge: number;        // Minimum age requirement (e.g., 18)
    credentialHash: string; // Public credential commitment
    nonce: string;         // Replay protection nonce
    requestTimestamp: number; // Request timestamp (Unix ms)
    merkleRoot: string;    // Root of valid credentials Merkle tree
  };
}
```

**Revocation Support:** The `merkleRoot` public signal binds the proof to a specific state of the valid credentials tree, enabling privacy-preserving revocation checks.

**Root Distribution:** See the _Revocation Root Distribution_ section below for versioning, TTL, and freshness rules.

**Storage Implementations:** The SDK includes a Postgres-backed `ValidCredentialTree` implementation for production deployments.

### Proof Response

```typescript
{
  credentialId: string;           // ID of credential used
  claimType: string;              // Type of claim proven ('age', 'nationality', 'age-revocable')
  proof: AgeProof | NationalityProof | AgeProofRevocable;  // The zero-knowledge proof
  signedCredential: SignedCredential | CircuitSignedCredential;  // Issuer-signed credential
  nonce: string;                  // From the request (replay protection)
  requestTimestamp: string;       // ISO 8601 timestamp from request
}
```

### Verification Result

```typescript
{
  verified: boolean;         // True if proof is valid
  claimType?: string;        // Type of claim verified
  minAge?: number;           // Minimum age proven (for age claims)
  targetNationality?: number; // Nationality proven (for nationality claims)
  error?: string;            // Error message if verification failed
  protocolVersion?: string;  // Protocol version used for verification (e.g., "zk-id/1.0-draft")
}
```

## Protocol Flows

### 1. Credential Issuance

```
┌──────┐                                    ┌────────┐
│ User │                                    │ Issuer │
└──────┘                                    └────────┘
    │                                            │
    │  1. Request credential + identity proof    │
    ├───────────────────────────────────────────>│
    │                                            │
    │                        2. Verify identity  │
    │                           (KYC, ID check)  │
    │                                            │
    │  3. Signed credential                      │
    │<───────────────────────────────────────────┤
    │                                            │
```

**Steps:**

1. User requests credential from issuer, provides identity proof (ID document, biometrics, etc.)
2. Issuer verifies user's identity through KYC process
3. Issuer extracts birth year and nationality from verified ID
4. Issuer generates credential:
   ```typescript
   salt = randomBytes(32);
   commitment = Poseidon(birthYear, nationality, salt);
   credential = { id, birthYear, nationality, salt, commitment, createdAt };
   signature = Sign(issuer.privateKey, commitment);
   signedCredential = { credential, issuer, signature, issuedAt };
   ```
5. Issuer returns signed credential to user
6. User stores credential securely (encrypted storage, wallet app)

**Security Considerations:**
- Issuer must verify identity thoroughly (real-world ID, biometrics)
- Signing key must be protected (HSM, KMS)
- All issuance events should be logged for audit

### 2. Age Verification

```
┌──────┐                                    ┌──────────┐
│ User │                                    │ Verifier │
└──────┘                                    └──────────┘
    │                                            │
    │  1. Access age-restricted content          │
    ├───────────────────────────────────────────>│
    │                                            │
    │  2. Proof request (minAge, nonce)          │
    │<───────────────────────────────────────────┤
    │                                            │
    │  3. Generate ZK proof locally              │
    │                                            │
    │  4. Proof response                         │
    ├───────────────────────────────────────────>│
    │                                            │
    │                      5. Verify proof       │
    │                                            │
    │  6. Verification result                    │
    │<───────────────────────────────────────────┤
    │                                            │
```

**Steps:**

1. User attempts to access age-restricted content
2. Verifier sends proof request:
   ```typescript
   request = {
     claimType: 'age',
     minAge: 18,
     nonce: randomHex(16),
     timestamp: new Date().toISOString()
   };
   ```
3. User generates proof locally:
   ```typescript
   // Circuit inputs
   input = {
     birthYear: credential.birthYear,        // Private
     nationality: credential.nationality,    // Private (not constrained, hidden)
     salt: credential.salt,                  // Private
     currentYear: new Date().getFullYear(), // Public
     minAge: request.minAge,                 // Public
     credentialHash: credential.commitment   // Public
   };

   // Generate Groth16 proof
   { proof, publicSignals } = await generateProof(input, wasm, zkey);
   ```
4. User submits proof response:
   ```typescript
   response = {
     credentialId: credential.id,
     claimType: 'age',
     proof: { proof, publicSignals },
     nonce: request.nonce
   };
   ```
5. Verifier verifies proof:
   - Check nonce hasn't been used (replay protection)
   - Validate public signals (year, age requirement)
   - Cryptographically verify proof using verification key
   - Check rate limits
6. Verifier returns result and grants/denies access

**Security Considerations:**
- Nonce must be checked to prevent replay attacks
- Proof must be verified using authentic verification key
- Rate limiting prevents brute-force attempts
- User's birth year is never revealed

## Cryptographic Details

### Poseidon Hash

Used for credential commitments.

```
commitment = Poseidon(birthYear, nationality, salt)
```

**Properties:**
- ZK-friendly (efficient inside SNARKs)
- Collision-resistant
- One-way function (can't reverse without salt)
- Binds all attributes together in a single commitment

**Implementation**: circomlibjs

### Groth16 ZK-SNARK

Used for age verification proofs.

**Circuit**: `age-verify.circom`

**Constraints:**
```
age = currentYear - birthYear
age >= minAge  (using GreaterEqThan comparator)
birthYear <= currentYear  (sanity check)
credentialHash included as public input
```

**Proving Key**: Generated via trusted setup (Powers of Tau)
**Verification Key**: Public, used by verifiers

**Security:**
- Proof is zero-knowledge: reveals nothing beyond validity
- Soundness: impossible to generate valid proof for false statement (assuming trusted setup)
- Succinctness: proof is ~200 bytes

### Trusted Setup

zk-id uses Groth16, which requires a trusted setup ceremony.

**Process:**
1. Powers of Tau ceremony (multi-party computation)
2. Phase 2: Circuit-specific setup
3. Generate proving key (private, destroyed after setup)
4. Generate verification key (public)

**Security:**
- If at least one participant is honest, setup is secure
- Use existing Powers of Tau ceremonies (Hermez, Perpetual Powers of Tau)
- For production, participate in multi-party ceremony

### Ed25519 Signatures

Used for credential authentication by issuers.

**Properties:**
- Asymmetric cryptography (public/private key pairs)
- Fast signature generation and verification
- Small signatures (64 bytes)
- Widely used and battle-tested (OpenSSH, Signal, etc.)

**Implementation**: Node.js crypto module or tweetnacl

### Credential Revocation

Implemented via revocation stores that track revoked credential commitments.

**Implementation:**
- `InMemoryRevocationStore`: In-memory store for demo/testing
- Verifiers check credential commitment against revocation store during verification
- Issuer can revoke credentials by commitment hash

**Revocation Check:**
```typescript
if (await revocationStore.isRevoked(credentialCommitment)) {
  return { verified: false, error: 'Credential has been revoked' };
}
```

### Revocation Root Distribution

Revocable proofs bind to the current valid-set Merkle root. Verifiers and clients need a
reliable way to obtain fresh root data and detect stale state.

**Root Info Endpoint:** `GET /api/revocation/root`

Returns a `RevocationRootInfo` object:

```typescript
{
  root: string;          // Current Merkle root (decimal string)
  version: number;       // Monotonic root version (increments on every add/remove)
  updatedAt: string;     // ISO 8601 timestamp of last tree mutation
  expiresAt?: string;    // ISO 8601 timestamp after which this root should be re-fetched
  ttlSeconds?: number;   // Recommended cache lifetime in seconds (default: 300)
  source?: string;       // Identifier for the root source (issuer name, registry URL)
}
```

**Versioning Rules:**
- `version` is a monotonically increasing counter; each tree mutation (add or remove) increments it by 1.
- Clients SHOULD track the last-seen version and re-fetch witnesses when the version advances.
- Verifiers MAY accept proofs against a recent-but-not-latest root within a configurable tolerance window (`maxRevocationRootAgeMs`).

**TTL & Caching Policy:**
- Servers set `ttlSeconds` (default: 300s / 5 minutes) and compute `expiresAt` from `updatedAt + ttlSeconds`.
- HTTP responses SHOULD include `Cache-Control: public, max-age=<ttlSeconds>` when served behind a CDN or reverse proxy.
- Clients SHOULD cache root info for at most `ttlSeconds` and re-fetch before generating proofs with stale roots.
- When `expiresAt` has passed, clients MUST re-fetch before relying on the root.

**Freshness Policy:**
- Servers can enforce a maximum root age via `maxRevocationRootAgeMs` in `ZkIdServerConfig`. When set, revocable proof verification rejects proofs if the tree's `updatedAt` is older than the threshold.
- Clients can set `maxRevocationRootAgeMs` in `ZkIdClientConfig`; `fetchRevocationRootInfo()` logs a warning when the root exceeds this age.
- Recommended defaults: 5 minutes for interactive flows, up to 1 hour for batch/offline scenarios.

**Witness Refresh:**
- When the root version advances, existing Merkle witnesses become invalid.
- Clients holding credentials SHOULD re-fetch witnesses from the tree before generating new proofs.
- The SDK's `ValidCredentialTree.getWitness(commitment)` always returns a witness for the current root.

### External Credential Formats

The system includes optional external format conversion utilities for interoperability.

**Conversion:**
```typescript
// Convert to external credential format
const external = toExternalCredentialFormat(signedCredential);

// Parse from external credential format
const signedCredential = fromExternalCredentialFormat(external);
```

**Properties:**
- JSON-based format with issuer, subject, and proof metadata
- Intended for interoperability demos, not production use

## Security Analysis

### Threat Model

**What We Protect Against:**

1. **Privacy leakage**: User's birth year never revealed
   - Proof reveals only age >= threshold
   - Credential commitment is hiding

2. **Proof forgery**: Cannot create valid proof without valid credential
   - ZK-SNARK soundness guarantees
   - Issuer signature required on credential

3. **Proof replay**: Cannot reuse same proof multiple times
   - Nonce-based replay protection
   - Verifiers check nonce uniqueness

4. **Proof reuse**: Cannot use proof from different user
   - Credential hash binds proof to specific credential
   - Commitments are unique per credential

5. **Impersonation**: Cannot use someone else's credential
   - Private salt value required to generate proofs
   - Credentials stored securely by user

**What We Don't Protect Against:**

1. **Issuer compromise**: If issuer is malicious, can issue fake credentials
   - Mitigation: Use trusted issuers (government, banks)
   - Future: Multi-issuer credentials

2. **Credential theft**: If attacker gets credential + salt, can impersonate
   - Mitigation: Secure storage (encrypted, wallet apps)
   - Future: Biometric binding

3. **Circuit bugs**: Flaws in circuit logic could break soundness
   - Mitigation: Professional audit before production
   - Open source for community review

### Privacy Properties

**Unlinkability**: Different proofs from same credential are unlinkable
- Proofs don't contain credential ID
- Proofs use different nonces
- Cannot tell if two proofs came from same user

**Forward Secrecy**: Compromising credential doesn't reveal past proofs
- Proofs are ephemeral (not stored long-term)
- Each proof uses fresh randomness

**Selective Disclosure**: User reveals only required information
- Age threshold met, not exact age
- No other attributes revealed

## API Specification

### Client API

```typescript
class ZkIdClient {
  constructor(config: ZkIdClientConfig);

  // Request age verification
  async verifyAge(minAge: number): Promise<boolean>;

  // Check if wallet is available
  async hasWallet(): Promise<boolean>;
}
```

### Server API

```typescript
class ZkIdServer {
  constructor(config: ZkIdServerConfig);

  // Verify a proof submission
  async verifyProof(
    proofResponse: ProofResponse,
    clientIdentifier?: string
  ): Promise<VerificationResult>;
}
```

**Policy enforcement**:
- Prefer `requiredPolicy` in server config to enforce minAge or nationality.

**ProofResponse (required fields)**:
- `credentialId`
- `claimType`
- `proof`
- `signedCredential` (issuer-signed credential binding commitment + issuer)
- `nonce`

**Nonce binding**:
- `nonce` is a public input in both circuits and must match `ProofResponse.nonce`.

**Timestamp binding**:
- `requestTimestamp` is a public input in both circuits and must match `ProofResponse.requestTimestamp`.

**Challenge flow (recommended)**:
- Server issues `nonce` + `requestTimestamp` (see `/api/challenge`).
- Clients must embed these values into the proof.

### Issuer Trust & Registry

Verifiers maintain an issuer registry that maps issuer identifiers to their
public keys, lifecycle status, and metadata.

**IssuerRecord:**

```typescript
{
  issuer: string;          // Issuer identifier (name or DID)
  publicKey: KeyObject;    // Ed25519 public key
  status?: 'active' | 'revoked' | 'suspended';
  validFrom?: string;      // ISO 8601 — key not valid before this time
  validTo?: string;        // ISO 8601 — key not valid after this time
  jurisdiction?: string;   // ISO 3166-1 alpha-2 code (e.g., "US", "DE")
  policyUrl?: string;      // URL to issuance/attestation policy
  auditUrl?: string;       // URL to audit report or compliance reference
}
```

**Status Lifecycle:**

```
  onboard         rotate key        suspend         reactivate
    ──→ active ──────→ active ──────→ suspended ──────→ active
                        │                                  │
                        └──→ revoked (permanent) ←─────────┘
                                                   deactivate
```

- **active**: Issuer credentials are accepted. This is the default.
- **suspended**: Issuer is temporarily blocked. Credentials signed by this
  issuer are rejected during verification. Use for incident response or
  pending investigation.
- **revoked**: Issuer is permanently deactivated. Credentials are rejected.
  This is irreversible in the default registry.

**Key Rotation:**

Issuers SHOULD rotate signing keys periodically. The registry supports
overlapping validity windows to allow a smooth transition:

1. Register the new key with `validFrom` set to the rotation time.
2. Keep the old key active until its `validTo` expires.
3. During the overlap window, both keys are accepted.
4. After the old key expires, the verifier only accepts the new key.

```typescript
// Example: rotate issuer key with 24-hour overlap
registry.upsert({
  issuer: 'gov-issuer',
  publicKey: newKey,
  status: 'active',
  validFrom: '2026-03-01T00:00:00Z',
  jurisdiction: 'US',
  policyUrl: 'https://issuer.example.gov/policy',
});
// Old key remains valid until its validTo
```

**Suspension Workflow:**

```typescript
// Emergency: suspend all keys for an issuer
registry.suspend('compromised-issuer');

// After investigation: reactivate
registry.reactivate('compromised-issuer');

// Permanent removal
registry.deactivate('compromised-issuer');
```

**Metadata Fields:**
- `jurisdiction`: Indicates the legal jurisdiction under which the issuer
  operates. Verifiers MAY use this to accept only issuers from specific
  jurisdictions.
- `policyUrl`: Points to the issuer's attestation policy (what identity
  checks they perform, data retention rules, etc.).
- `auditUrl`: Points to an external audit report or compliance certification.

### Issuer API

```typescript
class CredentialIssuer {
  constructor(config: IssuerConfig);

  // Issue a credential after identity verification
  async issueCredential(
    birthYear: number,
    nationality: number,
    userId?: string
  ): Promise<SignedCredential>;

  // Revoke a credential by commitment
  async revokeCredential(commitment: string): Promise<void>;
}
```

## Threat Model

See `docs/THREAT-MODEL.md`.

## Known Limitations

See `docs/KNOWN-LIMITATIONS.md`.

## Extension Points

### Additional Claim Types

The protocol can be extended with new circuits for:

- **Attribute claims**: Prove possession of attribute without revealing value
- **Range proofs**: Prove value is in range without revealing exact value
- **Set membership**: Prove element is in set without revealing which one

### Multi-Issuer Credentials

Support credentials signed by multiple issuers:

```typescript
{
  credentials: Credential[];
  issuers: string[];
  signatures: string[];
}
```

Useful for:
- Cross-border verification (multiple governments)
- Enhanced trust (multiple identity providers)
- Redundancy (if one issuer goes offline)

## Comparison to Related Protocols

### Iden3 Protocol

**Similarities:**
- Both use ZK-SNARKs
- Both support identity verification
- Both are decentralized

**Differences:**
- Iden3 uses identity trees and on-chain verification
- zk-id is simpler and off-chain focused
- Different circuit designs

### BBS+ Signatures

**Similarities:**
- Both enable selective disclosure
- Both provide unlinkability
- Both are used for credentials

**Differences:**
- BBS+ uses signature schemes, not SNARKs
- BBS+ doesn't natively support range proofs

## OpenAPI

See `docs/openapi.yaml` for the demo/server REST API schema.
- Different trust models

## Future Work

- Standardize JSON schemas for interoperability
- Define DID method for issuers (`did:zkid:...`)
- Implement mobile wallet specification
- Add accumulator-based revocation for improved privacy
- Browser extension implementation

## Optional Signed Circuits

This repo includes optional circuits that verify issuer signatures inside the proof.\nUse these for stronger, fully in-circuit issuer binding at the cost of larger public inputs and slower proving.
- Define browser extension APIs
- Add support for anonymous credentials
