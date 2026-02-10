# zk-id Architecture

This document describes the technical architecture of zk-id.

## Overview

zk-id is a privacy-preserving identity verification system built on zero-knowledge proofs. The system has three main actors:

1. **Issuers**: Trusted entities that verify identities and issue credentials
2. **Users**: Individuals who hold credentials and generate proofs
3. **Verifiers**: Websites/services that verify proofs to gate access

## System Components

### 1. Circuits (`packages/circuits/`)

The cryptographic foundation. Written in Circom, compiled to R1CS and WASM.

#### `age-verify.circom`

Proves that `currentYear - birthYear >= minAge` without revealing `birthYear` or `nationality`.

**Inputs:**

- Private: `birthYear`, `nationality`, `salt`
- Public: `currentYear`, `minAge`, `credentialHash`

**Constraints:**

- Age calculation: `age = currentYear - birthYear`
- Range check: `age >= minAge`
- Birth year validity: `birthYear <= currentYear`
- Credential binding: `credentialHash = Poseidon(birthYear, nationality, salt)`

**Selective Disclosure:** Nationality is included in the hash but not constrained, enabling proof of age without revealing nationality.

**Output:** Groth16 proof that constraints are satisfied

#### `nationality-verify.circom`

Proves that `nationality === targetNationality` without revealing `birthYear`.

**Inputs:**

- Private: `birthYear`, `nationality`, `salt`
- Public: `targetNationality`, `credentialHash`

**Constraints:**

- Nationality check: `nationality === targetNationality`
- Credential binding: `credentialHash = Poseidon(birthYear, nationality, salt)`

**Selective Disclosure:** Birth year is included in the hash but not constrained, enabling proof of nationality without revealing age.

**Output:** Groth16 proof that constraints are satisfied

#### `credential-hash.circom`

Computes a Poseidon hash commitment to credential attributes.

**Inputs:**

- `birthYear`: The user's birth year
- `nationality`: The user's nationality (ISO 3166-1 numeric code)
- `salt`: Random value for hiding

**Output:** `commitment = Poseidon(birthYear, nationality, salt)`

This commitment:

- Binds proofs to a specific credential (prevents proof reuse)
- Binds all attributes together (can't prove mismatched age/nationality)
- Hides the attributes (can't be reversed without knowing the salt)
- Can be publicly shared without privacy loss
- Enables selective disclosure through different proof circuits

### 2. Core Library (`packages/core/`)

TypeScript library that wraps the circuits and provides a developer-friendly API.

**Modules:**

- **`types.ts`**: TypeScript interfaces for credentials, proofs, verification keys
- **`credential.ts`**: Create and manage credentials
- **`poseidon.ts`**: Poseidon hash utilities (ZK-friendly hash function)
- **`prover.ts`**: Generate zero-knowledge proofs
- **`verifier.ts`**: Verify proofs cryptographically

**Key Functions:**

```typescript
// Create a credential
const credential = await createCredential(birthYear, nationality);

// Generate age proof (selective disclosure: hides nationality)
const ageProof = await generateAgeProof(
  credential,
  minAge,
  nonce,
  requestTimestampMs,
  wasmPath,
  zkeyPath,
);

// Generate nationality proof (selective disclosure: hides birth year)
const nationalityProof = await generateNationalityProof(
  credential,
  targetNationality,
  nonce,
  requestTimestampMs,
  wasmPath,
  zkeyPath,
);

// Verify proofs
const ageValid = await verifyAgeProof(ageProof, verificationKey);
const nationalityValid = await verifyNationalityProof(nationalityProof, verificationKey);
```

### 3. Issuer Package (`packages/issuer/`)

Service for credential issuance. In production, this would:

- Verify user identity (KYC, government ID check)
- Issue signed credentials
- Manage issuer keys securely (HSM/KMS)
- Log issuance events for audit
- Handle credential revocation

**Current Implementation:**

- Ed25519 (EdDSA) signatures for production-grade credential signing
- In-memory key storage (demo - use HSM/KMS in production)
- Console audit logging (demo)
- InMemoryRevocationStore for credential revocation

**Production Requirements:**

- Store keys in HSM or cloud KMS (currently in-memory for demo)
- Implement comprehensive audit logging
- Add rate limiting and abuse prevention
- Use persistent revocation store (database-backed)

### 4. SDK Package (`packages/sdk/`)

Integration SDK for websites. Provides both client and server utilities.

#### Client SDK (`client.ts`)

Runs in the user's browser. Responsibilities:

- Request proofs from user's wallet
- Handle user consent flow
- Submit proofs to website backend
- Implement replay protection (nonces)

```typescript
const client = new ZkIdClient({
  verificationEndpoint: '/api/verify-age',
});

const verified = await client.verifyAge(18);
```

#### Server SDK (`server.ts`)

Runs on website's backend. Responsibilities:

- Receive proof submissions
- Verify proofs cryptographically
- Check replay protection (nonce validation)
- Rate limiting
- Return verification results

```typescript
const issuerPublicKey = loadIssuerPublicKeyFromKms();
const issuerRegistry = new InMemoryIssuerRegistry([
  { issuer: 'Example Issuer', publicKey: issuerPublicKey },
]);

const server = new ZkIdServer({
  verificationKeyPath: './verification_key.json',
  issuerRegistry,
});

const result = await server.verifyProof(proofResponse);
```

## Data Flow

### Credential Issuance Flow

```
1. User visits issuer (e.g., government website)
2. User proves identity (uploads ID, biometrics, in-person, etc.)
3. Issuer extracts birth year and nationality from ID
4. Issuer generates credential:
   - Random salt
   - Commitment = Poseidon(birthYear, nationality, salt)
   - Signature over commitment
5. Issuer returns signed credential to user
6. User stores credential in wallet
```

### Verification Flow

```
1. User visits website with age requirement
2. Website requests proof: "Prove you're 18+"
3. User's wallet generates proof locally:
   - Inputs: birthYear (private), currentYear (public), minAge (public)
   - Circuit proves: currentYear - birthYear >= minAge
   - Includes credentialHash for binding
   - Generates ZK proof using snarkjs
4. Wallet submits proof to website's backend
5. Website verifies proof:
   - Checks cryptographic validity
   - Validates public inputs (year, age requirement)
   - Checks nonce (replay protection)
   - Checks rate limits
6. Website grants/denies access
```

## Security Model

### Threat Model

**Assumptions:**

- Issuers are trusted to verify identity correctly
- Users keep their credentials and salt values private
- Verification keys are authentic (from trusted setup)

**Protections Against:**

- ✅ Privacy leakage: Birth year never revealed
- ✅ Proof forgery: Cryptographically impossible without valid credential
- ✅ Proof replay: Nonce-based replay protection
- ✅ Proof reuse: Credential hash binds proof to specific identity
- ✅ Rate limit abuse: Server-side rate limiting

**Out of Scope:**

- Issuer compromise (if issuer is malicious, it can issue fake credentials)
- User credential theft (if attacker gets credential + salt, they can impersonate)
- Circuit bugs (circuits must be audited before production use)

### Cryptographic Primitives

**Groth16 ZK-SNARKs:**

- Proof system used for age verification
- Properties: Succinctness (small proofs), zero-knowledge (reveals nothing beyond validity)
- Trust setup required (Powers of Tau ceremony)
- Widely used in production (Zcash, Filecoin, Polygon)

**Poseidon Hash:**

- ZK-friendly hash function (efficient inside SNARKs)
- Used for credential commitments
- Much more efficient than SHA-256 in circuits

**BN128 Curve:**

- Elliptic curve used for pairing-based cryptography
- Standard for Ethereum ZK applications

## Error Handling Architecture

### Error Hierarchy

zk-id v0.6+ uses a typed error hierarchy for better error handling and debugging:

```
ZkIdError (base class)
├── ZkIdConfigError        // Configuration errors
├── ZkIdValidationError    // Input validation errors
├── ZkIdCredentialError    // Credential-related errors
├── ZkIdCryptoError        // Cryptographic errors
└── ZkIdProofError         // Proof generation/verification errors
```

### Error Properties

All `ZkIdError` subclasses have:

- **message**: Human-readable error description
- **name**: Error class name (e.g., "ZkIdValidationError")
- **field** (ValidationError only): Which field failed validation
- **code** (CredentialError only): Machine-readable error code

### Error Handling Best Practices

```typescript
try {
  await issuer.issueCredential(1990, 840);
} catch (error) {
  if (error instanceof ZkIdValidationError) {
    // Handle validation error
    console.error(`Invalid ${error.field}: ${error.message}`);
  } else if (error instanceof ZkIdCryptoError) {
    // Handle crypto error
    console.error('Cryptographic operation failed:', error.message);
  } else if (error instanceof ZkIdError) {
    // Handle other zk-id errors
    console.error('zk-id error:', error.message);
  } else {
    // Handle unexpected errors
    console.error('Unexpected error:', error);
  }
}
```

### Error Propagation

- **Client SDK (v0.7+)**: Re-throws `ZkIdError` subclasses for better debugging
- **Server SDK**: Uses `sanitizeError()` to prevent information leakage in non-verbose mode
- **Validation**: All validators throw `ZkIdValidationError` with field names

## Code Quality

### Automated Quality Assurance

zk-id v0.6+ includes comprehensive code quality automation:

#### ESLint

- **Configuration**: `.eslintrc.json` in each package
- **Rules**: TypeScript best practices, security patterns
- **Integration**: Runs on pre-commit and in CI

```bash
npm run lint         # Check code quality
npm run lint:fix     # Auto-fix issues
```

#### Prettier

- **Configuration**: `.prettierrc` in root
- **Style**: Consistent formatting across all packages
- **Integration**: Format on save, pre-commit hook

```bash
npm run format         # Format all code
npm run format:check   # Check formatting
```

### Quality Metrics

- **Test Coverage**: Target 80%+ for critical paths
- **Type Safety**: Strict TypeScript with no `any` in production code
- **Security**: ESLint security plugin for vulnerability detection
- **Performance**: Benchmarks for proof generation and verification

### Development Workflow

1. Write code with ESLint/Prettier integration
2. Run `npm run lint` before committing
3. Run `npm test` to verify changes
4. Pre-commit hooks ensure quality standards

## Performance

### Proof Generation (User's Device)

- **Time**: ~2-5 seconds (one-time, local)
- **Memory**: ~200MB WASM runtime
- **Works offline**: No network needed for proof generation

### Proof Verification (Website's Server)

- **Time**: <100ms per proof
- **Memory**: ~10MB for verification key
- **Scalable**: Can verify 100s of proofs per second per core

### Proof Size

- **On-wire**: ~200 bytes (3 curve points)
- **JSON**: ~400 bytes with metadata

## Privacy Properties

### What Verifiers Learn

✅ The user meets the age requirement (e.g., "at least 18")
✅ The proof is cryptographically valid
✅ The credential was issued by a trusted authority

### What Verifiers Don't Learn

❌ User's birth year
❌ User's exact age
❌ When credential was issued
❌ Any other personal information
❌ Link between proofs (unlinkability - each proof is independent)

### Credential Privacy

The credential commitment (`Poseidon(birthYear, nationality, salt)`) is:

- **Binding**: Can't change any attribute without detection
- **Hiding**: Can't reverse to find attributes without salt
- **Public**: Can be shared freely without revealing attributes
- **Selective**: Different circuits can prove different attributes while using the same commitment

## Comparison to Alternative Approaches

### vs. Traditional ID Upload

| Property         | zk-id     | ID Upload  |
| ---------------- | --------- | ---------- |
| Privacy          | ✅ Full   | ❌ None    |
| Speed            | ✅ Fast   | ⚠️ Slow    |
| UX               | ✅ Simple | ❌ Complex |
| Data Breach Risk | ✅ Low    | ❌ High    |

### vs. OAuth Age Token

| Property       | zk-id   | OAuth      |
| -------------- | ------- | ---------- |
| Privacy        | ✅ Full | ⚠️ Partial |
| Decentralized  | ✅ Yes  | ❌ No      |
| Vendor Lock-in | ✅ None | ❌ High    |
| Tracking       | ✅ No   | ❌ Yes     |

### vs. BBS+ Signatures

| Property           | zk-id (SNARKs)       | BBS+                  |
| ------------------ | -------------------- | --------------------- |
| Proof Size         | ✅ Small             | ✅ Small              |
| Verification Speed | ✅ Fast              | ✅ Fast               |
| Circuit Complexity | ⚠️ Requires circuits | ✅ No circuits        |
| Range Proofs       | ✅ Native            | ⚠️ Requires ZKP layer |
| Maturity           | ✅ Production ready  | ⚠️ Emerging           |

## Extension Points

### Adding New Claim Types

Currently supports age and nationality claims. Can be extended to:

- **Range claims**: "My income is in range [A, B]"
- **Set membership**: "I am a resident of {US, CA, UK}"
- **Comparative claims**: "My credit score > 700"
- **Date-based claims**: "My license was issued after 2020"

Each requires a new circuit.

### Multi-Attribute Credentials

Current credentials contain birth year and nationality with selective disclosure:

```typescript
interface Credential {
  id: string;
  birthYear: number; // Can prove age without revealing nationality
  nationality: number; // Can prove nationality without revealing age
  salt: string;
  commitment: string; // Binds both attributes together
}
```

**Selective Disclosure Design:**

- Single commitment binds all attributes: `Poseidon(birthYear, nationality, salt)`
- Each proof circuit includes ALL attributes as private inputs
- Each circuit only constrains the attributes being proven
- Unconstrained attributes remain hidden but contribute to credential binding

This can be extended to additional attributes:

```typescript
interface ExtendedCredential {
  birthYear: number;
  nationality: number;
  state?: string;
  issuerDID: string;
  salt: string;
}
```

Each attribute can be selectively disclosed using separate ZK proof circuits.

### Revocation

ZK-ID implements a **two-layer revocation model** for privacy-preserving credential lifecycle management:

#### 1. Simple Blacklist (`RevocationStore`)

- Tracks revoked credential commitments in a traditional key-value store
- Implementations: `InMemoryRevocationStore`, `PostgresRevocationStore`, `RedisRevocationStore`
- Used by issuers for administrative revocation checks
- Does **not** appear in ZK proofs

#### 2. ZK Merkle Whitelist (`ValidCredentialTree`)

- Sparse Merkle tree (depth 10, 1024 leaves) of **valid** (non-revoked) credential commitments
- Provers generate a **Merkle inclusion witness** at credential issuance time
- The circuit (`age-verify-revocable.circom`) proves the credential commitment is **in** the valid-set tree
- Verifiers only see the Merkle root, not the credential position — privacy-preserving
- Implementations: `InMemoryValidCredentialTree`, `PostgresValidCredentialTree`

#### Circuit Integration

The `age-verify-revocable` circuit accepts:

- Public input: Merkle root of the valid-set tree
- Private inputs: credential commitment, Merkle witness (siblings + path indices)
- Constraints: Verify Merkle path from commitment to root AND age threshold proof

Verifiers accept proofs referencing a recent root (TTL-based), rejecting stale witnesses.

#### Root Distribution & Freshness

- **Root info** includes: root hash, monotonic version, updatedAt timestamp, optional expiresAt/TTL
- Issuers publish root updates via REST API (GET `/revocation/root`)
- Clients cache witnesses and check freshness via `isWitnessFresh()` helper
- **Staleness guard**: Verifiers reject proofs with roots older than TTL (e.g., 7 days)

#### Production Storage

- **Postgres**: Persistent, ACID-compliant storage for revocation state and tree leaves
- **Redis**: High-throughput caching layer for root distribution and read-heavy workloads
- Both implementations maintain root versioning and atomic tree updates

#### Privacy Properties

- **Verifier learns**: Only the Merkle root (timestamp via version)
- **Verifier does NOT learn**: Which credential was used, position in tree, or total valid credential count
- **Issuer learns**: Revocation events (unavoidable for lifecycle management)
- **Prover learns**: Current root, witness for their credential (obtained at issuance)

## Production Deployment Checklist

### Issuer

- [ ] Implement proper KYC/identity verification
- [ ] Use HSM or cloud KMS for key management
- [ ] Implement comprehensive audit logging
- [ ] Add rate limiting and abuse detection
- [ ] Build credential revocation system
- [ ] Deploy with high availability
- [ ] Implement backup and disaster recovery

### Circuits

- [ ] Professional security audit of circuits
- [ ] Participate in multi-party trusted setup (Powers of Tau)
- [ ] Publish verification keys and circuit artifacts
- [ ] Document circuit logic and constraints
- [ ] Test against known attack vectors

### SDK/Website Integration

- [ ] Use HTTPS everywhere
- [x] Implement nonce-based replay protection
- [ ] Add rate limiting to verification endpoints
- [x] Log verification events for analytics (telemetry)
- [ ] Monitor for abuse patterns
- [ ] Implement graceful fallback if ZK verification fails
- [ ] Add user-facing explanation of privacy properties

## Current Features

- **Ed25519 Signatures**: Production-grade asymmetric signatures for credential authentication
- **Credential Revocation**: InMemoryRevocationStore with verifier integration
- **External Credential Formats**: Optional format conversion support (toExternalCredentialFormat/fromExternalCredentialFormat)
- **Telemetry**: Verification event tracking and monitoring
- **Batch Verification**: Efficient verification of multiple proofs in parallel
- **Replay Protection**: Nonce-based replay attack prevention

## Future Directions

- **Mobile wallets**: iOS/Android apps for credential storage
- **Browser extension**: Seamless integration with websites
- **DID integration**: Use DIDs for issuer identification
- **Cross-chain**: Support multiple blockchains for on-chain verification
- **Biometric binding**: Link credentials to device biometrics for security
- **Accumulator-based revocation**: More privacy-preserving revocation mechanism
