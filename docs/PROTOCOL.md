# zk-id Protocol Specification

This document specifies the zk-id protocol for privacy-preserving identity verification.

## Version

**Protocol Version**: 0.1.0
**Status**: Draft / Experimental
**Last Updated**: 2024

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
- Issue signed credentials containing verified attributes
- Manage signing keys securely
- Maintain audit logs
- Handle credential revocation

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
  signature: string;       // Issuer's signature over commitment
  issuedAt: string;        // ISO 8601 timestamp
}
```

### Proof Request

```typescript
{
  claimType: 'age' | 'nationality';  // Type of claim to prove
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

### Proof Response

```typescript
{
  credentialId: string;           // ID of credential used
  claimType: string;              // Type of claim proven
  proof: AgeProof | NationalityProof;  // The zero-knowledge proof
  nonce: string;                  // From the request (replay protection)
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

### Issuer API

```typescript
class CredentialIssuer {
  constructor(config: IssuerConfig);

  // Issue a credential after identity verification
  async issueCredential(
    birthYear: number,
    userId?: string
  ): Promise<SignedCredential>;
}
```

## Extension Points

### Additional Claim Types

The protocol can be extended with new circuits for:

- **Attribute claims**: Prove possession of attribute without revealing value
- **Range proofs**: Prove value is in range without revealing exact value
- **Set membership**: Prove element is in set without revealing which one

### Credential Revocation

Two approaches can be added:

1. **Accumulator-based**:
   - Credentials included in cryptographic accumulator
   - Proof includes accumulator membership proof
   - Issuer can remove credentials from accumulator

2. **Revocation list**:
   - Issuer publishes list of revoked credential IDs
   - Verifiers check ID against list
   - Simpler but less private (credential ID revealed)

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

### W3C Verifiable Credentials

**Similarities:**
- Both support selective disclosure
- Both use digital signatures
- Both enable decentralized identity

**Differences:**
- zk-id uses ZK-SNARKs for stronger privacy
- VCs typically use JSON-LD and JWTs
- zk-id is more computation-intensive

**Compatibility:** zk-id credentials can be wrapped as VCs

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
- Different trust models

## Future Work

- Standardize JSON schemas for interoperability
- Define DID method for issuers (`did:zkid:...`)
- Integrate with W3C Verifiable Credentials
- Add support for credential revocation
- Implement mobile wallet specification
- Define browser extension APIs
- Add support for anonymous credentials
