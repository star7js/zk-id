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

Proves that `currentYear - birthYear >= minAge` without revealing `birthYear`.

**Inputs:**
- Private: `birthYear`
- Public: `currentYear`, `minAge`, `credentialHash`

**Constraints:**
- Age calculation: `age = currentYear - birthYear`
- Range check: `age >= minAge`
- Birth year validity: `birthYear <= currentYear`
- Credential binding: includes `credentialHash` to prevent proof reuse

**Output:** Groth16 proof that constraints are satisfied

#### `credential-hash.circom`

Computes a Poseidon hash commitment to credential attributes.

**Inputs:**
- `birthYear`: The user's birth year
- `salt`: Random value for hiding

**Output:** `commitment = Poseidon(birthYear, salt)`

This commitment:
- Binds proofs to a specific credential (prevents proof reuse)
- Hides the birth year (can't be reversed without knowing the salt)
- Can be publicly shared without privacy loss

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
const credential = await createCredential(birthYear);

// Generate proof
const proof = await generateAgeProof(credential, minAge, wasmPath, zkeyPath);

// Verify proof
const isValid = await verifyAgeProof(proof, verificationKey);
```

### 3. Issuer Package (`packages/issuer/`)

Service for credential issuance. In production, this would:

- Verify user identity (KYC, government ID check)
- Issue signed credentials
- Manage issuer keys securely (HSM/KMS)
- Log issuance events for audit
- Handle credential revocation

**Current Implementation:**
- Simple HMAC-based signing (demo)
- In-memory key storage (demo)
- Console audit logging (demo)

**Production Requirements:**
- Use proper digital signatures (ECDSA, EdDSA)
- Store keys in HSM or cloud KMS
- Implement comprehensive audit logging
- Add rate limiting and abuse prevention
- Build revocation infrastructure

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
  verificationEndpoint: '/api/verify-age'
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
const server = new ZkIdServer({
  verificationKeyPath: './verification_key.json'
});

const result = await server.verifyProof(proofResponse);
```

## Data Flow

### Credential Issuance Flow

```
1. User visits issuer (e.g., government website)
2. User proves identity (uploads ID, biometrics, in-person, etc.)
3. Issuer extracts birth year from ID
4. Issuer generates credential:
   - Random salt
   - Commitment = Poseidon(birthYear, salt)
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

The credential commitment (`Poseidon(birthYear, salt)`) is:

- **Binding**: Can't change birthYear without detection
- **Hiding**: Can't reverse to find birthYear without salt
- **Public**: Can be shared freely without revealing birthYear

## Comparison to Alternative Approaches

### vs. Traditional ID Upload

| Property | zk-id | ID Upload |
|----------|-------|-----------|
| Privacy | ✅ Full | ❌ None |
| Speed | ✅ Fast | ⚠️ Slow |
| UX | ✅ Simple | ❌ Complex |
| Data Breach Risk | ✅ Low | ❌ High |

### vs. OAuth Age Token

| Property | zk-id | OAuth |
|----------|-------|-------|
| Privacy | ✅ Full | ⚠️ Partial |
| Decentralized | ✅ Yes | ❌ No |
| Vendor Lock-in | ✅ None | ❌ High |
| Tracking | ✅ No | ❌ Yes |

### vs. BBS+ Signatures

| Property | zk-id (SNARKs) | BBS+ |
|----------|----------------|------|
| Proof Size | ✅ Small | ✅ Small |
| Verification Speed | ✅ Fast | ✅ Fast |
| Circuit Complexity | ⚠️ Requires circuits | ✅ No circuits |
| Range Proofs | ✅ Native | ⚠️ Requires ZKP layer |
| Maturity | ✅ Production ready | ⚠️ Emerging |

## Extension Points

### Adding New Claim Types

Currently supports age claims. Can be extended to:

- **Attribute claims**: "I have attribute X" (without revealing value)
- **Range claims**: "My income is in range [A, B]"
- **Set membership**: "I am a resident of {US, CA, UK}"
- **Comparative claims**: "My credit score > 700"

Each requires a new circuit.

### Multi-Attribute Credentials

Current credentials contain only birth year. Can be extended to:

```typescript
interface ExtendedCredential {
  birthYear: number;
  country: string;
  state?: string;
  issuerDID: string;
  salt: string;
}
```

Each attribute can be selectively disclosed using ZK proofs.

### Revocation

Two approaches:

1. **Accumulator-based**: Include credential in a cryptographic accumulator, prove membership
2. **Revocation list**: Issuer publishes revoked credential IDs, verifiers check list

Both can be added without changing core protocol.

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
- [ ] Implement nonce-based replay protection
- [ ] Add rate limiting to verification endpoints
- [ ] Log verification events for analytics
- [ ] Monitor for abuse patterns
- [ ] Implement graceful fallback if ZK verification fails
- [ ] Add user-facing explanation of privacy properties

## Future Directions

- **Mobile wallets**: iOS/Android apps for credential storage
- **Browser extension**: Seamless integration with websites
- **W3C VC compatibility**: Issue credentials as Verifiable Credentials
- **DID integration**: Use DIDs for issuer identification
- **Cross-chain**: Support multiple blockchains for on-chain verification
- **Biometric binding**: Link credentials to device biometrics for security
