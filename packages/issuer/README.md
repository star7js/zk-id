# @zk-id/issuer

**Credential issuance service with multiple signature schemes and key management backends**

This package provides credential issuance using Ed25519, BabyJub EdDSA (for in-circuit verification), or BBS+ (for selective disclosure). It supports in-memory, file-based, and envelope-encrypted key management, along with policy enforcement and ISO 18013-5/7 standards mapping.

## Features

### Credential Issuers

- **CredentialIssuer** — Ed25519 signed credentials with `issueCredential()`, `revokeCredential()`, `verifySignature()`
- **ManagedCredentialIssuer** — Production issuer delegating to `IssuerKeyManager` interface (supports KMS/HSM)
- **CircuitCredentialIssuer** — BabyJub EdDSA signatures for in-circuit verification
- **BBSCredentialIssuer** — BBS+ signatures for selective disclosure proofs

### Key Management

- **InMemoryIssuerKeyManager** — In-memory key storage (testing only, keys lost on restart)
- **FileKeyManager** — File-based key storage using PEM files
- **EnvelopeKeyManager** — At-rest encryption using AES-256-GCM with master key
- **IssuerKeyManager Interface** — Pluggable interface for custom key backends (HSM, AWS KMS, Azure Key Vault, etc.)

### Policy

- **IssuerPolicy** — Policy definitions for key rotation, certificate expiry, and operational constraints
- **checkKeyRotation** — Check if issuer keys need rotation based on age and usage
- **validateIssuerPolicy** — Validate issuer against policy rules
- **generateRotationPlan** — Generate step-by-step key rotation plan

### Standards Mapping

- **ISO 18013-5/7** — Mobile driver's license (mDL) element mapping
- **toMdlElements** — Convert zk-id credentials to mDL data elements
- **createAgeOverAttestation** — Create ISO 18013-5 age_over attestations
- **Country Code Conversion** — ISO 3166-1 numeric ↔ alpha-2 conversion

## Installation

```bash
npm install @zk-id/issuer
```

**Peer dependency:** `@zk-id/core`

## Quick Start

```typescript
import { createTestIssuer } from '@zk-id/issuer';

// Create a test issuer (generates ephemeral keys)
const issuer = createTestIssuer({ name: 'Test Issuer' });

// Issue a credential
const credential = await issuer.issueCredential(1995, 840); // birth year, USA
console.log('Issued credential:', credential.id);
```

## Key Management Examples

### File-Based Key Management

```typescript
import { FileKeyManager, ManagedCredentialIssuer } from '@zk-id/issuer';

const keyManager = await FileKeyManager.fromPemFiles(
  './private-key.pem',
  './public-key.pem'
);

const issuer = new ManagedCredentialIssuer('Production Issuer', keyManager);
```

### Envelope Encryption (At-Rest)

```typescript
import { EnvelopeKeyManager, InMemoryIssuerKeyManager } from '@zk-id/issuer';

const masterKey = Buffer.from('...32-byte master key...');
const memoryManager = new InMemoryIssuerKeyManager(signingKey, publicKey);

// Seal keys for storage
const sealed = await EnvelopeKeyManager.seal(memoryManager, masterKey);
await fs.writeFile('sealed-keys.json', JSON.stringify(sealed));

// Unseal keys when needed
const unsealed = await EnvelopeKeyManager.unseal(sealed, masterKey);
const issuer = new ManagedCredentialIssuer('Issuer Name', unsealed);
```

## Signature Schemes

### Comparison Table

| Scheme | Use Case | Verification | Proving Time | Constraints |
|--------|----------|--------------|--------------|-------------|
| **Ed25519** | Off-chain verification | Fast (~1ms) | N/A | 0 |
| **BabyJub EdDSA** | In-circuit verification | In-proof (~15s) | ~15s | ~20k |
| **BBS+** | Selective disclosure | Off-chain (~10ms) | N/A | 0 |

### Ed25519 (Default)

Standard Ed25519 signatures. Fastest and most compatible. Verified off-chain by the server.

### BabyJub EdDSA (In-Circuit)

Uses Baby Jubjub curve for in-circuit signature verification. Enables trustless verification (no issuer registry needed), but adds ~20k constraints to the circuit.

**IMPORTANT:** BabyJub EdDSA is NOT compatible with standard Ed25519. They use different curves and produce different signatures.

```typescript
import { CircuitCredentialIssuer } from '@zk-id/issuer';

const issuer = new CircuitCredentialIssuer('Circuit Issuer', privateKey, publicKey);
const credential = await issuer.issueCredential(1995, 840);
// Use with generateAgeProofSigned() from @zk-id/core
```

### BBS+ (Selective Disclosure)

Enables selective disclosure of credential attributes. Users can prove individual claims (e.g., "I am over 18") without revealing other attributes.

```typescript
import { BBSCredentialIssuer } from '@zk-id/issuer';

const keyPair = await generateBBSKeyPair();
const issuer = new BBSCredentialIssuer('BBS Issuer', keyPair.secretKey);
const credential = await issuer.issueCredential(1995, 840);
// Use with deriveBBSDisclosureProof() from @zk-id/core
```

## Production Notes

- **createTestIssuer() generates keys in memory** — NEVER use for production. Keys are ephemeral and lost on restart. Use `FileKeyManager` or `EnvelopeKeyManager` for production.
- **BabyJub EdDSA is NOT compatible with Ed25519** — They use different elliptic curves (Baby Jubjub vs Curve25519). Signatures are not interchangeable.
- **EnvelopeKeyManager master key must be exactly 32 bytes** — Use a cryptographically secure random key. Store the master key securely (HSM, KMS, or vault).
- **Policy enforcement is advisory** — `validateIssuerPolicy()` returns warnings but does not block issuance. Integrate policy checks into your issuance workflow.
- **Key rotation requires coordination** — Use `generateRotationPlan()` to plan rotation steps. Maintain grace periods for signature verification during rotation.

## Testing

```bash
npm test
```

Tests cover all signature schemes, key management backends, policy enforcement, and standards mapping.

## Related Packages

- `@zk-id/core` — Core credential and proof primitives
- `@zk-id/circuits` — Circom circuits for in-circuit signature verification
- `@zk-id/sdk` — Server-side verification with issuer registry
- `@zk-id/redis` — Production-ready issuer registry with Redis

## License

Apache-2.0
