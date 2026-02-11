# zk-id

**Privacy-preserving identity verification using zero-knowledge proofs**

zk-id enables users to prove eligibility (age, attributes) without revealing personal information. Built on modern zero-knowledge proof technology (ZK-SNARKs) for practical, fast verification.

## Problem

Current age verification systems force users to expose sensitive information:

- Upload driver's license → reveals name, address, photo, ID number
- Enter credit card → reveals financial information
- Trust third parties → data breaches, tracking

**The solution**: Prove you're over 18 (or 21, or any requirement) without revealing your birth year, age, or any other personal data.

## How It Works

```
┌─────────────┐                  ┌──────────────┐                 ┌─────────────┐
│   Issuer    │                  │     User     │                 │   Website   │
│ (Gov/Bank)  │                  │  (Browser)   │                 │  (Verifier) │
└─────────────┘                  └──────────────┘                 └─────────────┘
       │                                │                                 │
       │  1. Issue credential           │                                 │
       │    (after ID verification)     │                                 │
       ├───────────────────────────────>│                                 │
       │                                │                                 │
       │                                │  2. Request: "Prove age >= 18"  │
       │                                │<────────────────────────────────┤
       │                                │                                 │
       │                                │  3. Generate ZK proof           │
       │                                │    (locally, private)           │
       │                                │                                 │
       │                                │  4. Submit proof                │
       │                                ├────────────────────────────────>│
       │                                │                                 │
       │                                │  5. Verify proof ✓              │
       │                                │     (learns: age >= 18)         │
       │                                │     (doesn't learn: birth year) │
       │                                │                                 │
```

## Features

- ✅ **Privacy-Preserving**: Prove eligibility without revealing personal data
- ✅ **Fast**: Proof verification in <100ms, optimized revocation checks with incremental Merkle trees
- ✅ **Small**: Proofs are ~200 bytes
- ✅ **Secure**: Built on Groth16 ZK-SNARKs with Ed25519 signatures
- ✅ **Multi-Attribute**: Support for multiple credential attributes with selective disclosure
- ✅ **Built-in Scenarios**: 7 predefined verification scenarios (voting, age-gated purchases, senior discount, GDPR consent)
- ✅ **Revocation**: In-circuit Merkle proofs for credential validity with O(1) reads and O(depth) updates
- ✅ **Telemetry**: Built-in verification event monitoring
- ✅ **Batch Verification**: Efficient verification of multiple proofs
- ✅ **Production Storage**: Postgres and Redis implementations with layer caching
- ✅ **Developer-Friendly**: Simple SDK for easy website integration
- ✅ **Protocol Versioning**: Explicit wire-format compatibility via headers
- ✅ **Code Quality**: ESLint + Prettier for automated code quality and formatting
- ✅ **Typed Errors**: Comprehensive error hierarchy for better error handling

## Quick Start

### Try the Demo

The fastest way to see zk-id in action:

```bash
cd examples/web-app
npm install
npm start
```

Then open http://localhost:3000 to see a working integration demo with credential issuance, zero-knowledge verification, and revocation.

**For a comprehensive tutorial**, see [GETTING-STARTED.md](./GETTING-STARTED.md) for step-by-step instructions covering setup, issuance, wallet integration, verification, and production deployment.

### For Users

1. Obtain a credential from a trusted issuer (government ID, bank, etc.)
2. Store it in your wallet (browser extension, mobile app, or local storage)
3. When a website requests age verification, generate a proof locally
4. Submit the proof - your birth year stays private

### For Websites

```bash
npm install @zk-id/sdk
```

**Client side** (user's browser):

```typescript
import { ZkIdClient } from '@zk-id/sdk';

const client = new ZkIdClient({
  verificationEndpoint: '/api/verify-age',
});

// Request age verification
const verified = await client.verifyAge(18);
if (verified) {
  // User is 18+, grant access
}
```

**Scenario verification** (combine multiple claims):

```typescript
import { SCENARIOS } from '@zk-id/core';

// Verify voting eligibility (age >= 18 AND nationality = USA)
const result = await client.verifyScenario(
  credential,
  SCENARIOS.VOTING_ELIGIBILITY_US
);
```

See the [SDK README](./packages/sdk/README.md#scenario-verification) for the full list of 7 built-in scenarios.

**Protocol version header (CORS note):**
The SDK sends `X-ZkId-Protocol-Version` by default only for same-origin endpoints in browsers to avoid CORS preflight issues. For cross-origin verification endpoints, either allow this header in CORS or set:

```typescript
const client = new ZkIdClient({
  verificationEndpoint: 'https://api.example.com/verify',
  protocolVersionHeader: 'always',
});
```

**Server side** (your backend):

```typescript
import { ZkIdServer, InMemoryIssuerRegistry, InMemoryChallengeStore } from '@zk-id/sdk';
import { InMemoryRevocationStore } from '@zk-id/core';

const issuerPublicKey = loadIssuerPublicKeyFromKms();
const issuerRegistry = new InMemoryIssuerRegistry([
  { issuer: 'Your Identity Service', publicKey: issuerPublicKey },
]);

const server = new ZkIdServer({
  verificationKeyPath: './verification_key.json',
  revocationStore: new InMemoryRevocationStore(), // optional
  requiredPolicy: { minAge: 18 }, // optional server-enforced policy
  issuerRegistry, // trusted issuer keys for signature checks
  challengeStore: new InMemoryChallengeStore(), // optional server-issued nonces
});

// Optional: issue a nonce+timestamp challenge for clients before proof generation
// If you configure a challenge store, clients must use this challenge in proofs.
const challenge = await server.createChallenge();

// Optional: load verification keys from KMS/HSM
// const provider = new StaticVerificationKeyProvider({ age: verificationKey });
// const server = await ZkIdServer.createWithKeyProvider({
//   verificationKeyProvider: provider,
//   requireSignedCredentials: false,
// });

// Optional: Listen for verification events
server.onVerification((event) => {
  console.log('Verification:', event.verified, 'Time:', event.verificationTimeMs);
});

app.post('/api/verify-age', async (req, res) => {
  const result = await server.verifyProof(req.body, req.ip);
  res.json({ verified: result.verified });
});
```

**Production storage (Postgres)**:

```typescript
import { ZkIdServer, PostgresValidCredentialTree } from '@zk-id/sdk';
import { Client } from 'pg';

const pg = new Client({ connectionString: process.env.PG_URL });
await pg.connect();
await pg.query('CREATE SCHEMA IF NOT EXISTS zkid;');

const validCredentialTree = new PostgresValidCredentialTree(pg, {
  schema: 'zkid',
  depth: 10,
});

const server = new ZkIdServer({
  verificationKeyPath: './verification_key.json',
  validCredentialTree,
});

// Optional: expose revocation root metadata
const rootInfo = await server.getRevocationRootInfo();
```

**Client helper for revocation root**:

```typescript
const client = new ZkIdClient({
  verificationEndpoint: '/api/verify-age',
  revocationRootEndpoint: '/api/revocation/root',
});

const rootInfo = await client.fetchRevocationRootInfo();
```

### For Issuers

```typescript
import { CredentialIssuer } from '@zk-id/issuer';
import { InMemoryRevocationStore } from '@zk-id/core';

// Create issuer with Ed25519 keys
const issuer = CredentialIssuer.createTestIssuer('Your Identity Service');

// Optional: Enable revocation
const revocationStore = new InMemoryRevocationStore();
issuer.setRevocationStore(revocationStore);

// After verifying user's government ID
const credential = await issuer.issueCredential(
  userBirthYear,
  nationality, // ISO 3166-1 numeric code
  userId,
);

// Revoke a credential if needed (by commitment)
await issuer.revokeCredential(credential.credential.commitment);
```

For KMS/HSM-backed signing:

```typescript
import { ManagedCredentialIssuer, InMemoryIssuerKeyManager } from '@zk-id/issuer';

const keyManager = new InMemoryIssuerKeyManager('Your Identity Service', privateKey, publicKey);
const issuer = new ManagedCredentialIssuer(keyManager);
```

## Repository Structure

```
zk-id/
├── packages/
│   ├── circuits/          # Circom ZK circuits (age-verify, nationality-verify, credential-hash)
│   ├── core/              # Core library (credential, prover, verifier, revocation, batch)
│   ├── issuer/            # Credential issuance with Ed25519 signatures
│   ├── sdk/               # Server SDK with telemetry & revocation checking
│   ├── redis/             # Redis stores for nonce, revocation, and distributed tree sync
│   └── contracts/         # Solidity on-chain Groth16 verifier
├── examples/
│   └── web-app/           # Full web integration example with credential issuance and verification
└── docs/                  # Architecture and protocol documentation
```

## 📦 Packages

zk-id is a monorepo with six packages. Each package has detailed documentation:

### Core Packages

**[@zk-id/core](./packages/core/)** — Core cryptographic library
Credential creation, ZK proof generation/verification, revocation, nullifiers, BBS selective disclosure, W3C VC interop.
[View README →](./packages/core/README.md)

**[@zk-id/circuits](./packages/circuits/)** — Zero-knowledge circuits
Seven Circom circuits for age/nationality verification, credential hashing, and nullifier computation.
[View README →](./packages/circuits/README.md)

### Integration Packages

**[@zk-id/sdk](./packages/sdk/)** — Client and server SDK
Server-side verification pipeline, client-side proof generation, browser wallet, security components.
[View README →](./packages/sdk/README.md)

**[@zk-id/issuer](./packages/issuer/)** — Credential issuance
Multiple signature schemes (Ed25519, BabyJub EdDSA, BBS+), key management, policy enforcement.
[View README →](./packages/issuer/README.md)

### Production Infrastructure

**[@zk-id/redis](./packages/redis/)** — Redis storage backends
Production-ready stores for nonces, challenges, revocation, rate limiting, issuer registry.
[View README →](./packages/redis/README.md)

**[@zk-id/contracts](./packages/contracts/)** — Solidity verifiers
On-chain Groth16 proof verification for Ethereum and EVM-compatible chains.
[View README →](./packages/contracts/README.md)

### Quick Reference

| Package            | Use For                           | npm install                        |
| ------------------ | --------------------------------- | ---------------------------------- |
| `@zk-id/core`      | Building custom integrations      | `npm install @zk-id/core`          |
| `@zk-id/sdk`       | Integrating into web apps         | `npm install @zk-id/sdk`           |
| `@zk-id/issuer`    | Issuing credentials               | `npm install @zk-id/issuer`        |
| `@zk-id/circuits`  | Circuit artifacts (auto-included) | `npm install @zk-id/circuits`      |
| `@zk-id/redis`     | Production storage                | `npm install @zk-id/redis ioredis` |
| `@zk-id/contracts` | On-chain verification             | `npm install @zk-id/contracts`     |

## Use Cases

**Note:** The current public schema supports `birthYear` and `nationality`. Use cases beyond those attributes require new issuer attestations and circuits.

### Supported Today

- **Age-Restricted Content**: Verify minimum age requirements for restricted websites (18+, 21+)
- **Social Media**: Compliance with age restrictions (13+, 16+)
- **E-Commerce**: Age verification for alcohol, tobacco, cannabis
- **Gaming**: Age-appropriate content access controls
- **Voting**: Prove eligibility (18+ and US citizen) via the built-in `VOTING_ELIGIBILITY_US` scenario
- **Discounts**: Prove senior (65+) via the built-in `SENIOR_DISCOUNT` scenario
- **Nationality Checks**: Prove a user has a specific nationality code without revealing other attributes
- **Revocable Eligibility**: Prove membership in a valid set with Merkle inclusion (non-revocation)

### Potential With Extended Schema

- **Bank account holder verification**: Prove you hold an active account without revealing account number or balance
- **Credit eligibility**: Prove creditworthiness meets a threshold without exposing exact score or history
- **Accredited investor status**: Prove income/net-worth thresholds for regulatory compliance without financial disclosure

- **Health insurance validity**: Prove active coverage to a provider without revealing policy details or medical history
- **Auto insurance**: Prove current coverage when renting a car or at a traffic stop without exposing policy limits or premium
- **Claims eligibility**: Prove coverage for a specific category without revealing full policy

- **Car registration**: Prove your vehicle registration is current without revealing VIN or address
- **Driver's license class**: Prove you hold a valid license of a required class without revealing license number

- **Country club or gym membership**: Prove active or transferable membership status without revealing member ID or payment history
- **Alumni verification**: Prove graduation from a university without revealing GPA, transcript, or student ID
- **Professional credentials**: Prove an active license (medical, legal, engineering) without exposing license number

- **Portable KYC**: Prove you passed identity verification at one institution so another can accept it without re-collecting documents
- **Employment verification**: Prove current employment for a loan or rental application without revealing salary or position
- **Income thresholds**: Prove income exceeds a required multiple (e.g., 3x rent) without revealing exact figures

- **Vaccination or health status**: Prove immunization compliance without revealing full medical records
- **Travel authorization**: Prove valid visa or entry status without revealing passport number or travel history

## Technology

- **Proof System**: Groth16 (efficient ZK-SNARKs)
- **Hash Function**: Poseidon (ZK-friendly)
- **Circuit Language**: Circom 2.1.x
- **Libraries**: snarkjs, circomlibjs
- **Proof Size**: ~200 bytes (Groth16, typical encoding)
- **Verification Time**: typically <100ms in demos; depends on hardware and load

## Specs & Roadmap

- OpenAPI schema: `docs/openapi.yaml`
- Protocol details: `docs/PROTOCOL.md`
- Project roadmap: `docs/ROADMAP.md`

## Security Notes

- Threat model: `docs/THREAT-MODEL.md`
- Known limitations: `docs/KNOWN-LIMITATIONS.md`

## Comparison to Existing Solutions

| Solution    | Privacy    | Speed   | Integration | Decentralized |
| ----------- | ---------- | ------- | ----------- | ------------- |
| **zk-id**   | ✅ Full    | ✅ Fast | ✅ Easy     | ✅ Yes        |
| Upload ID   | ❌ None    | ⚠️ Slow | ✅ Easy     | ❌ No         |
| Credit Card | ❌ None    | ✅ Fast | ✅ Easy     | ❌ No         |
| Yoti/Jumio  | ⚠️ Partial | ⚠️ Slow | ✅ Easy     | ❌ No         |
| Worldcoin   | ✅ Full    | ✅ Fast | ⚠️ Complex  | ✅ Yes        |

## Roadmap

See `docs/ROADMAP.md` for current priorities and version targets.

## Threat Model

Summary:

- Issuer-signed credentials only
- Verifier enforces policy and nonce binding
- Trusted issuer keys are required

See `docs/THREAT-MODEL.md` for full detail.

## Known Limitations

See `docs/KNOWN-LIMITATIONS.md` for current limitations and non-goals.

## Signed Circuits (Optional)

See `docs/SIGNED-CIRCUITS.md` for how to use circuits that verify issuer signatures inside the proof.
Note: These circuits use BabyJub EdDSA signatures (circomlib), not Ed25519.

- [x] Core cryptographic primitives
- [x] Age verification circuit
- [x] TypeScript SDK
- [x] Compile and test circuits
- [x] Working end-to-end demo
- [x] Issuer implementation with credential signing
- [x] Comprehensive test suite
- [x] **Security fix: Credential hash verification in circuit** (prevents malicious proofs)
- [x] **Multi-attribute credentials** (birthYear + nationality with selective disclosure)
- [x] **Ed25519 signatures** (production-grade asymmetric crypto)
- [x] **Credential revocation** (revocation store with verifier integration)
- [x] **Telemetry & monitoring** (verification event tracking)
- [x] **Batch verification** (efficient multi-proof verification)
- [x] **Web integration example** (Express + HTML demo)
- [x] **In-circuit revocation proofs** (Merkle inclusion for valid-set)
- [x] **TypeScript SDK integration for revocable credentials**
- [x] Browser wallet implementation
- [ ] Mobile wallet (iOS/Android)
- [x] Sparse Merkle tree for revocation-list (scalability improvement)
- [x] Recursive proof composition (scaffold)

## Security Considerations

### Recent Security Updates

- ✅ **Fixed nonce BigInt conversion** (Feb 2026): Fixed ZK proof generation failure caused by hex nonces. Nonces are now generated as decimal strings compatible with snarkjs BigInt parsing, and use 31 bytes to stay below the BN128 field modulus.
- ✅ **Fixed credential hash verification** (Feb 2026): The circuit now properly verifies that the credential hash matches the prover's private inputs (birthYear, salt), preventing malicious proofs with arbitrary birth years.

### Production Checklist

- [ ] Use production Powers of Tau ceremony (not test ceremony)
- [x] Implement proper key management (HSM/KMS for issuer keys)
- [x] Add rate limiting to verification endpoints
- [x] Implement nonce-based replay protection
- [ ] Use HTTPS for all communications
- [ ] Audit circuits before production use
- [x] Implement credential revocation mechanism
- [x] Add telemetry for verification events (alerting not implemented)

## Contributing

Contributions welcome! This is an open-source project aimed at bringing practical, privacy-preserving identity to the web.

See `CONTRIBUTING.md` for development setup and guidelines.

## License

Apache-2.0 - see `LICENSE` file for details.

## Notice

See `NOTICE` for attribution details.

## Learn More

- [Architecture Documentation](./docs/ARCHITECTURE.md)
- [Protocol Specification](./docs/PROTOCOL.md)
- [Example: Web Application Demo](./examples/web-app/)
- [Circom Circuits](./packages/circuits/)

## Comparison to Standards

zk-id is compatible with and inspired by:

- **BBS+ Signatures**: Alternative to ZK-SNARKs for selective disclosure
- **Iden3**: Shares similar goals, different implementation approach

## Why Zero-Knowledge Proofs?

Traditional identity systems are binary: either you share everything (your full ID) or nothing. Zero-knowledge proofs enable a third option: **prove specific claims without revealing underlying data**.

Example:

- ❌ Traditional: "Here's my driver's license" → reveals name, address, photo, ID number, birth date
- ✅ zk-id: "I'm over 18" → reveals only that one fact, nothing else

This is the future of privacy-preserving identity.
