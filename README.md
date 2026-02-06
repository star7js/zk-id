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

✅ **Privacy-Preserving**: Prove eligibility without revealing personal data
✅ **Fast**: Proof verification in <100ms
✅ **Small**: Proofs are ~200 bytes
✅ **Secure**: Built on Groth16 ZK-SNARKs, widely used in production
✅ **Developer-Friendly**: Simple SDK for easy website integration

## Quick Start

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
  verificationEndpoint: '/api/verify-age'
});

// Request age verification
const verified = await client.verifyAge(18);
if (verified) {
  // User is 18+, grant access
}
```

**Server side** (your backend):
```typescript
import { ZkIdServer } from '@zk-id/sdk';

const server = new ZkIdServer({
  verificationKeyPath: './verification_key.json'
});

app.post('/api/verify-age', async (req, res) => {
  const result = await server.verifyProof(req.body);
  res.json({ verified: result.verified });
});
```

### For Issuers

```typescript
import { CredentialIssuer } from '@zk-id/issuer';

const issuer = new CredentialIssuer({
  name: 'Your Identity Service',
  signingKey: process.env.ISSUER_KEY,
  publicKey: process.env.ISSUER_PUBLIC_KEY
});

// After verifying user's government ID
const credential = await issuer.issueCredential(userBirthYear, userId);
```

## Repository Structure

```
zk-id/
├── packages/
│   ├── circuits/          # Circom ZK circuits (age-verify, credential-hash)
│   ├── core/              # Core TypeScript library (credential, prover, verifier)
│   ├── issuer/            # Credential issuance service
│   └── sdk/               # Website integration SDK (client + server)
├── examples/
│   └── age-gate/          # Complete age verification demo
└── docs/                  # Architecture and protocol documentation
```

## Use Cases

- **Age-Restricted Content**: Verify minimum age requirements for restricted websites (18+, 21+)
- **Social Media**: Compliance with age restrictions (13+, 16+)
- **E-Commerce**: Age verification for alcohol, tobacco, cannabis
- **Gaming**: Age-appropriate content access controls
- **Voting**: Prove eligibility (18+) without revealing exact age
- **Discounts**: Prove senior (65+) or student status without ID

## Technology

- **Proof System**: Groth16 (efficient ZK-SNARKs)
- **Hash Function**: Poseidon (ZK-friendly)
- **Circuit Language**: Circom 2.0
- **Libraries**: snarkjs, circomlibjs
- **Proof Size**: ~200 bytes
- **Verification Time**: <100ms

## Comparison to Existing Solutions

| Solution | Privacy | Speed | Integration | Decentralized |
|----------|---------|-------|-------------|---------------|
| **zk-id** | ✅ Full | ✅ Fast | ✅ Easy | ✅ Yes |
| Upload ID | ❌ None | ⚠️ Slow | ✅ Easy | ❌ No |
| Credit Card | ❌ None | ✅ Fast | ✅ Easy | ❌ No |
| Yoti/Jumio | ⚠️ Partial | ⚠️ Slow | ✅ Easy | ❌ No |
| Worldcoin | ✅ Full | ✅ Fast | ⚠️ Complex | ✅ Yes |

## Roadmap

- [x] Core cryptographic primitives
- [x] Age verification circuit
- [x] TypeScript SDK
- [x] Compile and test circuits
- [x] Working end-to-end demo
- [x] Issuer implementation with credential signing
- [x] Comprehensive test suite (59 tests passing)
- [ ] Browser wallet implementation
- [ ] Mobile wallet (iOS/Android)
- [ ] Multi-attribute credentials (not just age)
- [ ] Credential revocation
- [ ] W3C Verifiable Credentials compatibility

## Security Considerations

### Production Checklist

- [ ] Use production Powers of Tau ceremony (not test ceremony)
- [ ] Implement proper key management (HSM/KMS for issuer keys)
- [ ] Add rate limiting to verification endpoints
- [ ] Implement nonce-based replay protection
- [ ] Use HTTPS for all communications
- [ ] Audit circuits before production use
- [ ] Implement credential revocation mechanism
- [ ] Add monitoring and alerting for abuse

## Contributing

Contributions welcome! This is an open-source project aimed at bringing practical, privacy-preserving identity to the web.

See `CONTRIBUTING.md` for development setup and guidelines.

## License

MIT License - see `LICENSE` file for details.

## Learn More

- [Architecture Documentation](./docs/ARCHITECTURE.md)
- [Protocol Specification](./docs/PROTOCOL.md)
- [Example: Age Verification Demo](./examples/age-gate/)
- [Circom Circuits](./packages/circuits/)

## Comparison to Standards

zk-id is compatible with and inspired by:

- **W3C Verifiable Credentials**: Can be adapted to issue VCs
- **W3C Decentralized Identifiers (DIDs)**: Can use DIDs for issuer identification
- **BBS+ Signatures**: Alternative to ZK-SNARKs for selective disclosure
- **Iden3**: Shares similar goals, different implementation approach

## Why Zero-Knowledge Proofs?

Traditional identity systems are binary: either you share everything (your full ID) or nothing. Zero-knowledge proofs enable a third option: **prove specific claims without revealing underlying data**.

Example:
- ❌ Traditional: "Here's my driver's license" → reveals name, address, photo, ID number, birth date
- ✅ zk-id: "I'm over 18" → reveals only that one fact, nothing else

This is the future of privacy-preserving identity.
