# W3C Verifiable Credentials Interoperability

**Status:** v1.1.0 (February 2026)

zk-id now supports W3C Verifiable Credentials Data Model v2.0, enabling interoperability with the W3C VC ecosystem while preserving zero-knowledge privacy guarantees.

## Overview

W3C Verifiable Credentials (VCs) provide a standard format for issuing and verifying digital credentials. zk-id's W3C VC support wraps the privacy-preserving zk-id credential in a standards-compliant envelope, enabling:

- **Interoperability** with W3C VC wallets and verifiers
- **DID integration** for issuer and subject identifiers
- **Standards compliance** for enterprise and government adoption
- **Privacy preservation** via zero-knowledge proofs

## W3C VC Format

A zk-id credential in W3C VC format looks like this:

```json
{
  "@context": [
    "https://www.w3.org/ns/credentials/v2",
    "https://w3id.org/zk-id/credentials/v1"
  ],
  "type": ["VerifiableCredential", "ZkIdCredential"],
  "id": "urn:uuid:123e4567-e89b-12d3-a456-426614174000",
  "issuer": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
  "issuanceDate": "2026-02-09T01:00:00.000Z",
  "expirationDate": "2027-02-09T01:00:00.000Z",
  "credentialSubject": {
    "id": "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH",
    "zkCredential": {
      "commitment": "12345678901234567890",
      "createdAt": "2026-02-09T00:00:00.000Z"
    }
  },
  "proof": {
    "type": "Ed25519Signature2020",
    "created": "2026-02-09T01:00:00.000Z",
    "verificationMethod": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK#key-1",
    "proofPurpose": "assertionMethod",
    "proofValue": "base64-encoded-signature"
  }
}
```

## Key Differences from Traditional VCs

### Traditional W3C VC
- Reveals all credential attributes (name, birth date, address, etc.)
- Signature proves authenticity
- Holder must share full credential to prove claims

### zk-id W3C VC
- **Only reveals the commitment** (Poseidon hash)
- Signature proves authenticity of the commitment
- Holder generates **zero-knowledge proofs** to prove claims (age >= 18, nationality, etc.) **without revealing the commitment or underlying attributes**
- Privacy-preserving by design

## Usage

### Convert zk-id SignedCredential to W3C VC

```typescript
import { toW3CVerifiableCredential } from '@zk-id/core';

// Existing zk-id signed credential
const signedCredential = await issuer.issueCredential(1990, 840);

// Convert to W3C VC format
const vc = toW3CVerifiableCredential(signedCredential, {
  issuerDID: 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK',
  subjectDID: 'did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH',
  expirationDate: '2027-02-09T00:00:00.000Z',
});

// Now `vc` can be stored in a W3C VC wallet or presented to a W3C VC verifier
```

### Convert W3C VC back to zk-id format

```typescript
import { fromW3CVerifiableCredential } from '@zk-id/core';

// W3C VC received from a wallet or issuer
const vc = await wallet.getCredential('credential-id');

// Convert back to zk-id SignedCredential
const signedCredential = fromW3CVerifiableCredential(vc);

// Use with zk-id prover to generate ZK proofs
const ageProof = await generateAgeProof(signedCredential.credential, 18, nonce, timestamp);
```

### Generate DID from Ed25519 Public Key

```typescript
import { ed25519PublicKeyToDIDKey, didKeyToEd25519PublicKey } from '@zk-id/core';

// Convert Ed25519 public key to did:key identifier
const publicKeyBytes = new Uint8Array(32); // Your Ed25519 public key
const didKey = ed25519PublicKeyToDIDKey(publicKeyBytes);
// Returns: "did:key:z6Mk..."

// Extract public key from did:key
const recoveredKey = didKeyToEd25519PublicKey(didKey);
// Returns: Uint8Array(32)
```

## DID Support

### Supported DID Methods

- **did:key** - Fully supported for Ed25519 keys (recommended for simple deployments)
- **did:web** - Planned (v1.2)
- **did:ion** - Planned (v2.0)

### Using did:key

`did:key` is a deterministic DID method that derives the DID from the public key itself. No registration or blockchain is required.

```typescript
// Issuer generates Ed25519 key pair
const { publicKey, privateKey } = generateKeyPairSync('ed25519');

// Convert public key to DID
const issuerDID = ed25519PublicKeyToDIDKey(
  publicKey.export({ type: 'spki', format: 'der' }).slice(-32) // Last 32 bytes
);

// Use DID when issuing credentials
const vc = toW3CVerifiableCredential(signedCredential, {
  issuerDID,
});
```

### Using did:web (Planned v1.2)

`did:web` anchors DIDs to web domains, enabling organizational trust.

```typescript
// Example (not yet implemented)
const vc = toW3CVerifiableCredential(signedCredential, {
  issuerDID: 'did:web:government.gov:issuers:passport',
});
```

## Interoperability Roadmap

### v1.1.0 (Current - February 2026)
- ✅ W3C VC Data Model v2.0 `@context` and `type` fields
- ✅ DID support for issuers and subjects (`did:key`)
- ✅ Ed25519Signature2020 proof type
- ✅ Conversion helpers (`toW3CVerifiableCredential`, `fromW3CVerifiableCredential`)
- ✅ Backward compatibility with existing zk-id credentials

### v1.2.0 (Q3 2026)
- JSON-LD `@context` alignment with zk-id-specific vocabulary
- `did:web` support for organizational issuers
- VC Data Integrity proof suite definition (`zkProof2026`)
- DIF Presentation Exchange v2.0 support

### v1.3.0 (Q4 2026)
- W3C VC v2.0 full compliance (passes VC validators)
- Credential Status integration (RevocationList2020)
- Selective disclosure presentation format

### v2.0.0 (2027+)
- `did:ion` support (Sidetree on Bitcoin)
- DID resolution across multiple methods
- Participation in W3C VC-WG interoperability testing
- Cross-ecosystem wallet support

## Limitations and Gaps

### Current Limitations (v1.1.0)

1. **zk-id-specific `@context` is a placeholder**
   - The `https://w3id.org/zk-id/credentials/v1` context URL does not resolve
   - Full JSON-LD vocabulary definition is planned for v1.2

2. **Proof type is standard Ed25519, not ZK-specific**
   - The `Ed25519Signature2020` proof signs the commitment, not the attributes
   - A custom `zkProof2026` proof suite is planned for v1.2

3. **Credential recovery is incomplete**
   - `fromW3CVerifiableCredential` cannot recover `birthYear`, `nationality`, or `salt` from the commitment
   - This is by design (privacy-preserving), but means the W3C VC envelope is primarily for signature verification

4. **No credential status support**
   - Revocation is handled via zk-id's Merkle tree, not W3C RevocationList2020
   - Integration planned for v1.3

### Privacy vs. Interoperability Tradeoff

**W3C VC wallets expect to display credential attributes.**

Traditional W3C VCs contain claims like:
```json
{
  "credentialSubject": {
    "name": "Alice Smith",
    "birthDate": "1990-01-15",
    "nationality": "USA"
  }
}
```

zk-id VCs only contain the commitment:
```json
{
  "credentialSubject": {
    "zkCredential": {
      "commitment": "12345678901234567890"
    }
  }
}
```

**Wallets that expect to display attributes will show "unknown" or the commitment hash.**

This is intentional — revealing attributes defeats the purpose of zero-knowledge proofs. Users must understand that:
- The credential itself is **opaque** (commitment only)
- **Proofs** are generated to prove specific claims (age >= 18, nationality = US)
- Verifiers receive **proofs**, not credentials

## Integration with W3C VC Wallets

### Browser Wallet Support

zk-id includes a browser wallet prototype (`BrowserWallet` in `@zk-id/sdk`) that:
- Stores W3C VC-formatted credentials in IndexedDB
- Generates ZK proofs when verifiers request them
- Presents proofs using W3C Presentation Exchange (v1.2)

### External Wallet Integration

To integrate with existing W3C VC wallets:

1. **Issue credentials in W3C VC format**
   ```typescript
   const vc = toW3CVerifiableCredential(signedCredential, { issuerDID, subjectDID });
   ```

2. **Wallet stores the VC**
   - The wallet sees a standard W3C VC
   - The `zkCredential` field contains the commitment
   - Most wallets will display this as an "unknown" credential type

3. **Verifier requests a proof (not the credential)**
   - Use DIF Presentation Exchange or custom proof request protocol
   - Wallet calls zk-id prover to generate ZK proof
   - Wallet sends proof to verifier (not the credential itself)

## Examples

### Example 1: Government ID Issuer with did:web

```typescript
import { ManagedCredentialIssuer } from '@zk-id/issuer';
import { toW3CVerifiableCredential } from '@zk-id/core';

// Government issuer with did:web (v1.2)
const issuer = new ManagedCredentialIssuer(keyManager);
const signedCredential = await issuer.issueCredential(1990, 840, userId);

const vc = toW3CVerifiableCredential(signedCredential, {
  issuerDID: 'did:web:government.gov:identity:issuers:passport',
  subjectDID: userDID,
  expirationDate: '2036-02-09T00:00:00.000Z', // 10-year passport validity
  verificationMethod: 'did:web:government.gov:identity:issuers:passport#signing-key-2026',
});

// Store in citizen's wallet
await wallet.store(vc);
```

### Example 2: University Credential

```typescript
// University issues age-verified credential for student discounts
const studentCredential = await universityIssuer.issueCredential(2000, 840);

const vc = toW3CVerifiableCredential(studentCredential, {
  issuerDID: 'did:web:university.edu:credentials',
  subjectDID: studentDID,
  expirationDate: '2028-06-01T00:00:00.000Z', // Valid until graduation
});

// Student proves they're 18+ for discount without revealing exact age
const ageProof = await generateAgeProof(studentCredential.credential, 18, nonce, timestamp);
await merchant.verifyProof(ageProof);
```

### Example 3: Cross-Border Identity

```typescript
// EU citizen with credential issued by member state
const euCredential = await euIssuer.issueCredential(1985, 276); // Germany (276)

const vc = toW3CVerifiableCredential(euCredential, {
  issuerDID: 'did:web:bsi.bund.de:eid', // German Federal Office for Information Security
  subjectDID: citizenDID,
});

// Citizen proves EU nationality to access EU-only service
const nationalityProof = await generateNationalityProof(
  euCredential.credential,
  276, // Germany
  nonce,
  timestamp
);

// Verifier accepts any EU member state nationality code
await verifier.verifyProof(nationalityProof);
```

## Standards Compliance

### W3C Verifiable Credentials Data Model v2.0

✅ **Compliant**:
- `@context` array with VC v2.0 context
- `type` array including "VerifiableCredential"
- Required properties: `id`, `issuer`, `issuanceDate`, `credentialSubject`
- Proof object with `type`, `created`, `verificationMethod`, `proofPurpose`

⚠️ **Partial Compliance**:
- Custom `@context` is a placeholder (not resolvable)
- `zkCredential` is a non-standard credentialSubject property

🔜 **Planned**:
- JSON-LD vocabulary definition
- Custom proof suite (`zkProof2026`)
- Credential Status integration

### W3C Decentralized Identifiers (DIDs) v1.0

✅ **Compliant**:
- `did:key` method implementation
- Multicodec prefix for Ed25519 (0xed 0x01)
- Base58 encoding with Bitcoin alphabet

🔜 **Planned**:
- `did:web` method support
- `did:ion` method support
- DID resolution

## Security Considerations

### Proof Security

The W3C VC proof signs the **commitment**, not the underlying attributes. This means:

✅ Signature proves the issuer created a valid commitment
✅ ZK proofs prove claims about the committed attributes
❌ The VC alone does not reveal the attributes

**Attack resistance:**
- Signature forgery is prevented by Ed25519 cryptography
- Commitment binding is enforced by Poseidon hash in the circuit
- Replay attacks are mitigated by nonce + timestamp in ZK proofs

### DID Security

- `did:key` is self-certifying (no external registry required)
- `did:web` relies on DNS and HTTPS security
- `did:ion` provides blockchain-anchored trust (planned)

**Key management:**
- Issuers must protect Ed25519 private keys
- Use KMS/HSM for production deployments
- Regular key rotation is recommended (see `@zk-id/issuer` policy tooling)

### Revocation Security

zk-id uses **Merkle tree inclusion proofs** for revocation, not W3C RevocationList2020. This provides:

✅ Privacy-preserving revocation checks (in-circuit)
✅ No centralized revocation list server required
❌ Not compatible with W3C VC revocation tooling (yet)

Integration with RevocationList2020 is planned for v1.3.

## Migration Guide

### From zk-id v1.0.0 to W3C VC (v1.1.0)

**Option 1: Dual format (recommended)**
- Issue credentials in both formats
- Store W3C VC in wallets for interoperability
- Use zk-id format internally for ZK proof generation

```typescript
const signedCredential = await issuer.issueCredential(1990, 840);
const vc = toW3CVerifiableCredential(signedCredential, { issuerDID });

// Store both
await internalDB.store(signedCredential); // For ZK proofs
await wallet.store(vc); // For W3C VC interoperability
```

**Option 2: W3C VC only (forward-compatible)**
- Issue only W3C VCs
- Convert to zk-id format when generating proofs

```typescript
const signedCredential = await issuer.issueCredential(1990, 840);
const vc = toW3CVerifiableCredential(signedCredential, { issuerDID });
await wallet.store(vc);

// Later: convert back for proof generation
const zkCredential = fromW3CVerifiableCredential(vc);
const proof = await generateAgeProof(zkCredential.credential, 18, nonce, timestamp);
```

**Option 3: W3C VC with embedded zk-id data (custom)**
- Extend `credentialSubject` with both formats

```typescript
const vc = {
  ...toW3CVerifiableCredential(signedCredential, { issuerDID }),
  credentialSubject: {
    ...toW3CVerifiableCredential(signedCredential, { issuerDID }).credentialSubject,
    zkIdInternal: signedCredential, // Embed original for proof generation
  },
};
```

**Breaking changes:** None. W3C VC support is additive.

**Backward compatibility:** All existing zk-id credentials work as-is.

## Learn More

- [W3C Verifiable Credentials Data Model v2.0](https://www.w3.org/TR/vc-data-model-2.0/)
- [W3C Decentralized Identifiers (DIDs) v1.0](https://www.w3.org/TR/did-core/)
- [DIF Presentation Exchange v2.0](https://identity.foundation/presentation-exchange/)
- [zk-id Protocol Documentation](./PROTOCOL.md)
- [zk-id Architecture](./ARCHITECTURE.md)

---

**Last updated:** 2026-02-09
**Version:** v1.1.0
**Status:** Production-ready with limitations (see above)
