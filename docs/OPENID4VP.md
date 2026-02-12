# OpenID4VP Integration

zk-id implements **OpenID for Verifiable Presentations (OpenID4VP)**, enabling interoperability with standard identity wallets and verifiers in the Self-Sovereign Identity (SSI) ecosystem.

## What is OpenID4VP?

OpenID4VP is an extension to OpenID Connect that enables presentation of verifiable credentials. It defines:

1. **Authorization Request**: How a verifier requests credentials from a wallet
2. **Presentation Definition**: What credentials are required (using DIF Presentation Exchange)
3. **Verifiable Presentation**: How credentials are packaged and presented
4. **Presentation Submission**: Metadata describing how requirements were fulfilled

## Why OpenID4VP for zk-id?

**Standards compliance** is critical for adoption:

- ✅ **Interoperability**: Works with any OpenID4VP-compliant wallet
- ✅ **First-mover**: First ZK identity project with native OpenID4VP support
- ✅ **Enterprise-ready**: Aligns with EU Digital Identity Wallet (EUDI), DC-API
- ✅ **Ecosystem integration**: Compatible with existing verifier infrastructure

## Architecture

```
┌──────────────┐                  ┌──────────────┐                 ┌──────────────┐
│   Verifier   │                  │    Wallet    │                 │    Issuer    │
│ (OpenID4VP)  │                  │  (OpenID4VP) │                 │  (zk-id)     │
└──────────────┘                  └──────────────┘                 └──────────────┘
       │                                 │                                 │
       │ 1. Create Authorization Request │                                 │
       │    (Presentation Definition)    │                                 │
       ├────────────────────────────────>│                                 │
       │                                 │                                 │
       │                                 │  2. Fetch credential            │
       │                                 │────────────────────────────────>│
       │                                 │                                 │
       │                                 │  3. Return signed credential    │
       │                                 │<────────────────────────────────┤
       │                                 │                                 │
       │                                 │  4. Generate ZK proof locally   │
       │                                 │     (no data sent)              │
       │                                 │                                 │
       │  5. Submit Verifiable           │                                 │
       │     Presentation (VP + proof)   │                                 │
       │<────────────────────────────────┤                                 │
       │                                 │                                 │
       │  6. Verify proof cryptographically                                │
       │     (learns: age >= 18)         │                                 │
       │     (doesn't learn: birth year) │                                 │
       │                                 │                                 │
```

## Usage

### For Verifiers

Use `OpenID4VPVerifier` to create standard-compliant authorization requests:

```typescript
import { ZkIdServer, OpenID4VPVerifier } from '@zk-id/sdk';

// Initialize standard zk-id server
const zkIdServer = new ZkIdServer({
  verificationKeyPath: './verification_key.json',
  issuerRegistry,
});

// Wrap with OpenID4VP verifier
const verifier = new OpenID4VPVerifier({
  zkIdServer,
  verifierUrl: 'https://your-verifier.com',
  verifierId: 'your-verifier-id',
  callbackUrl: 'https://your-verifier.com/openid4vp/callback',
});

// Create authorization request for age verification
const authRequest = verifier.createAgeVerificationRequest(18);

// Send to wallet (URL, QR code, deep link)
const authUrl = `openid4vp://?${new URLSearchParams({
  presentation_definition: JSON.stringify(authRequest.presentation_definition),
  response_uri: authRequest.response_uri,
  nonce: authRequest.nonce,
  client_id: authRequest.client_id,
  state: authRequest.state,
})}`;

// Or display as QR code for mobile wallets
```

### Handle Presentation Submission

```typescript
app.post('/openid4vp/callback', async (req, res) => {
  const presentationResponse = req.body;

  const result = await verifier.verifyPresentation(presentationResponse, req.ip);

  if (result.verified) {
    res.json({ status: 'success' });
  } else {
    res.status(400).json({ status: 'failed', error: result.error });
  }
});
```

### For Wallets

Use `OpenID4VPWallet` to handle authorization requests and generate presentations:

```typescript
import { OpenID4VPWallet, IndexedDBCredentialStore } from '@zk-id/sdk';

// Initialize wallet
const wallet = new OpenID4VPWallet({
  store: new IndexedDBCredentialStore(),
  walletId: 'did:example:123',
});

// Parse authorization request (from URL, QR, or deep link)
const authRequest = wallet.parseAuthorizationRequest(authRequestUrl);

// Generate verifiable presentation
const presentation = await wallet.generatePresentation(authRequest);

// Submit to verifier
const success = await wallet.submitPresentation(authRequest, presentation);
```

## Presentation Exchange Format

### Presentation Definition (Request)

The verifier specifies what credentials are required using DIF Presentation Exchange:

```json
{
  "id": "age-verification-12345",
  "name": "Age Verification",
  "purpose": "Prove you are at least 18 years old without revealing your birth year",
  "input_descriptors": [
    {
      "id": "age-proof",
      "name": "Age Proof",
      "purpose": "Minimum age: 18",
      "constraints": {
        "fields": [
          {
            "path": ["$.type"],
            "filter": {
              "type": "string",
              "pattern": "^AgeProof$"
            }
          },
          {
            "path": ["$.publicSignals.minAge"],
            "filter": {
              "type": "number",
              "minimum": 18
            }
          }
        ]
      }
    }
  ]
}
```

### Verifiable Presentation (Response)

The wallet packages the ZK proof as a verifiable presentation:

```json
{
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://identity.foundation/presentation-exchange/submission/v1"
  ],
  "type": ["VerifiablePresentation", "PresentationSubmission"],
  "presentation_submission": {
    "id": "abc-123",
    "definition_id": "age-verification-12345",
    "descriptor_map": [
      {
        "id": "age-proof",
        "format": "zk-id/proof-v1",
        "path": "$.verifiableCredential[0]"
      }
    ]
  },
  "verifiableCredential": [
    {
      "proofType": "age",
      "proof": {
        /* Groth16 proof */
      },
      "publicSignals": {
        "currentYear": 2026,
        "minAge": 18,
        "credentialHash": "...",
        "nonce": "...",
        "requestTimestamp": 1707652800000
      }
    }
  ],
  "holder": "did:example:123"
}
```

## Standards Compliance

### OpenID4VP

zk-id implements the core OpenID4VP specification:

- ✅ **Authorization Request**: Standard request format
- ✅ **Direct Post Response**: POST to callback URL
- ✅ **Presentation Submission**: Metadata describing fulfillment
- ⚠️ **Request by Reference**: Not yet supported (request_uri)
- ⚠️ **JWT-encoded Requests**: Not yet supported

### DIF Presentation Exchange v2.0.0

zk-id supports key features:

- ✅ **Presentation Definitions**: Input descriptors with constraints
- ✅ **Field Filters**: Type, pattern, minimum, maximum, enum
- ✅ **Presentation Submission**: Descriptor map
- ⚠️ **Predicate Logic**: Only simple constraints (no AND/OR combinations yet)
- ⚠️ **Submission Requirements**: Not yet supported

### W3C Verifiable Credentials

zk-id presentations use standard VC format:

- ✅ **@context**: Standard VC context URLs
- ✅ **type**: VerifiablePresentation type
- ✅ **holder**: Optional holder identifier
- ⚠️ **Proof**: ZK proof format is custom (not JSON-LD proof)

## Integration Patterns

### Pattern 1: Website Age Gate

```typescript
// 1. User visits age-restricted content
app.get('/restricted', (req, res) => {
  // 2. Verifier creates authorization request
  const authRequest = verifier.createAgeVerificationRequest(18);

  // 3. Display QR code or deep link
  res.render('age-gate', {
    authUrl: buildAuthUrl(authRequest),
    state: authRequest.state,
  });
});

// 4. Wallet scans QR, generates proof, submits
app.post('/openid4vp/callback', async (req, res) => {
  const result = await verifier.verifyPresentation(req.body, req.ip);

  if (result.verified) {
    // 5. Grant access
    req.session.ageVerified = true;
    res.redirect('/restricted');
  } else {
    res.status(400).json({ error: 'Verification failed' });
  }
});
```

### Pattern 2: Mobile App Integration

```typescript
// Deep link scheme: yourapp://openid4vp
const authUrl = `yourapp://openid4vp?${encodeAuthRequest(authRequest)}`;

// In mobile app
app.get('/openid4vp', async (params) => {
  const authRequest = wallet.parseAuthorizationRequest(params);

  // Show UI: "Verifier requests proof of age >= 18"
  const approved = await showConsentUI(authRequest);

  if (approved) {
    const presentation = await wallet.generatePresentation(authRequest);
    await wallet.submitPresentation(authRequest, presentation);
  }
});
```

### Pattern 3: Browser Extension Wallet

```typescript
// Content script listens for authorization requests
window.addEventListener('message', async (event) => {
  if (event.data.type === 'OPENID4VP_REQUEST') {
    const authRequest = event.data.request;

    // Extension popup: "Grant proof?"
    const approved = await chrome.runtime.sendMessage({
      type: 'REQUEST_APPROVAL',
      request: authRequest,
    });

    if (approved) {
      const presentation = await wallet.generatePresentation(authRequest);
      window.postMessage(
        {
          type: 'OPENID4VP_RESPONSE',
          presentation,
        },
        '*',
      );
    }
  }
});
```

## Security Considerations

### Nonce Replay Protection

- Each authorization request includes a unique nonce
- Verifier tracks nonces to prevent replay attacks
- Nonces expire after verification

### State Parameter

- Binds the authorization request to the callback
- Prevents CSRF attacks
- Must be validated on callback

### HTTPS Required

- All communication must use HTTPS in production
- Prevents man-in-the-middle attacks
- Required by OpenID4VP specification

### Credential Expiration

- Credentials can include `expiresAt` timestamp
- Verifier checks expiration before accepting proof
- Clock skew tolerance (default: 1 minute)

## Comparison to Standards-Based Alternatives

| Feature                   | zk-id + OpenID4VP | Plain OpenID4VP | SD-JWT VC    | BBS+          |
| ------------------------- | ----------------- | --------------- | ------------ | ------------- |
| **Zero-Knowledge**        | ✅ Full           | ❌ No           | ⚠️ Selective | ⚠️ Selective  |
| **Proof Size**            | ✅ ~200 bytes     | N/A             | ⚠️ ~1-5KB    | ⚠️ ~500 bytes |
| **Predicate Proofs**      | ✅ Yes (age >= X) | ❌ No           | ❌ No        | ❌ No         |
| **Standards Compliant**   | ✅ Yes            | ✅ Yes          | ✅ Yes       | ⚠️ Draft      |
| **Browser-based**         | ✅ Yes            | ✅ Yes          | ✅ Yes       | ⚠️ Limited    |
| **On-chain Verification** | ✅ Yes            | ❌ No           | ❌ No        | ⚠️ Limited    |

**Key Differentiator**: zk-id is the only solution that combines OpenID4VP compliance with true zero-knowledge predicate proofs (e.g., "age >= 18" without revealing birth year).

## Roadmap

### Near-term (Q1-Q2 2026)

- ✅ OpenID4VP verifier wrapper
- ✅ OpenID4VP wallet adapter
- ✅ DIF Presentation Exchange v2.0.0
- ✅ W3C VP format
- 🔄 JWT-encoded requests
- 🔄 Request by reference (request_uri)

### Medium-term (Q3-Q4 2026)

- 🔄 EU Digital Identity Wallet (EUDI) compatibility
- 🔄 DC-API (Digital Credentials API) integration
- 🔄 Mobile SDK with OpenID4VP support
- 🔄 Verifier discovery (OpenID Federation)

### Long-term (2027+)

- 🔄 DIDComm v2 integration
- 🔄 CHAPI (Credential Handler API) support
- 🔄 Verifiable Presentation Request v2.0

## Resources

### Specifications

- [OpenID for Verifiable Presentations](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html)
- [DIF Presentation Exchange v2.0.0](https://identity.foundation/presentation-exchange/spec/v2.0.0/)
- [W3C Verifiable Credentials Data Model](https://www.w3.org/TR/vc-data-model/)

### Implementations

- [OpenID4VP Reference Implementation](https://github.com/openid/OpenID4VP)
- [DIF Presentation Exchange](https://github.com/decentralized-identity/presentation-exchange)

### Tools

- [OpenID4VP Playground](https://openid4vp.org/playground)
- [Presentation Exchange Visualizer](https://identity.foundation/presentation-exchange/)

## FAQ

### Why not just use SD-JWT or BBS+?

**SD-JWT** and **BBS+** provide selective disclosure but not true zero-knowledge proofs:

- They reveal the exact disclosed attributes (e.g., birthDate: "1990-01-01")
- zk-id proves predicates without revealing inputs (e.g., "age >= 18" without revealing 1990)
- On-chain verification requires ZK-SNARKs (not possible with SD-JWT/BBS+)

### Can existing OpenID4VP wallets use zk-id?

**Partially**. Existing wallets can:

- Parse zk-id authorization requests (standard OpenID4VP)
- Display requested attributes
- Submit presentations to verifiers

But they need zk-id-specific proof generation:

- Use `@zk-id/sdk` for browser-based wallets
- Integrate `@zk-id/core` for mobile/native wallets

### Is zk-id compatible with EUDI?

**Yes, with a wallet adapter**. The EU Digital Identity Wallet (EUDI) uses:

- OpenID4VP for presentation (✅ compatible)
- SD-JWT for credentials (🔄 adapter needed)

zk-id can act as a privacy-enhancing layer:

1. Issuer issues both SD-JWT (for EUDI) and zk-id credential
2. Wallet stores both formats
3. For high-privacy scenarios, use zk-id credential
4. For standard scenarios, use SD-JWT credential

### Can I use zk-id with existing verifiers?

**Yes, if they support OpenID4VP**. The verifier just needs to:

1. Accept the custom proof format (`zk-id/proof-v1`)
2. Integrate `@zk-id/sdk` for verification
3. Trust the issuer's public key

For closed ecosystems (e.g., government verifiers), this requires negotiation.

## Support

For OpenID4VP integration support:

- GitHub Issues: https://github.com/your-repo/zk-id/issues
- Discussions: https://github.com/your-repo/zk-id/discussions
- Email: support@zk-id.io
