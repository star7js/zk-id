# OpenID4VP Demo

Standards-compliant demonstration of OpenID for Verifiable Presentations (OpenID4VP) with zk-id.

This example shows how zk-id integrates with the OpenID4VP standard to enable:

- **Wallet interoperability**: Any OpenID4VP-compliant wallet can work with zk-id verifiers
- **Standards compliance**: Implements DIF Presentation Exchange v2.0.0 and W3C VC format
- **Enterprise integration**: Compatible with existing SSI infrastructure

## Architecture

```
┌──────────────┐                  ┌──────────────┐                 ┌──────────────┐
│   Verifier   │                  │    Wallet    │                 │    Issuer    │
│ (OpenID4VP)  │                  │  (OpenID4VP) │                 │  (zk-id)     │
└──────────────┘                  └──────────────┘                 └──────────────┘
       │                                 │                                 │
       │ 1. Authorization Request        │                                 │
       │    (Presentation Definition)    │                                 │
       ├────────────────────────────────>│                                 │
       │                                 │  2. Fetch credential            │
       │                                 │────────────────────────────────>│
       │                                 │  3. Return credential           │
       │                                 │<────────────────────────────────┤
       │                                 │  4. Generate ZK proof           │
       │                                 │     (locally, private)          │
       │  5. Submit Presentation         │                                 │
       │<────────────────────────────────┤                                 │
       │  6. Verify proof ✓              │                                 │
```

## Quick Start

### Prerequisites

From the repository root:

```bash
# Install dependencies
npm install

# Compile circuits (if not already done)
npm run compile:circuits
npm run --workspace=@zk-id/circuits setup
```

### Run the Demo

```bash
cd examples/openid4vp-demo
npm install
npm start
```

This starts three servers:

1. **Issuer Server** (port 3001): Issues zk-id credentials
2. **Verifier Server** (port 3002): OpenID4VP-compliant verifier
3. **Web UI** (port 3000): Browser-based wallet simulator

Open http://localhost:3000 to try the demo.

## What You'll See

### Step 1: Get a Credential

The demo provides a test credential:

- Birth year: 1990
- Nationality: 840 (United States)
- Issuer: Demo Identity Provider
- Expiration: 1 year from issuance

### Step 2: Authorization Request

The verifier creates an OpenID4VP authorization request:

```json
{
  "presentation_definition": {
    "id": "age-verification-12345",
    "name": "Age Verification",
    "purpose": "Prove you are at least 18 years old",
    "input_descriptors": [...]
  },
  "response_mode": "direct_post",
  "response_uri": "http://localhost:3002/openid4vp/callback",
  "nonce": "abc123...",
  "client_id": "demo-verifier",
  "state": "xyz789..."
}
```

### Step 3: Generate Presentation

The wallet:

1. Parses the authorization request
2. Shows you what's being requested (age >= 18)
3. Generates a ZK proof locally (your birth year stays private!)
4. Packages it as a W3C Verifiable Presentation

### Step 4: Submit & Verify

The wallet submits the presentation to the verifier's callback URL. The verifier:

1. Validates the state parameter
2. Decodes the VP token
3. Verifies the ZK proof cryptographically
4. Checks credential expiration and issuer signature
5. Returns verification result

## Code Examples

### Verifier (Server-side)

```typescript
import { ZkIdServer, OpenID4VPVerifier } from '@zk-id/sdk';

// Standard zk-id server
const zkIdServer = new ZkIdServer({
  verificationKeyPath: './verification_key.json',
  issuerRegistry,
});

// Wrap with OpenID4VP
const verifier = new OpenID4VPVerifier({
  zkIdServer,
  verifierUrl: 'http://localhost:3002',
  verifierId: 'demo-verifier',
});

// Create authorization request
app.get('/auth/request', (req, res) => {
  const authRequest = verifier.createAgeVerificationRequest(18);
  res.json(authRequest);
});

// Handle presentation submission
app.post('/openid4vp/callback', async (req, res) => {
  const result = await verifier.verifyPresentation(req.body, req.ip);
  res.json({ verified: result.verified });
});
```

### Wallet (Browser-side)

```typescript
import { OpenID4VPWallet } from '@zk-id/sdk';

// Initialize wallet
const wallet = new OpenID4VPWallet({
  store: new IndexedDBCredentialStore(),
  walletId: 'demo-wallet',
});

// Fetch authorization request
const response = await fetch('http://localhost:3002/auth/request');
const authRequest = await response.json();

// Generate presentation
const presentation = await wallet.generatePresentation(authRequest);

// Submit to verifier
await wallet.submitPresentation(authRequest, presentation);
```

## File Structure

```
openid4vp-demo/
├── package.json
├── README.md
├── src/
│   ├── issuer.ts          # Credential issuer (port 3001)
│   ├── verifier.ts        # OpenID4VP verifier (port 3002)
│   ├── index.html         # Browser wallet UI
│   └── client.ts          # Browser wallet logic
└── public/
    └── style.css          # UI styling
```

## Standards Compliance

This demo implements:

### OpenID4VP

- ✅ Authorization Request format
- ✅ Direct Post response mode
- ✅ Presentation Submission metadata
- ⚠️ Request by reference (not yet implemented)

### DIF Presentation Exchange v2.0.0

- ✅ Presentation Definitions
- ✅ Input Descriptors with constraints
- ✅ Field filters (type, pattern, minimum, enum)
- ✅ Descriptor maps

### W3C Verifiable Credentials

- ✅ VerifiablePresentation type
- ✅ Standard @context URLs
- ✅ Holder identifier
- ⚠️ Proof format is custom (ZK-SNARK, not JSON-LD)

## Key Differentiator

Unlike standard OpenID4VP implementations that just disclose attributes (e.g., "birthDate: 1990-01-01"), zk-id provides **true zero-knowledge predicate proofs**:

- Standard OpenID4VP + SD-JWT: "Here's my birthDate: 1990-01-01"
- zk-id + OpenID4VP: "I'm >= 18 years old" (birth year stays private!)

This is the **only** OpenID4VP implementation with true zero-knowledge proofs.

## Try It Yourself

1. **Issue a credential** from the issuer server
2. **Scan the QR code** (or click the link) with your wallet
3. **See the authorization request** (what the verifier is asking for)
4. **Approve the request** (generates ZK proof locally)
5. **See the verification result** (proof verified, age confirmed!)

## Resources

- [OpenID4VP Specification](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html)
- [DIF Presentation Exchange](https://identity.foundation/presentation-exchange/spec/v2.0.0/)
- [zk-id OpenID4VP Documentation](../../docs/OPENID4VP.md)

## Next Steps

After trying this demo:

- Integrate OpenID4VP into your application (see [integration guide](../../docs/OPENID4VP.md))
- Deploy the reference issuer server (see [@zk-id/issuer-server](../../packages/issuer-server/README.md))
- Explore the full web-app example (see [web-app demo](../web-app/README.md))
