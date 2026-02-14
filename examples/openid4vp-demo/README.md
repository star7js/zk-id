# OpenID4VP Demo - 2-Minute Quickstart

See zero-knowledge age verification with OpenID4VP in action.

## What This Demo Shows

- **Browser wallet** that stores credentials and generates ZK proofs
- **Verifier** that creates OpenID4VP authorization requests
- **Full end-to-end flow** from credential issuance to proof verification
- **Standards compliance** with OpenID4VP and DIF Presentation Exchange

## Prerequisites

1. Node.js 18+ installed
2. From repository root, run:

```bash
npm install
npm run compile:circuits  # If not already done
npm run --workspace=@zk-id/circuits setup
```

## Run the Demo

```bash
cd examples/openid4vp-demo
npm start
```

This launches three servers automatically:

- **Port 3000**: Browser UI (opens automatically)
- **Port 3001**: Credential issuer
- **Port 3002**: OpenID4VP verifier

## Try It Out (2 minutes)

### Step 1: Issue a credential (30 seconds)

On the right panel (Browser Wallet):

1. Enter a name, date of birth, and nationality (defaults provided)
2. Click "Issue Credential from Issuer"
3. Wait for the credential to appear in "My Credentials"

### Step 2: Create verification request (15 seconds)

On the left panel (Verifier):

1. Set minimum age (default: 18)
2. Click "Create Authorization Request"
3. QR code appears (for mobile wallets) and request details below

### Step 3: Generate and verify proof (60 seconds)

On the right panel (Browser Wallet):

1. Click "Generate & Submit Proof"
2. Wait ~45 seconds while the ZK proof is generated
3. See verification result on the left panel

**Result**: The verifier confirms you're 18+ without seeing your exact birth date!

## What Just Happened?

1. **Issuer** signed a credential with your birth date
2. **Wallet** stored the credential locally
3. **Verifier** requested proof of age >= 18
4. **Wallet** generated a ZK proof (birth date stays private!)
5. **Verifier** verified the proof cryptographically

## Key Feature: Zero-Knowledge

Unlike standard OpenID4VP with SD-JWT (which reveals "birthDate: 1990-01-01"), zk-id only proves "age >= 18" without revealing the actual birth date.

## Architecture

```
Browser Wallet (3000) <---> Verifier (3002)
       |
       v
Issuer Server (3001)
```

- **Wallet**: Manages credentials, generates ZK proofs client-side
- **Verifier**: Creates OpenID4VP requests, verifies presentations
- **Issuer**: Issues signed credentials (EdDSA signatures)

## Code Highlights

### Verifier Setup

```typescript
import { OpenID4VPVerifier } from '@zk-id/sdk';

const verifier = new OpenID4VPVerifier({
  zkIdServer,
  verifierUrl: 'http://localhost:3002',
  callbackUrl: 'http://localhost:3002/openid4vp/callback',
});

// Create authorization request
const authRequest = verifier.createAgeVerificationRequest(18);

// Verify presentation
const result = await verifier.verifyPresentation(presentation);
```

### Wallet Setup

```typescript
import { OpenID4VPWallet, InMemoryCredentialStore } from '@zk-id/sdk';

const wallet = new OpenID4VPWallet({
  credentialStore: new InMemoryCredentialStore(),
  circuitPaths: { ageWasm, ageZkey },
});

// Generate presentation
const presentation = await wallet.generatePresentation(authRequest);
```

## File Structure

```
openid4vp-demo/
├── src/
│   ├── verifier.ts      # OpenID4VP verifier server (Express)
│   └── client.ts        # Browser wallet logic
├── index.html           # Split-panel UI (verifier + wallet)
├── vite.config.ts       # Vite bundler config
└── package.json         # Scripts and dependencies
```

## Next Steps

- Integrate into your app: See [Integration Guide](../../docs/INTEGRATION.md)
- Deploy issuer: See [@zk-id/issuer-server](../../packages/issuer-server)
- Mobile wallet: See [@zk-id/mobile](../../packages/mobile)
- Full docs: [OpenID4VP Documentation](../../docs/OPENID4VP.md)

## Standards Implemented

- ✅ OpenID4VP authorization requests
- ✅ DIF Presentation Exchange v2.0.0
- ✅ W3C Verifiable Presentations
- ✅ Direct Post response mode
- ⚠️ Request by reference (not yet implemented)

## Troubleshooting

**Servers not starting?**

- Ensure ports 3000, 3001, 3002 are available
- Check `npm install` completed successfully

**Proof generation taking too long?**

- First proof takes ~45-60 seconds (circuit loading)
- Subsequent proofs are faster (~10-15 seconds)

**Verification failing?**

- Ensure credential was issued before creating request
- Check browser console for errors
- Verify all three servers are running (check status dots)

## Resources

- [OpenID4VP Spec](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html)
- [DIF Presentation Exchange](https://identity.foundation/presentation-exchange/)
- [zk-id Documentation](https://zk-id.io/docs)
