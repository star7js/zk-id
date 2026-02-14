# Age Gate Widget - Add Age Verification in 3 Steps

Drop-in, self-contained age verification widget powered by zero-knowledge proofs. No user data collected, no tracking, complete privacy.

## Why This Matters

Traditional age verification either:

- **Asks for birthdates** (privacy violation, data liability)
- **Uses third-party services** (tracking, cost, friction)

**zk-id Age Gate** lets users prove they're 18+ without revealing their birthdate to anyone.

## Live Demo

```bash
# From repository root
cd examples/age-gate-widget
npm install
npm run dev
```

Open http://localhost:5173 and click "Enter Site"

**Note**: Requires the OpenID4VP demo verifier running on port 3002:

```bash
# In another terminal
cd examples/openid4vp-demo
npm start
```

## Integration

### Step 1: Install

```bash
npm install @zk-id/age-gate-widget
```

### Step 2: Import

```typescript
import { ZkIdAgeGateWidget } from '@zk-id/age-gate-widget';
```

### Step 3: Use

```typescript
document.getElementById('enter-button').addEventListener('click', () => {
  ZkIdAgeGateWidget.init({
    verificationEndpoint: 'https://your-verifier.com/auth/request',
    minAge: 18,
    onVerified: () => {
      // User verified! Unlock content
      showRestrictedContent();
    },
    onRejected: (reason) => {
      // Cancelled or failed
      console.log('Verification rejected:', reason);
    },
  });
});
```

**That's it!** The widget handles:

- ✅ Modal UI (self-contained CSS, no external dependencies)
- ✅ Credential issuance (test mode)
- ✅ ZK proof generation (client-side, ~45 seconds)
- ✅ Presentation submission
- ✅ User feedback and error handling

## Configuration

```typescript
interface ZkIdAgeGateConfig {
  // Required
  verificationEndpoint: string; // OpenID4VP verifier endpoint
  minAge: number; // Minimum age (e.g., 18, 21)
  onVerified: () => void; // Success callback

  // Optional
  onRejected?: (reason: string) => void; // Failure/cancel callback
  issuerEndpoint?: string; // Custom issuer (defaults to test issuer)

  circuitPaths?: {
    ageWasm: string; // Defaults to CDN
    ageZkey: string; // Defaults to CDN
  };

  branding?: {
    title?: string; // Modal title (default: "Age Verification Required")
    primaryColor?: string; // Accent color (default: "#238636")
    logo?: string; // Logo URL
  };
}
```

## How It Works

1. **User clicks** "Enter Site"
2. **Widget shows modal** with privacy explanation
3. **User enters birthdate** (for test credential issuance)
4. **ZK proof generated** locally on user's device (~45 seconds)
5. **Proof submitted** to your verifier
6. **Verifier confirms** age requirement met
7. **onVerified() called** → unlock content

**Privacy**: The birthdate never leaves the user's device. Only a cryptographic proof is sent.

## Production Setup

For production, you need:

### 1. Deploy a Verifier

```typescript
import { OpenID4VPVerifier, ZkIdServer } from '@zk-id/sdk';

const verifier = new OpenID4VPVerifier({
  zkIdServer: new ZkIdServer({
    verificationKeyPath: './verification_key.json',
    issuerRegistry,
  }),
  verifierUrl: 'https://your-verifier.com',
  callbackUrl: 'https://your-verifier.com/openid4vp/callback',
});

app.get('/auth/request', (req, res) => {
  const authRequest = verifier.createAgeVerificationRequest(18);
  res.json({ authRequest, qrCode: '...' });
});

app.post('/openid4vp/callback', async (req, res) => {
  const result = await verifier.verifyPresentation(req.body);
  res.json({ verified: result.verified });
});
```

See the [OpenID4VP demo](../openid4vp-demo) for a complete example.

### 2. Point to Your Verifier

```typescript
ZkIdAgeGateWidget.init({
  verificationEndpoint: 'https://your-verifier.com/auth/request',
  issuerEndpoint: 'https://your-issuer.com/issue', // Or integrate with a real credential issuer
  minAge: 18,
  onVerified: () => {
    /* ... */
  },
});
```

### 3. (Optional) Customize Branding

```typescript
ZkIdAgeGateWidget.init({
  // ... other config
  branding: {
    title: 'Verify Your Age',
    primaryColor: '#ff6b6b',
    logo: 'https://your-site.com/logo.png',
  },
});
```

## Use Cases

- **Gaming sites**: Verify players are 18+ for mature content
- **E-commerce**: Age-gate alcohol, tobacco, adult products
- **Social platforms**: Restrict access to age-appropriate content
- **Events**: Verify attendee age for 21+ venues
- **Compliance**: COPPA, GDPR, DSA age verification requirements

## Comparison

| Solution                        | Privacy               | UX                 | Cost                    | Setup              |
| ------------------------------- | --------------------- | ------------------ | ----------------------- | ------------------ |
| **Manual birthdate input**      | ❌ None               | ✅ Simple          | ✅ Free                 | ✅ Instant         |
| **Third-party ID verification** | ❌ Poor               | ❌ Friction        | ❌ $0.50-2/verification | ⚠️ Integration     |
| **zk-id Age Gate**              | ✅ **Zero-knowledge** | ⚠️ ~45s first time | ✅ Free (self-hosted)   | ✅ 3 lines of code |

## Roadmap

- [ ] Persistent wallet storage (localStorage/IndexedDB)
- [ ] Reusable proofs (generate once, use multiple times)
- [ ] Integration with EUDI Wallet / Digital Credentials API
- [ ] Nationality and custom predicate proofs
- [ ] Mobile SDK (React Native, Flutter)

## File Structure

```
age-gate-widget/
├── src/
│   └── age-gate.ts         # Widget implementation
├── index.html              # Demo page
├── package.json
├── vite.config.ts          # Vite config for dev server
└── README.md
```

## FAQ

**Q: Does this store user data?**
A: No. The birthdate is used client-side to generate a proof, then discarded. Nothing is stored.

**Q: Why does it take 45 seconds?**
A: The first proof generation loads the ZK circuit (~5MB WASM + zkey). Subsequent proofs are faster. We're working on proof caching.

**Q: Can users fake their age?**
A: No. The proof is cryptographically bound to a credential signed by a trusted issuer. Without a valid credential, no proof can be generated.

**Q: What about GDPR/COPPA compliance?**
A: zk-id is privacy-first. Since no birthdate is transmitted or stored, you have minimal data liability. Consult your legal team for specific requirements.

**Q: Can I use this in production?**
A: Yes, but you'll need to:

1. Deploy a verifier (see [deployment guide](../../docs/DEPLOYMENT.md))
2. Integrate with a real credential issuer or use the reference issuer
3. Host circuit files on your CDN (or use the default CDN)

## Support

- [Documentation](https://zk-id.io/docs)
- [GitHub Issues](https://github.com/star7js/zk-id/issues)
- [Discord Community](https://discord.gg/zk-id)

## License

MIT - see [LICENSE](../../LICENSE)
