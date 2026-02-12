---
title: 'Integration Guide'
description: 'Complete guide to integrating zero-knowledge identity verification into your application'
category: 'Getting Started'
order: 3
---

# Integration Guide

This guide covers multiple integration paths for adding zero-knowledge identity verification to your application, from quick embeds to full custom implementations.

## Table of Contents

1. [5-Minute Age Verification Embed](#5-minute-embed)
2. [Server-Side Verifier Setup](#server-side-setup)
3. [OpenID4VP Integration Path](#openid4vp-path)
4. [Mobile SDK Integration](#mobile-sdk-path)
5. [Configuration Options](#configuration)
6. [Troubleshooting](#troubleshooting)

---

## 5-Minute Age Verification Embed {#5-minute-embed}

The fastest way to add age verification to any website.

### Step 1: Install the Widget

```bash
npm install @zk-id/age-gate-widget
```

### Step 2: Add to Your Page

```html
<button id="verify-age">Enter Site (18+ Required)</button>

<script type="module">
  import { ZkIdAgeGateWidget } from '@zk-id/age-gate-widget';

  document.getElementById('verify-age').addEventListener('click', () => {
    ZkIdAgeGateWidget.init({
      verificationEndpoint: 'https://your-verifier.com/auth/request',
      minAge: 18,
      onVerified: () => {
        // User verified! Show restricted content
        document.getElementById('restricted-content').classList.remove('hidden');
      },
      onRejected: (reason) => {
        console.log('Verification failed:', reason);
      },
    });
  });
</script>
```

### Step 3: Deploy a Verifier

See [Server-Side Setup](#server-side-setup) below for deploying your verification endpoint.

### Widget Options

```typescript
interface ZkIdAgeGateConfig {
  // Required
  verificationEndpoint: string;  // Your OpenID4VP verifier endpoint
  minAge: number;                 // Minimum age (e.g., 18, 21)
  onVerified: () => void;         // Success callback

  // Optional
  onRejected?: (reason: string) => void;  // Failure callback
  issuerEndpoint?: string;                // Custom issuer URL

  circuitPaths?: {
    ageWasm: string;  // Defaults to CDN
    ageZkey: string;
  };

  branding?: {
    title?: string;        // Modal title
    primaryColor?: string; // Hex color (e.g., "#667eea")
    logo?: string;         // Logo URL
  };
}
```

### Example: Custom Branding

```javascript
ZkIdAgeGateWidget.init({
  verificationEndpoint: 'https://your-verifier.com/auth/request',
  minAge: 21,
  onVerified: () => unlockContent(),
  branding: {
    title: 'Verify Your Age',
    primaryColor: '#ff6b6b',
    logo: 'https://your-site.com/logo.png',
  },
});
```

---

## Server-Side Verifier Setup {#server-side-setup}

Every integration requires a verifier server to validate proofs.

### Quick Start (Express)

```bash
npm install @zk-id/sdk express cors
```

```typescript
import express from 'express';
import cors from 'cors';
import { ZkIdServer, OpenID4VPVerifier, InMemoryIssuerRegistry } from '@zk-id/sdk';

const app = express();
app.use(cors());
app.use(express.json());

// Initialize ZkIdServer
const zkIdServer = new ZkIdServer({
  verificationKeyPath: './verification_key.json',
  issuerRegistry: new InMemoryIssuerRegistry([
    // Add trusted issuer public keys here
  ]),
});

// Wrap with OpenID4VP
const verifier = new OpenID4VPVerifier({
  zkIdServer,
  verifierUrl: 'https://your-verifier.com',
  verifierId: 'your-verifier-id',
  callbackUrl: 'https://your-verifier.com/openid4vp/callback',
});

// Authorization endpoint
app.get('/auth/request', async (req, res) => {
  const minAge = parseInt(req.query.minAge as string) || 18;
  const authRequest = verifier.createAgeVerificationRequest(minAge);

  res.json({
    authRequest,
    qrCode: await generateQRCode(authRequest), // Optional
  });
});

// Callback endpoint
app.post('/openid4vp/callback', async (req, res) => {
  const result = await verifier.verifyPresentation(req.body, req.ip);

  if (result.verified) {
    res.json({ verified: true, message: 'Age verified' });
  } else {
    res.status(400).json({ verified: false, error: result.error });
  }
});

app.listen(3002, () => {
  console.log('Verifier running on http://localhost:3002');
});
```

### Issuer Registry Setup

Add trusted issuer public keys to validate credentials:

```typescript
import { InMemoryIssuerRegistry } from '@zk-id/sdk';

const issuerRegistry = new InMemoryIssuerRegistry([
  {
    id: 'issuer-1',
    publicKey: 'base64-encoded-public-key',
    name: 'Government ID Provider',
  },
  {
    id: 'issuer-2',
    publicKey: 'base64-encoded-public-key',
    name: 'Bank KYC Service',
  },
]);
```

### Environment Variables

```bash
# .env
VERIFIER_URL=https://your-verifier.com
VERIFIER_ID=your-verifier-id
VERIFICATION_KEY_PATH=./verification_key.json
PORT=3002
```

### Deployment

**Railway / Render / Fly.io:**

```bash
# Install dependencies
npm install

# Build
npm run build

# Start
npm start
```

**Docker:**

```dockerfile
FROM node:20-alpine
WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production
COPY . .
RUN npm run build
EXPOSE 3002
CMD ["npm", "start"]
```

---

## OpenID4VP Integration Path {#openid4vp-path}

Standards-compliant integration for interoperability with other wallets.

### Architecture

```
┌──────────────┐                  ┌──────────────┐                 ┌──────────────┐
│   Verifier   │                  │    Wallet    │                 │    Issuer    │
│ (Your App)   │                  │  (User's)    │                 │  (Trusted)   │
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

### Verifier Implementation

```typescript
import { OpenID4VPVerifier } from '@zk-id/sdk';

const verifier = new OpenID4VPVerifier({
  zkIdServer,
  verifierUrl: 'https://your-app.com',
  verifierId: 'your-app',
  callbackUrl: 'https://your-app.com/openid4vp/callback',
});

// Create authorization request
app.get('/auth/request', (req, res) => {
  const authRequest = verifier.createAgeVerificationRequest(18);

  // For mobile wallets, generate QR code
  const qrCode = generateQRCode(`openid4vp://?${new URLSearchParams({
    presentation_definition: JSON.stringify(authRequest.presentation_definition),
    response_uri: authRequest.response_uri,
    nonce: authRequest.nonce,
    client_id: authRequest.client_id,
    state: authRequest.state,
  })}`);

  res.json({ authRequest, qrCode });
});

// Handle presentation submission
app.post('/openid4vp/callback', async (req, res) => {
  const result = await verifier.verifyPresentation(req.body, req.ip);
  res.json({ verified: result.verified });
});
```

### Browser Wallet Implementation

```typescript
import { OpenID4VPWallet, InMemoryCredentialStore } from '@zk-id/sdk';

const wallet = new OpenID4VPWallet({
  credentialStore: new InMemoryCredentialStore(),
  circuitPaths: {
    ageWasm: 'https://cdn.example.com/age.wasm',
    ageZkey: 'https://cdn.example.com/age.zkey',
  },
  walletId: 'my-wallet',
});

// Fetch authorization request from verifier
const response = await fetch('https://verifier.com/auth/request');
const { authRequest } = await response.json();

// Generate presentation
const presentation = await wallet.generatePresentation(authRequest);

// Submit to callback
await fetch(authRequest.response_uri, {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify(presentation),
});
```

### Custom Presentation Definitions

Create custom verification requests:

```typescript
const customRequest = verifier.createAuthorizationRequest({
  presentation_definition: {
    id: 'nationality-verification',
    name: 'Nationality Verification',
    purpose: 'Verify citizenship',
    input_descriptors: [
      {
        id: 'nationality-proof',
        constraints: {
          fields: [
            {
              path: ['$.credentialSubject.nationality'],
              filter: {
                type: 'string',
                const: 'US',
              },
            },
          ],
        },
      },
    ],
  },
});
```

---

## Mobile SDK Integration {#mobile-sdk-path}

Native mobile wallet implementation for React Native and Expo.

### Installation

```bash
npm install @zk-id/mobile @zk-id/core
npm install @react-native-async-storage/async-storage
```

### Basic Setup (React Native)

```typescript
import AsyncStorage from '@react-native-async-storage/async-storage';
import { MobileWallet, MobileCredentialStore, SecureStorageAdapter } from '@zk-id/mobile';

// Create storage adapter
const storageAdapter: SecureStorageAdapter = {
  getItem: (key) => AsyncStorage.getItem(key),
  setItem: (key, value) => AsyncStorage.setItem(key, value),
  removeItem: (key) => AsyncStorage.removeItem(key),
  getAllKeys: () => AsyncStorage.getAllKeys(),
};

// Initialize wallet
const wallet = new MobileWallet({
  credentialStore: new MobileCredentialStore(storageAdapter),
  circuitPaths: {
    ageWasm: 'https://cdn.example.com/age.wasm',
    ageZkey: 'https://cdn.example.com/age.zkey',
  },
});
```

### Credential Management

```typescript
// Add credential from issuer
const credential = await fetchCredentialFromIssuer();
await wallet.addCredential(credential);

// List all credentials
const credentials = await wallet.listCredentials();

// Export for backup
const backup = await wallet.exportCredentials();
await saveToCloud(backup);

// Import from backup
const restored = await loadFromCloud();
await wallet.importCredentials(restored);
```

### Proof Generation

```typescript
// Generate age proof
const proofResponse = await wallet.generateAgeProof(
  null,  // Auto-select most recent credential
  18,    // Minimum age
  'challenge-nonce-from-verifier',
);

// Submit to verifier
await fetch('https://verifier.com/verify', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify(proofResponse),
});
```

### Deep Link Handling

```typescript
import { Linking } from 'react-native';
import { parseAuthorizationRequest, generatePresentation, submitPresentation } from '@zk-id/mobile';

// Listen for deep links
Linking.addEventListener('url', async (event) => {
  const url = event.url; // e.g., openid4vp://?presentation_definition=...

  // Parse authorization request
  const authRequest = parseAuthorizationRequest(url);

  // Generate presentation
  const presentation = await generatePresentation(authRequest, wallet);

  // Submit to verifier
  const httpAdapter = {
    post: (url, body, headers) =>
      fetch(url, { method: 'POST', headers, body: JSON.stringify(body) }),
    get: (url, headers) =>
      fetch(url, { headers }),
  };

  const result = await submitPresentation(
    authRequest.response_uri,
    presentation,
    httpAdapter,
  );

  console.log('Verification result:', result);
});
```

### QR Code Scanning

```typescript
import { Camera } from 'expo-camera';
import { parseAuthorizationRequest } from '@zk-id/mobile';

const handleBarCodeScanned = async ({ data }) => {
  if (data.startsWith('openid4vp://')) {
    const authRequest = parseAuthorizationRequest(data);
    // Handle authorization request...
  }
};

<Camera onBarCodeScanned={handleBarCodeScanned} />
```

### Expo SecureStore Example

```typescript
import * as SecureStore from 'expo-secure-store';

const expoStorageAdapter: SecureStorageAdapter = {
  getItem: (key) => SecureStore.getItemAsync(key),
  setItem: (key, value) => SecureStore.setItemAsync(key, value),
  removeItem: (key) => SecureStore.deleteItemAsync(key),
  getAllKeys: async () => {
    // Expo SecureStore doesn't support getAllKeys natively
    // Maintain a key index
    const index = await SecureStore.getItemAsync('zkid:key-index');
    return index ? JSON.parse(index) : [];
  },
};
```

---

## Configuration Options {#configuration}

### Circuit Paths

**CDN (Recommended for Production):**

```typescript
circuitPaths: {
  ageWasm: 'https://cdn.jsdelivr.net/npm/@zk-id/circuits/dist/age.wasm',
  ageZkey: 'https://cdn.jsdelivr.net/npm/@zk-id/circuits/dist/age.zkey',
  nationalityWasm: 'https://cdn.jsdelivr.net/npm/@zk-id/circuits/dist/nationality.wasm',
  nationalityZkey: 'https://cdn.jsdelivr.net/npm/@zk-id/circuits/dist/nationality.zkey',
}
```

**Self-Hosted:**

```typescript
circuitPaths: {
  ageWasm: 'https://your-cdn.com/circuits/age.wasm',
  ageZkey: 'https://your-cdn.com/circuits/age.zkey',
}
```

**Local Development:**

```typescript
circuitPaths: {
  ageWasm: '/circuits/age.wasm',
  ageZkey: '/circuits/age.zkey',
}
```

### Issuer Registry

**In-Memory (Development):**

```typescript
import { InMemoryIssuerRegistry } from '@zk-id/sdk';

const issuerRegistry = new InMemoryIssuerRegistry([
  { id: 'issuer-1', publicKey: 'key1', name: 'Test Issuer' },
]);
```

**Database-Backed (Production):**

```typescript
import { IssuerRegistry } from '@zk-id/sdk';

class PostgresIssuerRegistry implements IssuerRegistry {
  async getIssuer(id: string) {
    return await db.query('SELECT * FROM issuers WHERE id = $1', [id]);
  }

  async getAllIssuers() {
    return await db.query('SELECT * FROM issuers');
  }
}
```

### Credential Storage

**Browser (IndexedDB):**

```typescript
import { IndexedDBCredentialStore } from '@zk-id/sdk';

const store = new IndexedDBCredentialStore();
```

**Mobile (Secure Storage):**

```typescript
import { MobileCredentialStore } from '@zk-id/mobile';
import AsyncStorage from '@react-native-async-storage/async-storage';

const store = new MobileCredentialStore({
  getItem: (key) => AsyncStorage.getItem(key),
  setItem: (key, value) => AsyncStorage.setItem(key, value),
  removeItem: (key) => AsyncStorage.removeItem(key),
  getAllKeys: () => AsyncStorage.getAllKeys(),
});
```

**Server (In-Memory for Testing):**

```typescript
import { InMemoryCredentialStore } from '@zk-id/sdk';

const store = new InMemoryCredentialStore();
```

---

## Troubleshooting {#troubleshooting}

### Common Issues

#### Proof Generation Takes Too Long

**Problem:** First proof takes 45-60 seconds.

**Solution:**
- This is expected for the initial circuit load (~5MB WASM + zkey)
- Subsequent proofs are faster (~10-15 seconds)
- Consider adding a loading indicator
- Roadmap: Circuit caching and proof reuse (Q2 2026)

```typescript
// Show loading indicator
setLoading(true);
setLoadingMessage('Loading verification circuit... (~45 seconds)');

const proof = await wallet.generateAgeProof(null, 18, nonce);

setLoading(false);
```

#### CORS Errors

**Problem:** `Access-Control-Allow-Origin` errors when calling verifier.

**Solution:** Add CORS headers to your verifier:

```typescript
import cors from 'cors';

app.use(cors({
  origin: ['https://your-frontend.com', 'http://localhost:3000'],
  credentials: true,
}));
```

#### Circuit Files Not Loading

**Problem:** 404 errors for `.wasm` or `.zkey` files.

**Solution:**
1. Verify circuit paths are correct
2. Check CDN availability
3. Serve files with correct MIME types:

```typescript
// Express
app.use('/circuits', express.static('circuits', {
  setHeaders: (res, path) => {
    if (path.endsWith('.wasm')) {
      res.setHeader('Content-Type', 'application/wasm');
    }
  },
}));
```

#### Verification Fails with "Invalid Signature"

**Problem:** Proof verification returns "Invalid signature" error.

**Solution:**
1. Ensure issuer public key is in the registry
2. Verify credential hasn't expired
3. Check that proof timestamp is recent
4. Confirm circuit files match (same trusted setup)

```typescript
// Debug issuer registry
const issuer = await issuerRegistry.getIssuer(credential.issuerPublicKey);
console.log('Issuer found:', issuer);
```

#### Mobile Deep Links Not Working

**Problem:** `openid4vp://` URLs don't trigger the app.

**Solution:** Configure deep link handling in your app:

**iOS (Info.plist):**

```xml
<key>CFBundleURLTypes</key>
<array>
  <dict>
    <key>CFBundleURLSchemes</key>
    <array>
      <string>openid4vp</string>
    </array>
  </dict>
</array>
```

**Android (AndroidManifest.xml):**

```xml
<intent-filter>
  <action android:name="android.intent.action.VIEW" />
  <category android:name="android.intent.category.DEFAULT" />
  <category android:name="android.intent.category.BROWSABLE" />
  <data android:scheme="openid4vp" />
</intent-filter>
```

#### Storage Adapter Errors

**Problem:** `SecureStorageAdapter` methods throwing errors.

**Solution:**
- Ensure all 4 methods are implemented: `getItem`, `setItem`, `removeItem`, `getAllKeys`
- Handle null returns correctly
- Test with mock adapter first:

```typescript
const mockAdapter = {
  getItem: async (key) => mockStorage.get(key) ?? null,
  setItem: async (key, value) => { mockStorage.set(key, value); },
  removeItem: async (key) => { mockStorage.delete(key); },
  getAllKeys: async () => Array.from(mockStorage.keys()),
};
```

### Performance Optimization

#### Cache Circuit Files

```typescript
// Service Worker (browser)
self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open('zk-circuits').then((cache) => {
      return cache.addAll([
        '/circuits/age.wasm',
        '/circuits/age.zkey',
      ]);
    }),
  );
});
```

#### Preload Circuits

```html
<!-- HTML head -->
<link rel="preload" href="/circuits/age.wasm" as="fetch" crossorigin>
<link rel="preload" href="/circuits/age.zkey" as="fetch" crossorigin>
```

#### Lazy Load Wallet

```typescript
// Only load wallet when needed
const walletPromise = import('@zk-id/sdk').then((module) =>
  new module.OpenID4VPWallet(config)
);

button.addEventListener('click', async () => {
  const wallet = await walletPromise;
  // Use wallet...
});
```

### Security Best Practices

1. **Always use HTTPS** in production
2. **Validate nonces** on the server side
3. **Check proof timestamps** to prevent replay attacks
4. **Rate limit** verification endpoints
5. **Log verification attempts** for audit trails
6. **Keep issuer registry updated** with trusted issuers only
7. **Use secure storage** on mobile (Keychain/EncryptedSharedPreferences)
8. **Never log** user credentials or proofs

---

## Next Steps

- **Try the demos:**
  - [OpenID4VP Demo](https://github.com/star7js/zk-id/tree/main/examples/openid4vp-demo)
  - [Age-Gate Widget](https://github.com/star7js/zk-id/tree/main/examples/age-gate-widget)

- **Read the docs:**
  - [API Reference](/api-reference)
  - [Architecture](/docs/architecture)
  - [OpenID4VP Specification](/docs/openid4vp)

- **Join the community:**
  - [GitHub Discussions](https://github.com/star7js/zk-id/discussions)
  - [Report Issues](https://github.com/star7js/zk-id/issues)

- **Deploy to production:**
  - [Deployment Guide](/docs/deployment)
  - [Security Best Practices](/docs/security)

---

Need help? [Open an issue](https://github.com/star7js/zk-id/issues) or ask in [Discussions](https://github.com/star7js/zk-id/discussions).
