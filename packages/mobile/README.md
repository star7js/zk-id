## @zk-id/mobile

Zero-knowledge identity SDK for React Native, Expo, and mobile platforms.

### Key Features

- ✅ **No DOM dependencies** - Works in React Native, Expo, and vanilla Node.js
- ✅ **Pluggable storage** - Inject platform-specific secure storage (Keychain, EncryptedSharedPreferences)
- ✅ **OpenID4VP support** - Standards-compliant verifiable presentations
- ✅ **Deep link handling** - Parse `openid4vp://` URLs from QR codes
- ✅ **Credential management** - Add, remove, list, export, import credentials
- ✅ **Proof generation** - Age and nationality proofs (EdDSA + BBS+)
- 🚧 **Digital Credentials API** - Placeholder for future EUDI Wallet integration (Q3 2026)

### Installation

```bash
npm install @zk-id/mobile @zk-id/core
```

### Quick Start (React Native)

#### 1. Set up secure storage

```bash
npm install @react-native-async-storage/async-storage
# or
npm install expo-secure-store
```

#### 2. Create storage adapter

```typescript
import AsyncStorage from '@react-native-async-storage/async-storage';
import { SecureStorageAdapter } from '@zk-id/mobile';

const storageAdapter: SecureStorageAdapter = {
  getItem: (key) => AsyncStorage.getItem(key),
  setItem: (key, value) => AsyncStorage.setItem(key, value),
  removeItem: (key) => AsyncStorage.removeItem(key),
  getAllKeys: () => AsyncStorage.getAllKeys(),
};
```

#### 3. Initialize wallet

```typescript
import { MobileWallet, MobileCredentialStore } from '@zk-id/mobile';

const wallet = new MobileWallet({
  credentialStore: new MobileCredentialStore(storageAdapter),
  circuitPaths: {
    ageWasm: 'https://cdn.example.com/age.wasm',
    ageZkey: 'https://cdn.example.com/age.zkey',
  },
});
```

#### 4. Add a credential

```typescript
import { SignedCredential } from '@zk-id/core';

// Fetch from your issuer server
const response = await fetch('https://your-issuer.com/issue', {
  method: 'POST',
  body: JSON.stringify({ holderName: 'Alice', dateOfBirth: '1990-06-15' }),
});

const credential: SignedCredential = await response.json();

await wallet.addCredential(credential);
```

#### 5. Generate a proof

```typescript
const proofResponse = await wallet.generateAgeProof(
  null, // Auto-select most recent credential
  18,   // Minimum age
  'challenge-nonce-from-verifier',
);

// Submit to verifier
await fetch('https://your-verifier.com/verify', {
  method: 'POST',
  body: JSON.stringify(proofResponse),
});
```

### OpenID4VP Integration

Handle deep links from QR codes:

```typescript
import { parseAuthorizationRequest, generatePresentation, submitPresentation } from '@zk-id/mobile';
import { Linking } from 'react-native';

// Listen for deep links
Linking.addEventListener('url', async (event) => {
  const url = event.url; // e.g., openid4vp://?presentation_definition=...

  // Parse the authorization request
  const authRequest = parseAuthorizationRequest(url);

  // Generate presentation
  const presentation = await generatePresentation(authRequest, wallet);

  // Submit to verifier
  const httpAdapter = {
    post: (url, body, headers) => fetch(url, { method: 'POST', headers, body: JSON.stringify(body) }),
    get: (url, headers) => fetch(url, { headers }),
  };

  const result = await submitPresentation(authRequest.response_uri, presentation, httpAdapter);

  console.log('Verification result:', result);
});
```

### Expo Example

```typescript
import * as SecureStore from 'expo-secure-store';
import { MobileWallet, MobileCredentialStore, SecureStorageAdapter } from '@zk-id/mobile';

// Expo SecureStore adapter
const expoStorageAdapter: SecureStorageAdapter = {
  getItem: (key) => SecureStore.getItemAsync(key),
  setItem: (key, value) => SecureStore.setItemAsync(key, value),
  removeItem: (key) => SecureStore.deleteItemAsync(key),
  getAllKeys: async () => {
    // Expo SecureStore doesn't support getAllKeys
    // You'll need to maintain a key index
    const index = await SecureStore.getItemAsync('zkid:key-index');
    return index ? JSON.parse(index) : [];
  },
};

const wallet = new MobileWallet({
  credentialStore: new MobileCredentialStore(expoStorageAdapter),
  circuitPaths: {
    ageWasm: 'https://cdn.example.com/age.wasm',
    ageZkey: 'https://cdn.example.com/age.zkey',
  },
});
```

### Node.js Example (Testing)

```typescript
import { MobileWallet, InMemoryCredentialStore } from '@zk-id/mobile';

const wallet = new MobileWallet({
  credentialStore: new InMemoryCredentialStore(),
  circuitPaths: {
    ageWasm: './circuits/age.wasm',
    ageZkey: './circuits/age.zkey',
  },
});
```

### API Reference

#### `MobileWallet`

**Credential Management:**
- `addCredential(credential: SignedCredential): Promise<void>`
- `removeCredential(id: string): Promise<void>`
- `listCredentials(): Promise<SignedCredential[]>`
- `getCredential(id: string): Promise<SignedCredential | null>`
- `exportCredentials(): Promise<string>` - JSON export for backup
- `importCredentials(json: string): Promise<void>` - Restore from backup

**Proof Generation:**
- `generateAgeProof(credentialId, minAge, nonce): Promise<ProofResponse>`
- `generateNationalityProof(credentialId, nationality, nonce): Promise<ProofResponse>`
- `handleProofRequest(request: ProofRequest): Promise<ProofResponse>` - Auto-detect type

**BBS+ (Selective Disclosure):**
- `addBBSCredential(credential: SerializedBBSCredential): Promise<void>`
- `removeBBSCredential(id: string): Promise<void>`
- `listBBSCredentials(): Promise<SerializedBBSCredential[]>`
- `generateBBSProof(credentialId, disclosureFields, nonce): Promise<BBSProofResponse>`

#### `MobileCredentialStore`

```typescript
constructor(storage: SecureStorageAdapter)

get(id: string): Promise<SignedCredential | null>
getAll(): Promise<SignedCredential[]>
put(credential: SignedCredential): Promise<void>
delete(id: string): Promise<void>
clear(): Promise<void>
```

#### OpenID4VP Functions

```typescript
parseAuthorizationRequest(url: string): AuthorizationRequest
generatePresentation(authRequest, wallet): Promise<PresentationResponse>
submitPresentation(responseUri, presentation, httpAdapter): Promise<any>
buildDeepLink(authRequest): string
```

### Storage Adapters

#### AsyncStorage (React Native)

```typescript
import AsyncStorage from '@react-native-async-storage/async-storage';

const adapter: SecureStorageAdapter = {
  getItem: (key) => AsyncStorage.getItem(key),
  setItem: (key, value) => AsyncStorage.setItem(key, value),
  removeItem: (key) => AsyncStorage.removeItem(key),
  getAllKeys: () => AsyncStorage.getAllKeys(),
};
```

#### SecureStore (Expo)

```typescript
import * as SecureStore from 'expo-secure-store';

const adapter: SecureStorageAdapter = {
  getItem: (key) => SecureStore.getItemAsync(key),
  setItem: (key, value) => SecureStore.setItemAsync(key, value),
  removeItem: (key) => SecureStore.deleteItemAsync(key),
  getAllKeys: async () => {
    // Maintain a separate index of keys
    const index = await SecureStore.getItemAsync('zkid:key-index');
    return index ? JSON.parse(index) : [];
  },
};
```

#### Keychain (iOS - react-native-keychain)

```typescript
import * as Keychain from 'react-native-keychain';

const adapter: SecureStorageAdapter = {
  getItem: async (key) => {
    const result = await Keychain.getGenericPassword({ service: key });
    return result ? result.password : null;
  },
  setItem: async (key, value) => {
    await Keychain.setGenericPassword('zkid', value, { service: key });
  },
  removeItem: async (key) => {
    await Keychain.resetGenericPassword({ service: key });
  },
  getAllKeys: async () => {
    // Keychain doesn't support listing - maintain index
    const index = await adapter.getItem('zkid:key-index');
    return index ? JSON.parse(index) : [];
  },
};
```

### Comparison with @zk-id/sdk

| Feature | @zk-id/sdk | @zk-id/mobile |
|---------|------------|---------------|
| **Platform** | Browser (DOM) | React Native, Expo, Node.js |
| **Storage** | IndexedDB | Injected (Keychain, SecureStore) |
| **HTTP** | fetch (built-in) | Injected adapter |
| **OpenID4VP** | ✅ | ✅ |
| **BBS+** | ✅ | ✅ |
| **Deep Links** | ❌ | ✅ |
| **QR Scanning** | Via library | Via library |
| **Digital Credentials API** | Future | Future (Q3 2026) |

### Design Principles

1. **No DOM dependencies**: No `window`, `document`, `navigator`, `localStorage`, `IndexedDB`, or `fetch`
2. **Injected I/O**: All storage and HTTP via platform-specific adapters
3. **API compatibility**: Mirrors `@zk-id/sdk` API where possible
4. **Test-friendly**: In-memory stores for unit tests
5. **Type-safe**: Full TypeScript support

### Verification

```bash
# Ensure no DOM dependencies
grep -r "indexedDB\|window\|document\|navigator" packages/mobile/src/
# Should return zero hits
```

### Roadmap

- **Q1 2026**: React Native example app
- **Q2 2026**: EUDI Wallet integration research
- **Q3 2026**: Digital Credentials API implementation
- **Q4 2026**: Flutter SDK (Dart FFI bindings)

### Examples

See `examples/mobile-wallet-rn/` for a complete React Native example.

### Support

- [Documentation](https://zk-id.io/docs)
- [GitHub Issues](https://github.com/star7js/zk-id/issues)
- [Discord](https://discord.gg/zk-id)

### License

Apache-2.0
