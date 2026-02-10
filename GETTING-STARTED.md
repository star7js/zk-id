# Getting Started with zk-id

This guide walks you through everything you need to know to integrate zk-id into your application, from initial setup to production deployment.

## Table of Contents

- [Prerequisites](#prerequisites)
- [Part 1: Initial Setup](#part-1-initial-setup)
- [Part 2: Running the Demo](#part-2-running-the-demo)
- [Part 3: Setting Up as an Issuer](#part-3-setting-up-as-an-issuer)
- [Part 4: Setting Up as a User (Wallet)](#part-4-setting-up-as-a-user-wallet)
- [Part 5: Setting Up as a Verifier (Website)](#part-5-setting-up-as-a-verifier-website)
- [Part 6: Production Deployment](#part-6-production-deployment)
- [Troubleshooting](#troubleshooting)

## Prerequisites

Before you begin, ensure you have:

- **Node.js 18+** — Check with `node --version`
- **npm 8+** — Check with `npm --version`
- **Git** — For cloning the repository

Optional for building circuits from source:
- **circom 0.5.46+** — Circuit compiler ([installation guide](https://docs.circom.io/getting-started/installation/))
- **Rust toolchain** — Required by circom ([rustup.rs](https://rustup.rs/))

## Part 1: Initial Setup

### 1.1 Clone the Repository

```bash
git clone https://github.com/star7js/zk-id.git
cd zk-id
```

### 1.2 Install Dependencies

From the repository root:

```bash
npm install
```

This installs dependencies for all packages in the monorepo.

### 1.3 Compile Circuits (First Time Only)

The circuits package ships with pre-compiled artifacts, but if you need to rebuild:

```bash
# Compile .circom files → .wasm + .r1cs
npm run compile:circuits

# Run trusted setup (generates .zkey + verification_key.json)
npm run --workspace=@zk-id/circuits setup

# Verify artifact hashes (optional, may show platform differences)
npm run --workspace=@zk-id/circuits verify-hashes
```

**Note:** The setup phase downloads Powers of Tau files (~155 MB) and takes 1-2 minutes.

### 1.4 Build All Packages

```bash
npm run build
```

This compiles TypeScript for all packages.

### 1.5 Run Tests

```bash
npm test
```

You should see all tests passing (circuits, contracts, core, issuer, sdk, redis).

## Part 2: Running the Demo

The fastest way to see zk-id in action is to run the example web application.

### 2.1 Start the Demo Server

From the repository root:

```bash
npm start --workspace=@zk-id/example-web-app
```

Or from `examples/web-app/`:

```bash
cd examples/web-app
npm start
```

### 2.2 Open the Demo

Navigate to `http://localhost:3000` in your browser.

### 2.3 Try the Workflow

1. **Issue a Credential**
   - Enter birth year (e.g., 1995) and nationality (e.g., 840 for USA)
   - Click "Issue Credential"
   - The credential is stored in browser memory

2. **Verify Age**
   - Select minimum age (e.g., 18)
   - Click "Verify Age"
   - Watch the browser generate a ZK proof locally (~5 seconds)
   - Server verifies the proof ✓

3. **Test Revocation**
   - Click "Revoke Credential"
   - Try to verify again → should fail (credential revoked)

See the [example app README](./examples/web-app/README.md) for more details.

## Part 3: Setting Up as an Issuer

Issuers are trusted entities (governments, banks, employers) that verify user identity and issue signed credentials.

### 3.1 Choose Your Signature Scheme

| Scheme | Best For | Verification | Circuit Size |
|--------|----------|--------------|--------------|
| **Ed25519** | Most cases | Off-chain (fast) | N/A |
| **BabyJub EdDSA** | Trustless on-chain | In-circuit (~15s) | ~20k constraints |
| **BBS+** | Selective disclosure | Off-chain (fast) | N/A |

For most use cases, start with **Ed25519**.

### 3.2 Basic Issuer Setup (Ed25519)

```typescript
import { createTestIssuer } from '@zk-id/issuer';

// For development/testing only
const issuer = createTestIssuer({ name: 'Demo Issuer' });

// Issue a credential after verifying user identity
const credential = await issuer.issueCredential(
  1995, // birth year from verified ID
  840,  // ISO 3166-1 numeric: 840 = USA
  'user-123' // optional user identifier for audit
);

console.log('Issued credential:', credential.id);
```

### 3.3 Production Issuer Setup

**NEVER use `createTestIssuer()` in production** — it generates ephemeral keys.

Use file-based or envelope-encrypted key management:

```typescript
import { FileKeyManager, ManagedCredentialIssuer } from '@zk-id/issuer';
import { ConsoleAuditLogger } from '@zk-id/core';

// Load keys from PEM files
const keyManager = await FileKeyManager.fromPemFiles(
  './config/issuer-private-key.pem',
  './config/issuer-public-key.pem'
);

const issuer = new ManagedCredentialIssuer(
  'Production Issuer Name',
  keyManager,
  new ConsoleAuditLogger() // Replace with real logging in production
);

// Issue credentials
const credential = await issuer.issueCredential(birthYear, nationality, userId);
```

### 3.4 Key Generation

Generate production Ed25519 keys:

```bash
# Generate private key
openssl genpkey -algorithm ED25519 -out issuer-private-key.pem

# Extract public key
openssl pkey -in issuer-private-key.pem -pubout -out issuer-public-key.pem
```

**Security:** Store private keys in HSM, AWS KMS, or Azure Key Vault for production.

### 3.5 Enable Revocation

```typescript
import { InMemoryRevocationStore } from '@zk-id/core';
// For production, use RedisRevocationStore from @zk-id/redis

const revocationStore = new InMemoryRevocationStore();
issuer.setRevocationStore(revocationStore);

// Revoke a credential
await issuer.revokeCredential(credential.credential.commitment);
```

See the [issuer package README](./packages/issuer/README.md) for more details.

## Part 4: Setting Up as a User (Wallet)

Users store their credentials in a wallet and generate proofs locally.

### 4.1 Browser Wallet Setup

```typescript
import { IndexedDBCredentialStore } from '@zk-id/sdk';

// Create a persistent credential store
const store = new IndexedDBCredentialStore();

// Store a credential
await store.saveCredential(credential);

// List all credentials
const credentials = await store.listCredentials();

// Retrieve a specific credential
const cred = await store.getCredential(credentialId);
```

### 4.2 Generate a Proof

```typescript
import { generateAgeProofAuto } from '@zk-id/core';

// Generate age proof (client-side, in browser)
const proof = await generateAgeProofAuto(
  credential,
  18, // minAge
  'nonce-from-server',
  Date.now()
);

// proof.proof contains the ZK proof (~192 bytes)
// proof.publicSignals contains public values (currentYear, minAge, etc.)
```

### 4.3 Proof Generation Performance

Typical browser performance:

- **First proof**: 5-7 seconds (downloads ~5-10 MB of circuit artifacts)
- **Subsequent proofs**: 3-5 seconds (artifacts cached)
- **WASM download**: Cached by browser for 1 hour+

Use Web Workers to avoid blocking the UI during proof generation.

### 4.4 Backup and Recovery

```typescript
// Export credentials as encrypted JSON
const backup = await store.exportCredentials('user-password');

// Import from backup
await store.importCredentials(backup, 'user-password');
```

See the [SDK package README](./packages/sdk/README.md) for more details.

## Part 5: Setting Up as a Verifier (Website)

Websites verify proofs submitted by users without learning private data.

### 5.1 Server-Side Setup

```typescript
import { ZkIdServer } from '@zk-id/sdk';
import { InMemoryNonceStore, InMemoryIssuerRegistry } from '@zk-id/sdk';
import { readFileSync } from 'fs';

// Load issuer's public key
const issuerPublicKey = readFileSync('./config/issuer-public-key.pem');

// Create issuer registry
const issuerRegistry = new InMemoryIssuerRegistry();
await issuerRegistry.registerIssuer({
  issuer: 'Production Issuer Name',
  publicKey: issuerPublicKey,
  status: 'active',
});

// Create verification server
const server = new ZkIdServer({
  verificationKeyPath: './circuits/age-verify-verification-key.json',
  nonceStore: new InMemoryNonceStore({ ttlSeconds: 300 }),
  issuerRegistry: issuerRegistry,
  requiredPolicy: {
    maxProofAgeMs: 60000, // Proofs expire after 1 minute
  },
  verboseErrors: false, // Don't leak circuit details to clients
});
```

### 5.2 Express Integration

```typescript
import express from 'express';

const app = express();
app.use(express.json());

// Challenge endpoint (optional but recommended)
app.get('/api/challenge', async (req, res) => {
  const challenge = await server.createChallenge();
  res.json(challenge);
});

// Verification endpoint
app.post('/api/verify-age', async (req, res) => {
  try {
    const result = await server.verifyAge(req.body, req.ip);

    if (result.success) {
      // Age verified! Grant access
      res.json({ verified: true });
    } else {
      res.status(400).json({ verified: false, error: result.error });
    }
  } catch (error) {
    res.status(500).json({ verified: false, error: 'Verification failed' });
  }
});

app.listen(3000, () => {
  console.log('Verification server running on http://localhost:3000');
});
```

### 5.3 Client-Side Integration

```typescript
import { ZkIdClient } from '@zk-id/sdk';

const client = new ZkIdClient({
  verificationEndpoint: 'https://yoursite.com/api/verify-age',
});

// Request age verification
try {
  const result = await client.verifyAge(credential, 18);

  if (result.success) {
    console.log('Age verified! User is 18+');
    // Grant access to age-restricted content
  } else {
    console.error('Verification failed:', result.error);
  }
} catch (error) {
  console.error('Network error:', error);
}
```

### 5.4 Revocation Checks

To support revocable credentials:

```typescript
import { PostgresValidCredentialTree } from '@zk-id/sdk';
import { Client } from 'pg';

const pg = new Client({ connectionString: process.env.DATABASE_URL });
await pg.connect();

const validCredentialTree = new PostgresValidCredentialTree(pg, {
  schema: 'zkid',
  depth: 10,
});

const server = new ZkIdServer({
  verificationKeyPath: './circuits/age-verify-revocable-verification-key.json',
  validCredentialTree: validCredentialTree,
  // ... other config
});

// Expose revocation root for clients
app.get('/api/revocation/root', async (req, res) => {
  const rootInfo = await server.getRevocationRootInfo();
  res.json(rootInfo);
});
```

See the [SDK package README](./packages/sdk/README.md) for more details.

## Part 6: Production Deployment

### 6.1 Production Checklist

Security:
- [ ] Use production Powers of Tau ceremony (not dev/test)
- [ ] Store issuer keys in HSM, AWS KMS, or Azure Key Vault
- [ ] Enable HTTPS/TLS for all endpoints
- [ ] Implement proper authentication for credential issuance
- [ ] Audit circuits with ZK security experts
- [ ] Enable rate limiting with Redis-backed limiter
- [ ] Implement comprehensive audit logging

Infrastructure:
- [ ] Replace in-memory stores with Redis or Postgres
- [ ] Set up monitoring and alerting
- [ ] Configure CDN for circuit artifact delivery
- [ ] Set up database backups
- [ ] Implement graceful shutdown for nonce store cleanup
- [ ] Configure CORS properly for cross-origin verification

Performance:
- [ ] Enable circuit artifact caching (browser + CDN)
- [ ] Use Web Workers for client-side proof generation
- [ ] Implement batch verification for high-throughput scenarios
- [ ] Monitor verification latency and set SLOs

### 6.2 Redis Setup (Recommended)

```typescript
import Redis from 'ioredis';
import {
  RedisNonceStore,
  RedisIssuerRegistry,
  RedisRevocationStore,
  RedisRateLimiter,
} from '@zk-id/redis';

const redis = new Redis(process.env.REDIS_URL);

const server = new ZkIdServer({
  verificationKeyPath: './verification_key.json',
  nonceStore: new RedisNonceStore(redis, { ttlSeconds: 300 }),
  issuerRegistry: new RedisIssuerRegistry(redis),
  revocationStore: new RedisRevocationStore(redis),
  rateLimiter: new RedisRateLimiter(redis, {
    limit: 100,
    windowMs: 60000,
  }),
});
```

### 6.3 Postgres Setup

```sql
-- Create schema
CREATE SCHEMA IF NOT EXISTS zkid;

-- Valid credential tree (managed by PostgresValidCredentialTree)
-- Tables are auto-created by the SDK
```

```typescript
import { PostgresValidCredentialTree } from '@zk-id/sdk';
import { Client } from 'pg';

const pg = new Client({
  host: process.env.PG_HOST,
  port: 5432,
  database: process.env.PG_DATABASE,
  user: process.env.PG_USER,
  password: process.env.PG_PASSWORD,
  ssl: { rejectUnauthorized: false }, // Configure properly for production
});

await pg.connect();

const validCredentialTree = new PostgresValidCredentialTree(pg, {
  schema: 'zkid',
  depth: 10,
});

// Use in ZkIdServer
const server = new ZkIdServer({
  validCredentialTree: validCredentialTree,
  // ... other config
});
```

### 6.4 Monitoring and Observability

```typescript
import { ConsoleAuditLogger } from '@zk-id/core';

// Implement custom audit logger
class ProductionAuditLogger extends ConsoleAuditLogger {
  async log(event: AuditEvent): Promise<void> {
    // Send to your logging service (DataDog, Splunk, etc.)
    await yourLoggingService.log(event);
  }
}

const server = new ZkIdServer({
  auditLogger: new ProductionAuditLogger(),
  // ... other config
});

// Listen for verification events
server.onVerification((event) => {
  // Send metrics to Prometheus/CloudWatch/etc.
  metrics.recordVerification({
    claimType: event.claimType,
    verified: event.verified,
    duration: event.verificationTimeMs,
  });
});
```

### 6.5 Environment Variables

Example `.env` file:

```bash
# Server
NODE_ENV=production
PORT=3000
LOG_LEVEL=info

# Redis
REDIS_URL=redis://localhost:6379

# Postgres
DATABASE_URL=postgresql://user:password@localhost:5432/zkid

# Keys
ISSUER_PRIVATE_KEY_PATH=/secrets/issuer-private-key.pem
ISSUER_PUBLIC_KEY_PATH=/config/issuer-public-key.pem

# Verification
VERIFICATION_KEY_PATH=/config/age-verify-verification-key.json
NATIONALITY_VERIFICATION_KEY_PATH=/config/nationality-verify-verification-key.json

# Security
REQUIRE_SIGNED_CREDENTIALS=true
MAX_PROOF_AGE_MS=60000
NONCE_TTL_SECONDS=300
RATE_LIMIT_WINDOW_MS=60000
RATE_LIMIT_MAX_REQUESTS=100

# CORS
ALLOWED_ORIGINS=https://yoursite.com,https://www.yoursite.com
```

### 6.6 Docker Deployment

Example `Dockerfile`:

```dockerfile
FROM node:18-alpine

WORKDIR /app

# Copy package files
COPY package*.json ./
COPY packages/ ./packages/

# Install dependencies
RUN npm ci --production

# Build packages
RUN npm run build

# Copy configuration
COPY config/ ./config/

# Expose port
EXPOSE 3000

# Health check
HEALTHCHECK --interval=30s --timeout=3s \
  CMD node -e "require('http').get('http://localhost:3000/api/health', (r) => process.exit(r.statusCode === 200 ? 0 : 1))"

# Start server
CMD ["node", "examples/web-app/dist/server.js"]
```

### 6.7 Kubernetes Deployment

See [docs/DEPLOYMENT.md](./docs/DEPLOYMENT.md) for Kubernetes manifests and Helm charts.

## Troubleshooting

### Circuit Compilation Fails

**Error:** `circom: command not found`

**Solution:** Install circom following the [official guide](https://docs.circom.io/getting-started/installation/).

### Proof Generation Fails in Browser

**Error:** `Cannot find module '@zk-id/circuits/build/age-verify.wasm'`

**Solution:** Ensure circuit artifacts are compiled:
```bash
npm run compile:circuits
npm run --workspace=@zk-id/circuits setup
```

### Verification Fails with "Invalid proof"

**Causes:**
1. Circuit artifacts mismatch (recompile circuits on all environments)
2. Wrong verification key (ensure same version)
3. Clock skew (timestamp validation failed)
4. Nonce expired or reused

**Debug:**
```typescript
const server = new ZkIdServer({
  verboseErrors: true, // Enable detailed errors
  // ... other config
});
```

### Performance Issues

**Slow proof generation:**
- Use Web Workers for non-blocking proof generation
- Serve circuit artifacts from CDN with long cache headers
- Consider native mobile apps (faster than browser)

**Slow verification:**
- Enable batch verification for multiple proofs
- Check database query performance (add indexes)
- Monitor circuit artifact download times

### Rate Limiting

**Error:** `Rate limit exceeded`

**Solution:**
- Check `RedisRateLimiter` configuration
- Implement proper user authentication (don't rely on IP)
- Adjust limits based on your traffic patterns

## Next Steps

- Read the [Architecture Documentation](./docs/ARCHITECTURE.md)
- Explore the [Protocol Specification](./docs/PROTOCOL.md)
- Review the [Threat Model](./docs/THREAT-MODEL.md)
- Check the [Roadmap](./docs/ROADMAP.md) for upcoming features
- Join the community and contribute!

## Package Documentation

- [@zk-id/core](./packages/core/README.md) — Core cryptographic library
- [@zk-id/circuits](./packages/circuits/README.md) — Zero-knowledge circuits
- [@zk-id/sdk](./packages/sdk/README.md) — Client and server SDK
- [@zk-id/issuer](./packages/issuer/README.md) — Credential issuance
- [@zk-id/redis](./packages/redis/README.md) — Redis storage backends
- [@zk-id/contracts](./packages/contracts/README.md) — Solidity verifiers

## Getting Help

- **Issues:** [GitHub Issues](https://github.com/star7js/zk-id/issues)
- **Documentation:** [docs/](./docs/)
- **Example App:** [examples/web-app/](./examples/web-app/)

## License

Apache-2.0 - see [LICENSE](./LICENSE) for details.
