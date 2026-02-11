---
title: 'Deployment Guide'
description: '**Version:** 1.0.0'
category: 'Operations'
order: 30
---

# Deployment Guide

**Version:** 1.0.0
**Date:** 2026-02-09
**Target:** Production deployments

---

## 1. Prerequisites

### 1.1 System Requirements

- **Node.js:** >= 20.0.0 (LTS recommended: 20.11.0+)
- **npm:** >= 9.0.0
- **Operating System:** Linux (Ubuntu 22.04+, Amazon Linux 2023), macOS 13+, Windows Server 2022+
- **Memory:** Minimum 4GB RAM (8GB+ recommended for proof generation)
- **CPU:** Multi-core recommended (proof generation is CPU-intensive)

### 1.2 Optional Build Requirements

**Only needed for circuit compilation from source** (most deployments use pre-compiled artifacts):

- **circom:** 0.5.46 (exact version)
  ```bash
  npm install -g circom@0.5.46
  ```
- **snarkjs:** 0.7.6 (exact version, installed as dependency)

**Note:** Circuit compilation requires ~16GB RAM and can take 10-30 minutes. Use pre-compiled artifacts from releases for production.

---

## 2. Package Overview

zk-id is organized as a monorepo with role-specific packages:

### 2.1 For Issuers (Credential Creation)

```bash
npm install @zk-id/issuer @zk-id/core
```

**Packages:**

- `@zk-id/issuer` — Credential issuance, signing, key management
- `@zk-id/core` — Shared types, credential schema, Poseidon hashing

**Use case:** Government agencies, identity providers issuing signed credentials

### 2.2 For Verifiers (Proof Validation)

```bash
npm install @zk-id/sdk @zk-id/core
```

**Packages:**

- `@zk-id/sdk` — Server-side verification, nonce/revocation stores
- `@zk-id/core` — Shared types, verification logic

**Optional:**

- `@zk-id/redis` — Redis-backed nonce and revocation stores (recommended for production)

**Use case:** Websites, APIs validating age/nationality proofs

### 2.3 For Holders (Proof Generation)

```bash
npm install @zk-id/core
```

**Packages:**

- `@zk-id/core` — Client-side proof generation (browser or Node.js)

**Use case:** Frontend applications generating proofs in users' browsers

---

## 3. Configuration

### 3.1 ZkIdServer Configuration

The `ZkIdServerConfig` interface controls all verification behavior:

```typescript
import { ZkIdServer } from '@zk-id/sdk';
import { RedisNonceStore } from '@zk-id/redis';
import Redis from 'ioredis';

const redis = new Redis(process.env.REDIS_URL);

const server = new ZkIdServer({
  // Verification keys (required)
  verificationKeyPath: './keys/age_verification_key.json',
  nationalityVerificationKeyPath: './keys/nationality_verification_key.json',
  signedVerificationKeyPath: './keys/age_signed_verification_key.json',
  revocableVerificationKeyPath: './keys/age_revocable_verification_key.json',

  // Replay protection (required for production)
  nonceStore: new RedisNonceStore(redis),
  maxRequestAgeMs: 5 * 60 * 1000, // 5 minutes
  maxFutureSkewMs: 60 * 1000, // 1 minute clock skew tolerance

  // Rate limiting (required for production)
  rateLimiter: new CustomRateLimiter(), // See section 5.3

  // Issuer trust (required if using signed credentials)
  requireSignedCredentials: true,
  issuerRegistry: new InMemoryIssuerRegistry([
    {
      issuer: 'gov.example',
      publicKey: loadPublicKey('./keys/issuer_public_key.pem'),
      status: 'active',
      validFrom: '2026-01-01T00:00:00Z',
      validTo: '2027-01-01T00:00:00Z',
      rotationGracePeriodMs: 7 * 24 * 60 * 60 * 1000, // 7 days
    },
  ]),

  // Server-side policy enforcement
  requiredPolicy: {
    minAge: 18, // Enforce minimum age
    // nationality: 840, // Enforce specific nationality (ISO 3166-1 numeric)
  },

  // Security settings
  verboseErrors: false, // CRITICAL: Never enable in production
  validatePayloads: true, // Strict JSON validation
  protocolVersionPolicy: 'warn', // 'strict' for breaking changes

  // Audit logging
  auditLogger: new CustomAuditLogger(), // See section 5.4
});
```

### 3.2 Environment Variables

**Recommended `.env` structure:**

```bash
# Node.js environment
NODE_ENV=production
PORT=3000

# Redis (nonce store, revocation cache)
REDIS_URL=redis://localhost:6379
REDIS_TLS=true # Use TLS in production

# Verification keys (paths)
VERIFICATION_KEY_AGE=./keys/age_verification_key.json
VERIFICATION_KEY_NATIONALITY=./keys/nationality_verification_key.json
VERIFICATION_KEY_AGE_SIGNED=./keys/age_signed_verification_key.json
VERIFICATION_KEY_AGE_REVOCABLE=./keys/age_revocable_verification_key.json

# Issuer keys (paths to PEM files)
ISSUER_PUBLIC_KEY=./keys/issuer_public_key.pem

# Security settings
MAX_REQUEST_AGE_MS=300000 # 5 minutes
MAX_FUTURE_SKEW_MS=60000 # 1 minute
VERBOSE_ERRORS=false # NEVER set to true in production

# Rate limiting
RATE_LIMIT_WINDOW_MS=60000 # 1 minute
RATE_LIMIT_MAX_REQUESTS=100 # 100 requests per minute

# Protocol version enforcement
PROTOCOL_VERSION_POLICY=warn # 'strict' | 'warn' | 'off'
```

---

## 4. Key Management

### 4.1 Generating Issuer Keys

**Ed25519 key pair (for off-chain credential signing):**

```bash
# Generate private key
openssl genpkey -algorithm ED25519 -out issuer_private_key.pem

# Extract public key
openssl pkey -in issuer_private_key.pem -pubout -out issuer_public_key.pem
```

**BabyJubJub key pair (for in-circuit EdDSA verification):**

```typescript
import { CircuitCredentialIssuer } from '@zk-id/issuer';

const issuer = new CircuitCredentialIssuer('gov.example');
const { privateKey, publicKeyBits } = issuer.exportKeys();

// Store privateKey securely (HSM/KMS recommended)
// Distribute publicKeyBits to verifiers
```

### 4.2 Key Storage Options

#### Option 1: FileKeyManager (Development Only)

```typescript
import { FileKeyManager } from '@zk-id/issuer';

const keyManager = new FileKeyManager('./keys');
// Keys stored as plaintext files — NOT PRODUCTION SAFE
```

#### Option 2: EnvelopeKeyManager (Intermediate)

```typescript
import { EnvelopeKeyManager } from '@zk-id/issuer';

const keyManager = new EnvelopeKeyManager(
  process.env.MASTER_KEY, // AES-256-GCM key (store in environment)
  './encrypted-keys',
);
// Keys encrypted at rest with AES-256-GCM
```

#### Option 3: HSM/KMS Integration (Production Recommended)

```typescript
import { KMSKeyManager } from './custom/kms-key-manager';
import AWS from 'aws-sdk';

const kms = new AWS.KMS({ region: 'us-east-1' });
const keyManager = new KMSKeyManager(kms, 'arn:aws:kms:...');
// Keys never leave HSM
```

**Supported HSM/KMS:**

- AWS KMS (recommended for AWS deployments)
- Azure Key Vault (recommended for Azure deployments)
- HashiCorp Vault (cross-cloud)
- Google Cloud KMS
- Hardware HSM (Thales Luna, Gemalto SafeNet)

### 4.3 Key Rotation

**Rotation procedure:**

1. Generate new issuer key pair
2. Add new key to `IssuerRegistry` with `validFrom` = future date
3. Set `rotationGracePeriodMs` on old key (e.g., 7 days)
4. Wait for grace period to elapse
5. Set old key `status: 'revoked'`

**Example:**

```typescript
registry.upsert({
  issuer: 'gov.example',
  publicKey: newPublicKey,
  status: 'active',
  validFrom: '2026-03-01T00:00:00Z',
  validTo: '2027-03-01T00:00:00Z',
});

// Old key with grace period
registry.upsert({
  issuer: 'gov.example',
  publicKey: oldPublicKey,
  status: 'active',
  validFrom: '2025-03-01T00:00:00Z',
  validTo: '2026-03-01T00:00:00Z',
  rotationGracePeriodMs: 7 * 24 * 60 * 60 * 1000, // 7 days
});
```

---

## 5. Verification Key Distribution

### 5.1 Obtaining Verification Keys

**Option 1: Download from release artifacts** (recommended)

```bash
# Download from GitHub releases
wget https://github.com/your-org/zk-id/releases/download/v1.0.0/verification-keys.tar.gz
tar -xzf verification-keys.tar.gz -C ./keys
```

**Option 2: Build from source** (for custom circuits)

```bash
cd packages/circuits
npm run compile
# Verification keys generated in ./build/verification_keys/
```

### 5.2 Verifying Key Integrity

**Always verify SHA-256 hashes:**

```bash
npm run verify-circuits
# Compares against docs/circuit-hashes.json
```

**Manual verification:**

```bash
sha256sum keys/age_verification_key.json
# Compare with docs/circuit-hashes.json
```

---

## 6. Production Checklist

### 6.1 Mandatory Security Controls

- [ ] **TLS 1.3+** enabled on all API endpoints (reverse proxy recommended)
- [ ] **Persistent nonce store** (Redis with TTL, not `InMemoryNonceStore`)
- [ ] **Authenticated rate limiter** (token bucket per session, not IP-based)
- [ ] **verboseErrors: false** (default; never enable in production)
- [ ] **maxRequestAgeMs** configured (recommended: 300000 = 5 minutes)
- [ ] **maxFutureSkewMs** configured (recommended: 60000 = 1 minute)
- [ ] **Audit logging** with tamper-evident storage (S3 write-only, Elasticsearch WORM)
- [ ] **Circuit artifact hashes verified** (run `npm run verify-circuits` in CI)

### 6.2 Recommended Security Controls

- [ ] **HSM/KMS for issuer keys** (AWS KMS, Azure Key Vault, Vault)
- [ ] **Strict protocol version enforcement** (`protocolVersionPolicy: 'strict'`)
- [ ] **Revocation root staleness checks** (`maxRevocationRootAgeMs: 300000`)
- [ ] **NTP clock synchronization** (chrony, ntpd)
- [ ] **Monitoring and alerting** (proof verification failures, rate limit hits)
- [ ] **Regular key rotation** (annual minimum, quarterly recommended)

### 6.3 Infrastructure Requirements

- [ ] **Reverse proxy** (nginx, HAProxy, AWS ALB) for TLS termination
- [ ] **Load balancer** for horizontal scaling (stateless verifiers)
- [ ] **Shared Redis cluster** for nonce store (Redis Cluster or ElastiCache)
- [ ] **Monitoring** (Prometheus, Datadog, CloudWatch)
- [ ] **Log aggregation** (Elasticsearch, Splunk, CloudWatch Logs)

---

## 7. Infrastructure Recommendations

### 7.1 Reverse Proxy Configuration

**nginx example:**

```nginx
upstream zk-id-verifier {
  server 127.0.0.1:3000;
  server 127.0.0.1:3001;
  keepalive 32;
}

server {
  listen 443 ssl http2;
  server_name verify.example.com;

  ssl_certificate /etc/letsencrypt/live/verify.example.com/fullchain.pem;
  ssl_certificate_key /etc/letsencrypt/live/verify.example.com/privkey.pem;
  ssl_protocols TLSv1.3;
  ssl_ciphers HIGH:!aNULL:!MD5;

  # Rate limiting (per IP, fallback)
  limit_req_zone $binary_remote_addr zone=verifier:10m rate=10r/s;
  limit_req zone=verifier burst=20 nodelay;

  location /api/verify {
    proxy_pass http://zk-id-verifier;
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection 'upgrade';
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
  }
}
```

### 7.2 Redis Configuration

**Redis deployment options:**

1. **AWS ElastiCache** (managed, recommended for AWS)

   ```typescript
   const redis = new Redis({
     host: 'zk-id.abc123.cache.amazonaws.com',
     port: 6379,
     tls: { servername: 'zk-id.abc123.cache.amazonaws.com' },
   });
   ```

2. **Redis Cluster** (self-managed, high availability)

   ```bash
   # redis.conf
   cluster-enabled yes
   cluster-config-file nodes.conf
   cluster-node-timeout 5000
   appendonly yes
   ```

3. **Single Redis instance** (development only)
   ```bash
   redis-server --maxmemory 2gb --maxmemory-policy allkeys-lru
   ```

### 7.3 Rate Limiting Strategy

**Production rate limiter example (token bucket + Redis):**

```typescript
import { RateLimiter } from '@zk-id/sdk';
import Redis from 'ioredis';

class TokenBucketRateLimiter implements RateLimiter {
  constructor(
    private redis: Redis,
    private capacity: number = 100,
    private refillRate: number = 10, // tokens per second
  ) {}

  async allowRequest(sessionId: string): Promise<boolean> {
    const key = `rate:${sessionId}`;
    const now = Date.now();

    // Atomic token bucket check using Lua script
    const allowed = await this.redis.eval(
      `
      local key = KEYS[1]
      local capacity = tonumber(ARGV[1])
      local refillRate = tonumber(ARGV[2])
      local now = tonumber(ARGV[3])

      local bucket = redis.call('HMGET', key, 'tokens', 'lastRefill')
      local tokens = tonumber(bucket[1]) or capacity
      local lastRefill = tonumber(bucket[2]) or now

      local elapsed = (now - lastRefill) / 1000
      tokens = math.min(capacity, tokens + elapsed * refillRate)

      if tokens >= 1 then
        tokens = tokens - 1
        redis.call('HMSET', key, 'tokens', tokens, 'lastRefill', now)
        redis.call('EXPIRE', key, 3600)
        return 1
      else
        return 0
      end
      `,
      1,
      key,
      this.capacity,
      this.refillRate,
      now,
    );

    return allowed === 1;
  }
}
```

---

## 8. Scaling Considerations

### 8.1 Stateless Verifiers

- **Horizontal scaling:** Run multiple `ZkIdServer` instances behind a load balancer
- **Shared state:** Use Redis for nonce store (avoids replay across instances)
- **Session affinity:** Not required (verification is stateless)

### 8.2 Nonce Store Scaling

- **Redis Cluster:** Shard nonce keys across multiple nodes
- **TTL strategy:** Nonces expire after `maxRequestAgeMs` (auto-cleanup)
- **Capacity planning:** ~100 bytes per nonce, 1M nonces = ~100MB

### 8.3 Merkle Tree Synchronization

For revocable proofs, the Merkle tree must be synchronized across verifiers:

**Option 1: Shared Redis** (recommended for < 10K credentials)

```typescript
import { RedisMerkleTreeStore } from '@zk-id/redis';

const treeStore = new RedisMerkleTreeStore(redis);
const tree = new ValidCredentialTree(treeStore);
```

**Option 2: Database-backed** (for > 10K credentials)

```typescript
import { PostgresMerkleTreeStore } from './custom/postgres-tree-store';

const treeStore = new PostgresMerkleTreeStore(pgClient);
const tree = new ValidCredentialTree(treeStore);
```

---

## 9. Monitoring and Observability

### 9.1 Key Metrics

**Verification metrics:**

- `verification_total{result="success|failure"}` — Total verifications
- `verification_duration_seconds` — Proof verification latency (histogram)
- `verification_errors{error_type="..."}` — Errors by category

**System metrics:**

- `nonce_store_size` — Number of active nonces
- `rate_limit_rejects_total` — Rate limit rejections
- `issuer_registry_cache_hits` — Issuer lookup cache efficiency

### 9.2 Prometheus Integration

```typescript
import { register, Counter, Histogram } from 'prom-client';

const verificationCounter = new Counter({
  name: 'zk_id_verification_total',
  help: 'Total proof verifications',
  labelNames: ['result', 'claim_type'],
});

const verificationDuration = new Histogram({
  name: 'zk_id_verification_duration_seconds',
  help: 'Proof verification latency',
  labelNames: ['claim_type'],
  buckets: [0.1, 0.5, 1, 2, 5, 10],
});

server.onVerification((event) => {
  verificationCounter.inc({
    result: event.verified ? 'success' : 'failure',
    claim_type: event.claimType,
  });

  verificationDuration.observe({ claim_type: event.claimType }, event.verificationTimeMs / 1000);
});
```

### 9.3 Alerts

**Recommended alert rules:**

1. **High error rate:** > 5% verification failures over 5 minutes
2. **Rate limit saturation:** > 50% requests rate-limited
3. **Stale revocation root:** `maxRevocationRootAgeMs` exceeded
4. **Nonce store latency:** > 100ms p99 Redis latency
5. **Certificate expiry:** TLS certificates expiring within 30 days

---

## 10. Troubleshooting

### 10.1 Common Issues

**Issue:** `Error: Verification key not configured`

- **Cause:** Missing verification key file
- **Fix:** Ensure verification key paths are correct in config

**Issue:** `Error: Invalid proof constraints`

- **Cause:** Proof generated with mismatched circuit or public signals
- **Fix:** Verify client and server use same circuit version

**Issue:** `Error: Nonce already used (replay attack detected)`

- **Cause:** Proof submitted twice or nonce store failure
- **Fix:** Check Redis connectivity, verify nonce TTL is configured

**Issue:** `Error: Request timestamp is too far in the future`

- **Cause:** Clock skew between client and server
- **Fix:** Enable NTP on servers, increase `maxFutureSkewMs` cautiously

**Issue:** `Error: Rate limit exceeded`

- **Cause:** Client exceeded rate limit
- **Fix:** Implement exponential backoff on client side

---

## 11. Security Hardening

### 11.1 Network Security

- **Firewall rules:** Allow only ports 443 (HTTPS), 6379 (Redis, internal only)
- **DDoS protection:** Cloudflare, AWS Shield, or similar
- **IP allowlisting:** Restrict issuer key management endpoints

### 11.2 Secrets Management

- **Never commit secrets:** Use `.env` files (gitignored)
- **Rotate secrets regularly:** Issuer keys (annually), API keys (quarterly)
- **Use secret managers:** AWS Secrets Manager, HashiCorp Vault

### 11.3 Audit Logging

**Store audit logs in tamper-evident storage:**

```typescript
import AWS from 'aws-sdk';
import { AuditLogger, AuditEntry } from '@zk-id/core';

class S3AuditLogger implements AuditLogger {
  private s3: AWS.S3;

  constructor(bucket: string) {
    this.s3 = new AWS.S3();
    this.bucket = bucket;
  }

  async log(entry: AuditEntry): Promise<void> {
    const key = `audit/${entry.timestamp.slice(0, 10)}/${Date.now()}.json`;
    await this.s3
      .putObject({
        Bucket: this.bucket,
        Key: key,
        Body: JSON.stringify(entry),
        ContentType: 'application/json',
        ServerSideEncryption: 'AES256',
        ObjectLockMode: 'COMPLIANCE', // WORM (write-once-read-many)
        ObjectLockRetainUntilDate: new Date(Date.now() + 7 * 365 * 24 * 60 * 60 * 1000), // 7 years
      })
      .promise();
  }
}
```

---

## 12. References

- **API Reference:** Auto-generated at `docs/api/` (run `npm run docs`)
- **Protocol Documentation:** `docs/PROTOCOL.md`
- **Threat Model:** `docs/THREAT-MODEL.md`
- **Circuit Diagrams:** `docs/CIRCUIT-DIAGRAMS.md`
- **Security Policy:** `SECURITY.md`

---

**Last updated:** 2026-02-09
**Maintained by:** zk-id core team
