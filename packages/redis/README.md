# @zk-id/redis

Redis store implementations for zk-id production deployments.

## Overview

This package provides Redis-backed implementations of zk-id's pluggable store interfaces, enabling horizontally scalable, production-ready deployments.

## Implemented Stores

- **RedisNonceStore** - Replay attack prevention with automatic expiration
- **RedisChallengeStore** - Nonce challenge issuance and consumption
- **RedisRevocationStore** - Permanent credential revocation tracking
- **RedisRateLimiter** - Sliding window rate limiting per identifier
- **RedisIssuerRegistry** - Issuer public key and metadata storage

## Installation

```bash
npm install @zk-id/redis ioredis
```

Note: `ioredis` is a peer dependency. You can use any Redis client that implements the `RedisClient` interface.

## Usage

```typescript
import Redis from 'ioredis';
import { createZkIdServer } from '@zk-id/sdk';
import {
  RedisNonceStore,
  RedisChallengeStore,
  RedisRevocationStore,
  RedisRateLimiter,
  RedisIssuerRegistry
} from '@zk-id/redis';

const redis = new Redis(process.env.REDIS_URL);

const server = createZkIdServer({
  nonceStore: new RedisNonceStore(redis, { ttlSeconds: 300 }),
  challengeStore: new RedisChallengeStore(redis),
  revocationStore: new RedisRevocationStore(redis),
  rateLimiter: new RedisRateLimiter(redis, { limit: 10, windowMs: 60000 }),
  issuerRegistry: new RedisIssuerRegistry(redis),
  // ... other config
});
```

## Configuration Options

### RedisNonceStore

```typescript
new RedisNonceStore(client, {
  keyPrefix: 'zkid:nonce:', // Default key prefix
  ttlSeconds: 300,          // TTL in seconds (default: 300)
});
```

### RedisChallengeStore

```typescript
new RedisChallengeStore(client, {
  keyPrefix: 'zkid:challenge:', // Default key prefix
});
```

### RedisRevocationStore

```typescript
new RedisRevocationStore(client, {
  key: 'zkid:revoked', // Redis SET key for revocations
});
```

### RedisRateLimiter

```typescript
new RedisRateLimiter(client, {
  keyPrefix: 'zkid:rate:', // Default key prefix
  limit: 10,               // Max requests per window (default: 10)
  windowMs: 60000,         // Window size in ms (default: 60000)
});
```

### RedisIssuerRegistry

```typescript
new RedisIssuerRegistry(client, {
  keyPrefix: 'zkid:issuer:', // Default key prefix
});
```

## Testing

```bash
# Run tests (requires Redis)
REDIS_URL=redis://localhost:6379 npm test

# Tests will skip gracefully if REDIS_URL is not set
npm test
```

## License

Apache-2.0
