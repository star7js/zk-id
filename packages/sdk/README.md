# @zk-id/sdk

**Client and server SDK for integrating zk-id into web applications**

This package provides server-side proof verification with security policies, nonce replay protection, rate limiting, issuer registry, and audit logging. It also includes client-side proof requesting with wallet integration and a browser wallet with IndexedDB persistence.

## Features

### ZkIdServer

- **Verification Pipeline** — Complete security pipeline including rate limiting, nonce check, policy enforcement, signature validation, crypto verification, and audit logging
- **createChallenge()** — Generate nonce challenges for replay protection
- **getRevocationRootInfo()** — Retrieve current revocation Merkle root and metadata
- **Security Policies** — Enforce proof freshness, protocol version compatibility, and issuer trust requirements

### ZkIdClient

- **Browser SDK** — Client-side proof generation for `verifyAge()`, `verifyNationality()`, `verifyAgeRevocable()`, `verifyScenario()`
- **Wallet Integration** — Connect to browser wallets via `WalletConnector` interface
- **Revocation Root Fetching** — Automatically fetch revocation roots for revocable proofs

### BrowserWallet

- **CredentialStore Interface** — Abstract interface for credential storage
- **IndexedDBCredentialStore** — Production-ready credential storage with IndexedDB persistence
- **Backup/Recovery** — Export and import credentials as encrypted JSON
- **Consent Callbacks** — Optional user consent prompts before proof generation

### Security Components

- **InMemoryNonceStore** — TTL-based nonce store with automatic pruning (configurable interval)
- **InMemoryChallengeStore** — Challenge issuance and consumption tracking
- **InMemoryIssuerRegistry** — Issuer public key registry with key rotation and grace periods
- **SimpleRateLimiter** — Basic IP-based rate limiting (NOT production-suitable)

### PostgresValidCredentialTree

- **Production Merkle Tree** — Postgres-backed sparse Merkle tree for valid credentials
- **Layer Caching** — Efficient layer-by-layer caching for fast proof generation
- **Concurrent Updates** — Transaction-safe concurrent credential additions

### IssuerDashboard

- **Aggregate Statistics** — Dashboard combining issuer registry, audit log, and revocation store metrics
- **Monitoring** — Track issuance rate, revocation rate, active issuers, and key rotation status

## Installation

```bash
npm install @zk-id/sdk
```

**Peer dependency:** `@zk-id/core`

## Server Setup

```typescript
import { createZkIdServer } from '@zk-id/sdk';
import { readFileSync } from 'fs';
import express from 'express';

const server = createZkIdServer({
  verificationKeyPath: './age-verify-verification-key.json',
  nonceStore: new InMemoryNonceStore({ ttlSeconds: 300 }),
  issuerRegistry: new InMemoryIssuerRegistry(),
  requiredPolicy: { maxProofAgeMs: 60000 },
  verboseErrors: false, // Don't leak circuit errors to clients
});

const app = express();
app.use(express.json());

app.post('/api/verify-age', async (req, res) => {
  const result = await server.verifyAge(req.body);
  res.json(result);
});

app.listen(3000);
```

## Client Setup

```typescript
import { ZkIdClient } from '@zk-id/sdk';

const client = new ZkIdClient({
  verificationEndpoint: 'https://example.com/api/verify-age',
});

// Request age verification
const result = await client.verifyAge(credential, 18);
if (result.success) {
  console.log('Age verified!');
}
```

## Scenario Verification

Scenarios combine multiple claims into named real-world use cases. Instead of manually orchestrating age and nationality proofs, use built-in scenarios like voting eligibility or senior discounts.

### Client-Side Usage

```typescript
import { ZkIdClient } from '@zk-id/sdk';
import { SCENARIOS } from '@zk-id/core';

const client = new ZkIdClient({
  verificationEndpoint: '/api/verify-voting-eligibility',
});

// Verify voting eligibility (age >= 18 AND nationality = USA)
const result = await client.verifyScenario(
  credential,
  SCENARIOS.VOTING_ELIGIBILITY_US
);

if (result.verified) {
  console.log('Voter is eligible!');
}
```

### Built-in Scenarios

| Scenario Key | Name | Description | Claims |
|--------------|------|-------------|--------|
| `VOTING_ELIGIBILITY_US` | US Voting Eligibility | Verify user is 18+ and a US citizen | age >= 18, nationality = USA (840) |
| `SENIOR_DISCOUNT` | Senior Discount | Verify user is 65+ for senior discounts | age >= 65 |
| `ALCOHOL_PURCHASE_US` | US Alcohol Purchase | Verify user is 21+ for alcohol purchase | age >= 21 |
| `TOBACCO_PURCHASE_US` | US Tobacco Purchase | Verify user is 21+ for tobacco purchase | age >= 21 |
| `GAMBLING_US` | US Gambling | Verify user is 21+ for gambling | age >= 21 |
| `EU_GDPR_AGE_CONSENT` | EU GDPR Age of Consent | Verify user is 16+ for GDPR data processing consent | age >= 16 |
| `RENTAL_CAR_US` | US Rental Car | Verify user is 25+ for rental car (standard rate) | age >= 25 |

### VerificationScenario Interface

```typescript
interface VerificationScenario {
  /** Unique identifier for the scenario */
  id: string;
  /** Human-readable name */
  name: string;
  /** Description of what the scenario verifies */
  description: string;
  /** Claims that must be proven for this scenario */
  claims: ClaimSpec[];
}
```

### Custom Scenarios

You can define custom scenarios by creating a `VerificationScenario` object:

```typescript
import { VerificationScenario } from '@zk-id/core';

const customScenario: VerificationScenario = {
  id: 'my-custom-scenario',
  name: 'Custom Age Check',
  description: 'Verify user meets custom requirements',
  claims: [
    {
      label: 'minimum-age',
      claimType: 'age',
      minAge: 25,
    },
    {
      label: 'eu-citizen',
      claimType: 'nationality',
      targetNationality: 276, // Germany
    },
  ],
};

const result = await client.verifyScenario(credential, customScenario);
```

## Configuration Reference

### ZkIdServerConfig

Key configuration options:

- **verificationKeyPath** — Path to age verification key JSON
- **nationalityVerificationKeyPath** — Path to nationality verification key JSON
- **verificationKeys** — In-memory verification keys (alternative to file paths)
- **nonceStore** — Nonce store implementation (e.g., `InMemoryNonceStore`, `RedisNonceStore`)
- **issuerRegistry** — Issuer registry implementation (e.g., `InMemoryIssuerRegistry`, `RedisIssuerRegistry`)
- **revocationStore** — Revocation tracking (optional, for revocable proofs)
- **validCredentialTree** — Merkle tree for valid credentials (optional, for revocable proofs)
- **requiredPolicy** — Policy object with `maxProofAgeMs`, `minProtocolVersion`, `trustedIssuers`
- **verboseErrors** — Return detailed circuit errors to clients (default: `false`, use `true` for debugging)
- **maxFutureSkewMs** — Max allowed timestamp skew into future (default: 5000ms)
- **auditLogger** — Audit logger implementation (default: `ConsoleAuditLogger`)
- **protocolVersionPolicy** — How to handle version mismatches: `'strict'` (reject), `'warn'` (log), `'off'` (ignore)

## Production Notes

- **SimpleRateLimiter is NOT production-suitable** — It's IP-based and easily bypassable with proxies. Use a Redis-backed token bucket algorithm with user authentication for production.
- **InMemoryNonceStore starts a background prune timer** — Call `.stop()` on server shutdown to prevent memory leaks. The prune interval is configurable (default: 60 seconds).
- **Protocol version headers are same-origin only by default** — The `X-ZkId-Protocol-Version` header is only sent for same-origin requests in browsers (CORS restriction). Set `protocolVersionHeader: 'always'` to override.
- **Verbose errors leak circuit information** — Setting `verboseErrors: true` can expose circuit structure and constraint details to attackers. Only enable for debugging in development.

## Testing

```bash
npm test
```

Tests cover server verification pipeline, client-side proof generation, browser wallet storage, and security components.

## Related Packages

- `@zk-id/core` — Core credential and proof primitives
- `@zk-id/circuits` — Circom circuits and compiled artifacts
- `@zk-id/issuer` — Credential issuance
- `@zk-id/redis` — Production-ready Redis stores for nonces, challenges, and rate limiting
- `@zk-id/contracts` — On-chain Solidity verifiers

## License

Apache-2.0
