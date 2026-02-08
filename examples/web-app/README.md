# ZK-ID Web Application Demo

Interactive web demonstration of zero-knowledge identity verification with age and nationality proofs.

## Features

### Verification Types
- **Age Verification**: Prove age ≥ minimum without revealing exact birth year
- **Nationality Verification**: Prove nationality without exposing age or other data
- **Signed Circuit Proofs**: Issuer signature verification inside the ZK circuit
- **Revocable Proofs**: Merkle tree membership proofs for revocation support

### Security Features
- Server-generated nonce challenges to prevent replay attacks
- Request timestamp validation
- Ed25519 signature verification for credentials
- Rate limiting on sensitive endpoints
- Protocol version compatibility checking

## Quick Start

### Prerequisites

1. **Compile circuits** (required for proof generation):
   ```bash
   # From repository root
   npm run compile:circuits
   npm run --workspace=@zk-id/circuits setup
   ```

2. **Install dependencies**:
   ```bash
   npm install
   ```

### Running the Demo

```bash
npm start
```

Then open your browser to `http://localhost:3000`

### Development Mode

For auto-reload during development:

```bash
npm run dev
```

## How It Works

### 1. Credential Issuance

The demo issuer (simulating a government ID service) issues credentials containing:
- Birth year
- Nationality (ISO 3166-1 numeric code)
- Cryptographic commitment
- Ed25519 signature

In production, this would require KYC/identity verification.

### 2. Proof Generation

When verification is requested:
1. User selects claim type (age or nationality)
2. Client fetches a server challenge (nonce + timestamp)
3. Server generates a ZK proof using the credential
4. Proof includes public signals but hides sensitive data

### 3. Verification

The server:
1. Validates the challenge (nonce freshness, timestamp)
2. Verifies the Groth16 proof using verification keys
3. Checks Ed25519 signature (or in-circuit for signed proofs)
4. Validates against revocation store
5. Returns verification result

## API Endpoints

### Credential Management
- `POST /api/issue-credential` - Issue a standard credential
- `POST /api/issue-credential-signed` - Issue a signed-circuit credential
- `POST /api/revoke-credential` - Revoke a credential (admin)

### Verification
- `GET /api/challenge` - Get nonce + timestamp challenge
- `POST /api/verify-age` - Verify age proof
- `POST /api/verify-nationality` - Verify nationality proof
- `POST /api/demo/verify-age` - Combined proof generation + verification
- `POST /api/demo/verify-age-signed` - Signed circuit age verification
- `POST /api/demo/verify-nationality` - Combined nationality proof + verification
- `POST /api/demo/verify-nationality-signed` - Signed circuit nationality verification
- `POST /api/demo/verify-age-revocable` - Revocable age proof

### System
- `GET /api/health` - Health check
- `GET /api/revocation/root` - Get revocation tree root

## Architecture

```
┌─────────────┐
│   Browser   │
│   (Client)  │
└──────┬──────┘
       │ HTTP/JSON
       │
┌──────▼──────┐
│   Express   │
│   Server    │
├─────────────┤
│  ZkIdServer │  ← SDK integration
│             │
│  • Nonce    │
│  • Challenge│
│  • Verify   │
└──────┬──────┘
       │
┌──────▼──────┐
│   Circuits  │
│   (WASM +   │
│    ZKEY)    │
└─────────────┘
```

## Configuration

Environment variables:

- `PORT` - Server port (default: 3000)
- `API_RATE_LIMIT` - Requests per minute for API endpoints (default: 60)
- `DEMO_PROOF_RATE_LIMIT` - Requests per minute for proof generation (default: 10)

## Performance

Typical timings on modern hardware:

- **Proof Generation**: 2-5 seconds
- **Verification**: 10-50 ms
- **Proof Size**: ~1.5 KB

## Production Deployment

⚠️ **This is a demo application.** For production:

1. **Key Management**: Use HSM or secure key storage instead of in-memory
2. **Database**: Replace in-memory stores with persistent database
3. **Authentication**: Add proper authentication for credential issuance
4. **Rate Limiting**: Configure appropriate rate limits for your use case
5. **Monitoring**: Add observability and logging
6. **HTTPS**: Enable TLS termination
7. **Circuit Audits**: Have circuits audited by ZK security experts

## Telemetry

The server logs verification events for monitoring:

```javascript
zkIdServer.onVerification((event) => {
  console.log({
    timestamp: event.timestamp,
    claimType: event.claimType,
    verified: event.verified,
    timeMs: event.verificationTimeMs,
    client: event.clientIdentifier,
    error: event.error
  });
});
```

## Testing

Try these scenarios:

1. **Happy Path**: Issue credential, verify age/nationality
2. **Revocation**: Issue → Verify → Revoke → Verify again (should fail)
3. **Age Requirement**: Issue with birth year 2020 → Verify age ≥ 18 (should fail)
4. **Wrong Nationality**: Issue with US (840) → Verify German (276) (should fail)
5. **Replay Attack**: Generate proof → Verify → Verify again (nonce expires)

## Troubleshooting

### "Circuit artifacts not found"

Compile the circuits first:
```bash
cd ../../packages/circuits
npm run compile
npm run setup
```

### "Hash verification failed"

This is expected during development. The hash check ensures circuit reproducibility.

### Proof generation timeout

Proof generation is CPU-intensive (2-5s). For better UX in production, consider:
- Client-side proof generation (move to browser)
- Worker threads for concurrent proof generation
- Caching trusted setup artifacts

## License

Apache-2.0
