# ZK-ID Web Application Demo

Interactive web demonstration of zero-knowledge identity verification with age and nationality proofs. **Proofs are generated entirely in the browser** — your credential data never leaves your device.

## Features

### Verification Types
- **Age Verification**: Prove age ≥ minimum without revealing exact birth year
- **Nationality Verification**: Prove nationality without exposing age or other data
- **Revocable Proofs**: Merkle tree membership proofs for revocation support

### Security & Privacy Features
- **Client-side proof generation**: ZK proofs run in your browser using WebAssembly
- **Privacy-preserving**: Credential data never sent to server
- Server-generated nonce challenges to prevent replay attacks
- Request timestamp validation
- Ed25519 signature verification for credentials
- Rate limiting on sensitive endpoints
- Protocol version compatibility checking

## Quick Start

### First-Time Setup

Run these commands from the **repository root** (`zk-id/`):

1. **Install dependencies**:
   ```bash
   npm install
   ```

2. **Compile circuits and perform trusted setup** (required for proof generation):
   ```bash
   npm run compile:circuits
   npm run --workspace=@zk-id/circuits setup
   ```

   This downloads Powers of Tau files (~86 MB) and generates proving/verification keys. Takes 1-2 minutes.

### Running the Demo

The web app automatically builds all required packages (core, SDK, issuer) before starting.

From the **repository root**:

```bash
npm start --workspace=@zk-id/example-web-app
```

Or from the **web-app directory** (`examples/web-app/`):

```bash
npm start
```

Then open your browser to `http://localhost:3000`

### Development Mode

For auto-reload during development:

```bash
npm run dev --workspace=@zk-id/example-web-app
```

### Manual Package Builds (Optional)

If you need to manually build packages:

```bash
# From repository root
npm run build --workspace=@zk-id/core
npm run build --workspace=@zk-id/sdk
npm run build --workspace=@zk-id/issuer

# Or from web-app directory
npm run setup:deps
```

## How It Works

### 1. Credential Issuance

The demo issuer (simulating a government ID service) issues credentials containing:
- Birth year
- Nationality (ISO 3166-1 numeric code)
- Cryptographic commitment
- Ed25519 signature

In production, this would require KYC/identity verification.

### 2. Proof Generation (Client-Side)

When verification is requested:
1. User selects claim type (age or nationality)
2. Browser fetches a server challenge (nonce + timestamp)
3. **Browser downloads circuit artifacts (WASM + zkey) and generates ZK proof locally**
4. Browser sends only the proof to server (credential data stays client-side)

The proof generation happens entirely in your browser using:
- **snarkjs** for ZK proof generation
- **WebAssembly** for high-performance circuit execution
- **Circuit artifacts** served statically from `/circuits`

### 3. Verification (Server-Side)

The server:
1. Validates the challenge (nonce freshness, timestamp)
2. Verifies the Groth16 proof using verification keys
3. Checks Ed25519 signature
4. Validates against revocation store
5. Returns verification result

**Important**: The server never sees your credential data — only the proof and public signals.

## API Endpoints

### Credential Management
- `POST /api/issue-credential` - Issue a credential
- `POST /api/revoke-credential` - Revoke a credential (admin)

### Verification
- `GET /api/challenge` - Get nonce + timestamp challenge
- `POST /api/verify-age` - Verify client-generated age proof
- `POST /api/verify-nationality` - Verify client-generated nationality proof

### System
- `GET /api/health` - Health check
- `GET /api/revocation/root` - Get revocation tree root

## Architecture

```
┌─────────────────────────┐
│   Browser (Client)      │
│                         │
│  1. Fetch challenge     │
│  2. Download circuits   │ ← /circuits/*.wasm, *.zkey
│  3. Generate ZK proof   │ ← snarkjs + WASM
│     (local, private)    │
│  4. Send proof only     │
└────────┬────────────────┘
         │ HTTP/JSON
         │ (proof only, no credential)
         │
┌────────▼────────────────┐
│   Express Server        │
├─────────────────────────┤
│  ZkIdServer (SDK)       │
│                         │
│  • Nonce/Challenge      │
│  • Verify proofs        │
│  • Revocation checks    │
└────────┬────────────────┘
         │
┌────────▼────────────────┐
│   Verification Keys     │
│   (server-side only)    │
└─────────────────────────┘
```

## Configuration

Environment variables:

- `PORT` - Server port (default: 3000)
- `API_RATE_LIMIT` - Requests per minute for API endpoints (default: 60)

## Performance

Typical timings on modern hardware (client-side in browser):

- **Circuit Download**: 500ms - 2s (cached after first load)
- **Proof Generation**: 3-7 seconds (in browser, depends on device)
- **Verification**: 10-50 ms (server-side)
- **Proof Size**: ~1.5 KB

**Note**: First-time proof generation requires downloading ~5-10MB of circuit artifacts (WASM + zkey). These are cached by the browser for subsequent proofs.

## Production Deployment

⚠️ **This is a demo application.** For production:

1. **Key Management**: Use HSM or secure key storage instead of in-memory
2. **Database**: Replace in-memory stores with persistent database
3. **Authentication**: Add proper authentication for credential issuance
4. **Rate Limiting**: Configure appropriate rate limits for your use case
5. **Monitoring**: Add observability and logging
6. **HTTPS**: Enable TLS termination
7. **Circuit Audits**: Have circuits audited by ZK security experts
8. **CDN**: Serve circuit artifacts from CDN for faster downloads
9. **Wallet Integration**: For production, users should store credentials in a wallet app

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

Compile the circuits and run setup from the repository root:
```bash
npm run compile:circuits
npm run --workspace=@zk-id/circuits setup
```

### "Cannot find module '@zk-id/core'" or similar build errors

Build the required packages from the repository root:
```bash
npm run build --workspace=@zk-id/core
npm run build --workspace=@zk-id/sdk
npm run build --workspace=@zk-id/issuer
```

### "Hash verification failed"

This is expected during development. The hash check ensures circuit reproducibility.

### Slow proof generation in browser

Proof generation is CPU-intensive (3-7s in browser). This is normal for ZK proofs. In production:
- Use Web Workers to avoid blocking the UI
- Show progress indicators
- Consider using faster devices or native mobile apps for better performance

## Privacy Architecture

**Your credential data never leaves your browser:**

1. **Issuance**: Credential is stored in browser memory only
2. **Proof Generation**: Runs entirely client-side (snarkjs + WASM)
3. **Verification**: Only the proof and public signals are sent to server
4. **Result**: Server cannot learn your birth year, nationality, or other private data

The server only learns:
- That you have a valid credential from the issuer
- The minimum age threshold you meet (e.g., "age ≥ 18")
- Or your nationality (if you choose to prove it)

The server **cannot** learn:
- Your exact birth year
- Other attributes you didn't choose to prove
- Your credential's private data

## Future: Wallet SDK Integration

This demo currently uses server-side storage for Merkle witnesses (revocable proofs). A production wallet SDK would add:
- Client-side Merkle witness fetching via `/api/witness` endpoint
- Fully client-side revocable proof generation
- Credential storage in secure wallet
- Multi-issuer support

## License

Apache-2.0
