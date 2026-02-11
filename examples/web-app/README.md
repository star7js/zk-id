# ZK-ID Web Application Demo

Interactive web demonstration of zero-knowledge identity verification with age and nationality proofs. **Proofs are generated entirely in the browser** — your credential data never leaves your device.

**For a comprehensive integration guide**, see [GETTING-STARTED.md](../../GETTING-STARTED.md) in the repository root.

## Features

### Verification Types

- **Age Verification**: Prove age ≥ minimum without revealing exact birth year
- **Nationality Verification**: Prove nationality without exposing age or other data
- **Scenario Verification**: Combine multiple claims in a single check (e.g., voting eligibility = age + nationality)
- **Revocable Proofs**: Merkle tree membership proofs for revocation support

### Security & Privacy Features

- **Client-side proof generation**: ZK proofs run in your browser using WebAssembly
- **Privacy-preserving**: Credential data never sent to server
- Server-generated nonce challenges to prevent replay attacks
- Request timestamp validation
- Ed25519 signature verification for credentials
- Rate limiting on sensitive endpoints
- Protocol version compatibility checking

## What You'll See

This demo simulates the complete zk-id workflow:

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   Issuer    │────>│    User     │────>│  Verifier   │
│  (Server)   │     │  (Browser)  │     │  (Server)   │
└─────────────┘     └─────────────┘     └─────────────┘
   Issue cred        Generate proof     Verify proof
   + signature       (client-side)      (check sig)
```

**Try it live:** Issue a credential → Verify age → Verify nationality → Test scenario verification (voting, senior discount) → Test revocation

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

### 4. Scenario Verification (Combined Claims)

For real-world use cases requiring multiple claims (e.g., voting requires both age and nationality), the app uses **scenario verification**:

1. The scenario defines which claims are needed (from the `SCENARIOS` registry in `@zk-id/core`)
2. The browser generates **separate proofs** for each claim using reusable helper functions
3. All proofs are verified independently; the scenario passes only if every proof succeeds

The web app demonstrates two built-in scenarios:

- **Voting Eligibility** (Step 4): Proves age >= 18 AND nationality = USA (2 proofs)
- **Senior Discount** (Step 5): Proves age >= 65 (1 proof)

## API Endpoints

### Credential Management

- `POST /api/issue-credential` - Issue a credential
- `POST /api/revoke-credential` - Revoke a credential (admin)

### Verification

- `GET /api/challenge` - Get nonce + timestamp challenge
- `POST /api/verify-age` - Verify client-generated age proof
- `POST /api/verify-nationality` - Verify client-generated nationality proof
- `POST /api/verify-scenario` - Verify scenario bundle (e.g., voting eligibility, senior discount)
- `POST /api/verify-voting-eligibility` - Verify voting eligibility (age + nationality)
- `POST /api/verify-senior-discount` - Verify senior discount eligibility (age)

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
│  • Scenario endpoints   │
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
    error: event.error,
  });
});
```

## Testing Scenarios

### 1. Happy Path (Success)

```
Issue credential (1995, USA)
→ Verify age ≥ 18 ✓
→ Verify nationality = USA ✓
```

### 2. Age Too Young (Failure)

```
Issue credential (2010, USA)
→ Verify age ≥ 18 ✗
Expected: Verification fails (age < 18)
```

### 3. Wrong Nationality (Failure)

```
Issue credential (1995, USA = 840)
→ Verify nationality = Germany (276) ✗
Expected: Verification fails (nationality mismatch)
```

### 4. Revocation (Failure After Revoke)

```
Issue credential (1995, USA)
→ Verify age ≥ 18 ✓
→ Revoke credential
→ Verify age ≥ 18 again ✗
Expected: Second verification fails (revoked)
```

### 5. Replay Attack (Nonce Expiry)

```
Generate proof with nonce N
→ Verify ✓
→ Wait 5+ minutes
→ Verify same proof again ✗
Expected: Fails (nonce expired)
```

### 6. Multiple Age Thresholds

```
Issue credential (1995)
→ Verify age ≥ 18 ✓
→ Verify age ≥ 21 ✓
→ Verify age ≥ 65 ✗
Expected: Passes 18+ and 21+, fails 65+
```

### 7. Boundary Conditions

```
Issue credential (birthYear = currentYear - 18)
→ Verify age ≥ 18 ✓
Expected: Exactly 18 years old passes
```

### 8. Voting Eligibility (Combined Scenario)

```
Issue credential (1995, USA = 840)
→ Verify voting eligibility ✓ (age 18+ AND US citizen)

Issue credential (1995, Germany = 276)
→ Verify voting eligibility ✗
Expected: Fails (nationality is not USA)
```

### 9. Senior Discount (Age Threshold)

```
Issue credential (1955, USA)
→ Verify senior discount ✓ (age 65+)

Issue credential (1995, USA)
→ Verify senior discount ✗
Expected: Fails (age < 65)
```

## Troubleshooting

### Build Errors

**Error:** `Cannot find module '@zk-id/core'` or similar

**Cause:** TypeScript packages not built

**Solution:**

```bash
# From repository root
npm run build

# Or build specific packages
npm run build --workspace=@zk-id/core
npm run build --workspace=@zk-id/sdk
npm run build --workspace=@zk-id/issuer
```

### Circuit Errors

**Error:** `Cannot find circuit artifacts` or `ENOENT: no such file`

**Cause:** Circuits not compiled

**Solution:**

```bash
# From repository root
npm run compile:circuits
npm run --workspace=@zk-id/circuits setup
```

**Error:** `Hash verification failed`

**Cause:** Platform-dependent circuit artifacts (macOS vs Linux)

**Solution:** This is expected during development. The hash check ensures reproducibility but allows platform differences.

### Verification Errors

**Error:** `Proof verification failed` with valid inputs

**Possible causes:**

1. **Circuit version mismatch** — Client and server using different circuit versions
   - Solution: Rebuild circuits on both sides
2. **Clock skew** — Timestamp validation failed
   - Solution: Sync system clocks (use NTP)
3. **Nonce expired** — Proof older than TTL (default: 5 minutes)
   - Solution: Generate fresh proof with new challenge
4. **Wrong verification key** — Server using incorrect key
   - Solution: Ensure `verification_key.json` matches circuit version

**Enable verbose errors for debugging:**

```typescript
const server = new ZkIdServer({
  verboseErrors: true, // Shows detailed circuit errors
  // ... other config
});
```

### Performance Issues

**Issue:** Proof generation takes 10+ seconds in browser

**Causes and solutions:**

- **First load:** Downloading ~5-10 MB of circuit artifacts
  - Expected on first proof, cached after
  - Solution: Show loading indicator, serve from CDN
- **Slow device:** CPU-intensive computation
  - Solution: Use Web Workers, show progress bar
- **Large circuits:** Signed circuits take ~15s (20k constraints)
  - Expected for in-circuit signature verification
  - Solution: Use basic circuits when possible

**Issue:** Verification taking >1 second on server

**Causes:**

- Database query slow (revocation check)
  - Solution: Add indexes, use Redis
- Circuit artifact loading slow
  - Solution: Preload verification keys at startup

### Runtime Errors

**Error:** `ReferenceError: snarkjs is not defined`

**Cause:** snarkjs not loaded in browser

**Solution:** Ensure snarkjs is bundled or loaded via CDN:

```html
<script src="https://cdn.jsdelivr.net/npm/snarkjs@0.7.6/build/snarkjs.min.js"></script>
```

**Error:** `Invalid issuer signature`

**Cause:** Issuer registry not configured or public key mismatch

**Solution:**

```typescript
// Register issuer's public key
await issuerRegistry.registerIssuer({
  issuer: 'Demo Issuer',
  publicKey: issuerPublicKeyPem,
  status: 'active',
});
```

### Browser Compatibility

**Issue:** Proof generation fails in Safari/iOS

**Cause:** WASM memory limits or SharedArrayBuffer restrictions

**Solution:**

- Increase WASM memory limit
- Use Chrome/Firefox for development
- Test on actual devices (Safari desktop vs iOS Safari differ)

**Issue:** Circuit artifacts not loading (CORS)

**Cause:** Cross-origin resource sharing blocked

**Solution:**

```typescript
// In Express server
app.use(
  '/circuits',
  express.static('circuits', {
    setHeaders: (res) => {
      res.set('Access-Control-Allow-Origin', '*');
      res.set('Cross-Origin-Embedder-Policy', 'require-corp');
      res.set('Cross-Origin-Opener-Policy', 'same-origin');
    },
  }),
);
```

### Common Mistakes

**Mistake:** Using `createTestIssuer()` in production

**Why it's wrong:** Generates ephemeral keys, lost on restart

**Fix:** Use `FileKeyManager` or `EnvelopeKeyManager`

**Mistake:** Not calling `nonceStore.stop()` on shutdown

**Why it's wrong:** Background prune timer keeps Node.js process alive

**Fix:**

```typescript
process.on('SIGTERM', async () => {
  await nonceStore.stop();
  process.exit(0);
});
```

**Mistake:** Reusing nonces across proofs

**Why it's wrong:** Replay attacks

**Fix:** Fetch fresh challenge for each proof:

```typescript
const challenge = await client.fetchChallenge();
const proof = await generateAgeProofAuto(cred, 18, challenge.nonce, challenge.timestamp);
```

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

## Deep Dive: Package Documentation

Want to build your own integration? Read the package READMEs:

- **[@zk-id/core](../../packages/core/README.md)** — Core cryptographic library for proof generation/verification
- **[@zk-id/sdk](../../packages/sdk/README.md)** — Client and server SDK (this is what the demo uses)
- **[@zk-id/issuer](../../packages/issuer/README.md)** — Credential issuance with multiple signature schemes
- **[@zk-id/circuits](../../packages/circuits/README.md)** — Zero-knowledge circuits (7 circuits, constraint counts)
- **[@zk-id/redis](../../packages/redis/README.md)** — Production Redis stores for scaling
- **[@zk-id/contracts](../../packages/contracts/README.md)** — On-chain Solidity verifiers

## Production Migration Path

This demo uses in-memory stores. To go production:

### Phase 1: Basic Production (Single Server)

- ✅ Replace `InMemoryNonceStore` with `RedisNonceStore`
- ✅ Replace `InMemoryIssuerRegistry` with `RedisIssuerRegistry`
- ✅ Use `FileKeyManager` for issuer keys
- ✅ Enable HTTPS
- ✅ Add proper authentication for `/api/issue-credential`

### Phase 2: Scalable Production (Multi-Server)

- ✅ Deploy Redis cluster for horizontal scaling
- ✅ Use `PostgresValidCredentialTree` for revocation
- ✅ Add CDN for circuit artifacts
- ✅ Implement `RedisRateLimiter`
- ✅ Add monitoring and alerting

### Phase 3: Enterprise Production

- ✅ Move issuer keys to HSM/KMS (AWS KMS, Azure Key Vault)
- ✅ Implement comprehensive audit logging
- ✅ Add WAF and DDoS protection
- ✅ Run production Powers of Tau ceremony
- ✅ Get circuit security audit
- ✅ Implement disaster recovery

See [GETTING-STARTED.md](../../GETTING-STARTED.md) for detailed deployment guides.

## License

Apache-2.0
