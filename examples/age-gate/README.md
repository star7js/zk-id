# Age Gate Example

This example demonstrates a complete end-to-end age verification flow using zk-id.

## Scenario

A user wants to access age-restricted content (e.g., adult website, alcohol purchase, social media) without revealing their exact age or birth year.

## Flow

1. **Credential Issuance**: User obtains a credential from a trusted issuer (government, identity provider) after ID verification
2. **Proof Generation**: User generates a zero-knowledge proof that they meet the age requirement
3. **Proof Verification**: Website verifies the proof and grants access

## What Makes This Private?

- The website learns **only** that the user meets the age requirement (e.g., "at least 18")
- The website does **not** learn:
  - The user's birth year
  - The user's exact age
  - Any other personal information

## Running the Demo

```bash
# Install dependencies
npm install

# Run the demo
npm run demo
```

## With Full Proof Generation

To see actual proof generation and verification:

```bash
# 1. Compile the circuits
cd ../../packages/circuits
npm install
npm run compile
npm run setup

# 2. Run the demo again
cd ../../examples/age-gate
npm run demo
```

## Real-World Integration

For a real website integration, see:

**Client side** (user's browser):
```typescript
import { ZkIdClient } from '@zk-id/sdk';

const client = new ZkIdClient({
  verificationEndpoint: '/api/verify-age'
});

const verified = await client.verifyAge(18);
if (verified) {
  // Grant access
}
```

**Server side** (website backend):
```typescript
import { ZkIdServer } from '@zk-id/sdk';

const server = new ZkIdServer({
  verificationKeyPath: './verification_key.json'
});

app.post('/api/verify-age', async (req, res) => {
  const result = await server.verifyProof(req.body);
  res.json({ verified: result.verified });
});
```
