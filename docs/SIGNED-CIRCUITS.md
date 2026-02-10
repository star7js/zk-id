# Signed Circuits (Optional)

This repo includes optional circuits that verify issuer signatures **inside** the proof.
These circuits use **BabyJub EdDSA** (circomlib) signatures, which are different from
the Ed25519 signatures used in the default issuer flow.
Use these when you want the proof to be self‑contained (issuer trust bound in‑circuit),
at the cost of larger public inputs and slower proving.

## What’s Included

- `age-verify-signed.circom`
- `nationality-verify-signed.circom`

These circuits verify:

- Claim constraint (age or nationality)
- Credential commitment (Poseidon hash)
- Nonce and request timestamp
- **Issuer signature** over the credential commitment

## How It Works (High Level)

1. Issuer signs the credential commitment using a circuit‑compatible EdDSA signature.
2. Prover supplies signature bits + issuer public key bits as circuit inputs.
3. Circuit verifies signature and proof claims.

## Usage (High Level)

1. Issue a circuit‑signed credential using `CircuitCredentialIssuer`.
2. Build the `CircuitSignatureInputs` (issuer pubkey + signature bits).
3. Generate a signed proof using the `generate*Signed` functions.
4. Verify using `verify*Signed` and the signed verification keys.

If you use the server SDK, call `verifySignedProof` and configure:

- `signedVerificationKeyPath` / `signedNationalityVerificationKeyPath`
- `issuerPublicKeyBits` (trusted BabyJub public key bits per issuer)

## Code Sketch

```ts
import { generateAgeProofSigned, verifyAgeProofSigned } from '@zk-id/core';
import { CircuitCredentialIssuer } from '@zk-id/issuer';

const issuer = await CircuitCredentialIssuer.createTestIssuer('Demo Issuer');
const signed = await issuer.issueCredential(1990, 840);
const signatureInputs = issuer.getSignatureInputs(signed);

const nonce = '...';
const requestTimestampMs = Date.now();

const proof = await generateAgeProofSigned(
  signed.credential,
  18,
  nonce,
  requestTimestampMs,
  signatureInputs,
  'path/to/age-verify-signed.wasm',
  'path/to/age-verify-signed.zkey',
);

// verifyAgeProofSigned(proof, verificationKey)
```

## Notes

- The signed circuits are optional. The default circuits are still supported.
- The signed circuits are significantly heavier; proving time will be higher.
- Only use these if you need issuer trust enforced inside the proof.
