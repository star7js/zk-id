import { expect } from 'chai';
import path from 'path';
import { CircuitCredentialIssuer } from '@zk-id/issuer';
import { generateAgeProofSigned } from '../src/prover';
import { loadVerificationKey, verifyAgeProofSignedWithIssuer } from '../src/verifier';

// Note: This is a slow integration test that uses compiled circuits

describe('Signed Proof Integration', () => {
  it('should generate and verify a signed age proof end-to-end', async function () {
    this.timeout(60000);

    const issuer = await CircuitCredentialIssuer.createTestIssuer('Signed Issuer');
    const signed = await issuer.issueCredential(1990, 840);

    const signatureInputs = issuer.getSignatureInputs(signed);

    const wasmPath = path.resolve(
      __dirname,
      '../../circuits/build/age-verify-signed_js/age-verify-signed.wasm'
    );
    const zkeyPath = path.resolve(
      __dirname,
      '../../circuits/build/age-verify-signed.zkey'
    );
    const vkeyPath = path.resolve(
      __dirname,
      '../../circuits/build/age-verify-signed_verification_key.json'
    );

    const nonce = 'nonce-123';
    const requestTimestampMs = Date.now();

    const proof = await generateAgeProofSigned(
      signed.credential,
      18,
      nonce,
      requestTimestampMs,
      signatureInputs,
      wasmPath,
      zkeyPath
    );

    const vkey = await loadVerificationKey(vkeyPath);
    const ok = await verifyAgeProofSignedWithIssuer(
      proof,
      vkey,
      signed.issuerPublicKey
    );

    expect(ok).to.equal(true);
  });
});
