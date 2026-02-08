import { expect } from 'chai';
import { ZkIdServer } from '../src/server';
import { AgeProofSigned } from '@zk-id/core';
import path from 'path';

function getSignedVerificationKeyPath(): string {
  return path.resolve(
    __dirname,
    '../../circuits/build/age-verify-signed_verification_key.json'
  );
}

describe('ZkIdServer - signed proofs', () => {
  it('rejects signed proof when issuer bits do not match trusted issuer', async () => {
    const server = new ZkIdServer({
      verificationKeyPath: getSignedVerificationKeyPath(),
      signedVerificationKeyPath: getSignedVerificationKeyPath(),
      issuerPublicKeyBits: {
        Trusted: ['0', '1'],
      },
    });

    const tsMs = Date.now();
    const proof: AgeProofSigned = {
      proof: {
        pi_a: [],
        pi_b: [],
        pi_c: [],
        protocol: 'groth16',
        curve: 'bn128',
      },
      publicSignals: {
        currentYear: 2026,
        minAge: 18,
        credentialHash: '123',
        nonce: 'nonce',
        requestTimestamp: tsMs,
        issuerPublicKey: ['1', '1'],
      },
    };

    const result = await server.verifySignedProof({
      claimType: 'age',
      issuer: 'Trusted',
      nonce: 'nonce',
      requestTimestamp: new Date(tsMs).toISOString(),
      proof,
    });

    expect(result.verified).to.equal(false);
    expect(result.error).to.equal('Proof verification failed');
  });
});
