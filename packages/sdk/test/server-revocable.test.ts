import { expect } from 'chai';
import path from 'path';
import { ZkIdServer } from '../src/server';
import { AgeProofRevocable, ProofResponse } from '@zk-id/core';

function makeAgeProofRevocable(
  credentialHash: string,
  merkleRoot: string,
  minAge: number,
  nonce: string,
  requestTimestamp: number
): AgeProofRevocable {
  return {
    proofType: 'age-revocable',
    proof: {
      pi_a: ['1', '2'],
      pi_b: [
        ['3', '4'],
        ['5', '6'],
      ],
      pi_c: ['7', '8'],
      protocol: 'groth16',
      curve: 'bn128',
    },
    publicSignals: {
      currentYear: new Date().getFullYear(),
      minAge,
      credentialHash,
      merkleRoot,
      nonce,
      requestTimestamp,
    },
  };
}

function getVerificationKeyPath(): string {
  return path.resolve(__dirname, '../../circuits/build/age-verify_verification_key.json');
}

describe('ZkIdServer - revocable proof support', () => {
  it('rejects age-revocable proof when verification key not configured', async () => {
    const server = new ZkIdServer({
      verificationKeyPath: getVerificationKeyPath(),
      requireSignedCredentials: false,
      verboseErrors: true,
    });

    const timestamp = Date.now();
    const proofResponse: ProofResponse = {
      credentialId: 'cred-1',
      claimType: 'age-revocable',
      proof: makeAgeProofRevocable('123', '456', 18, 'nonce-1', timestamp),
      nonce: 'nonce-1',
      requestTimestamp: new Date(timestamp).toISOString(),
    } as ProofResponse;

    const result = await server.verifyProof(proofResponse);
    expect(result.verified).to.equal(false);
    expect(result.error).to.equal('Revocable age verification key not configured');
  });

  it('enforces requiredMinAge policy for age-revocable proofs', async () => {
    const server = new ZkIdServer({
      verificationKeyPath: getVerificationKeyPath(),
      requireSignedCredentials: false,
      requiredMinAge: 21,
      verboseErrors: true,
    });

    const timestamp = Date.now();
    const proofResponse: ProofResponse = {
      credentialId: 'cred-1',
      claimType: 'age-revocable',
      proof: makeAgeProofRevocable('123', '456', 18, 'nonce-1', timestamp),
      nonce: 'nonce-1',
      requestTimestamp: new Date(timestamp).toISOString(),
    } as ProofResponse;

    const result = await server.verifyProof(proofResponse);
    expect(result.verified).to.equal(false);
    expect(result.error).to.equal('Proof does not satisfy required minimum age');
  });

  it('extracts nonce and timestamp correctly from revocable proofs', async () => {
    const server = new ZkIdServer({
      verificationKeyPath: getVerificationKeyPath(),
      requireSignedCredentials: false,
      verboseErrors: true,
    });

    const timestamp = Date.now();
    const nonce = 'test-nonce-123';

    const proofResponse: ProofResponse = {
      credentialId: 'cred-1',
      claimType: 'age-revocable',
      proof: makeAgeProofRevocable('123', '456', 18, nonce, timestamp),
      nonce,
      requestTimestamp: new Date(timestamp).toISOString(),
    } as ProofResponse;

    // We expect this to fail with verification key not configured, but it should pass
    // nonce and timestamp validation first
    const result = await server.verifyProof(proofResponse);
    expect(result.error).to.equal('Revocable age verification key not configured');
  });

  it('rejects revocable proof when merkle root does not match expected root', async () => {
    const server = new ZkIdServer({
      verificationKeyPath: getVerificationKeyPath(),
      requireSignedCredentials: false,
      verificationKeys: {
        age: {} as any,
        ageRevocable: {} as any,
      },
      validCredentialTree: {
        add: async () => undefined,
        remove: async () => undefined,
        contains: async () => false,
        getRoot: async () => '0',
        getWitness: async () => null,
        size: async () => 0,
      },
      verboseErrors: true,
    });

    const proofResponse: ProofResponse = {
      credentialId: 'cred-1',
      claimType: 'age-revocable',
      proof: makeAgeProofRevocable('123', '1', 18, 'nonce-1', Date.now()),
      nonce: 'nonce-1',
      requestTimestamp: new Date().toISOString(),
    } as ProofResponse;

    const result = await server.verifyProof(proofResponse);
    expect(result.verified).to.equal(false);
    expect(result.error).to.equal('Proof verification failed');
  });
});
