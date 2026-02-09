import { expect } from 'chai';
import path from 'path';
import { ZkIdServer, InMemoryChallengeStore } from '../src/server';
import { AgeProof, ProofResponse } from '@zk-id/core';

function makeAgeProof(
  credentialHash: string,
  minAge: number,
  nonce: string,
  requestTimestamp: number
): AgeProof {
  return {
    proofType: 'age',
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
      nonce,
      requestTimestamp,
    },
  };
}

function getVerificationKeyPath(): string {
  return path.resolve(__dirname, '../../circuits/build/age-verify_verification_key.json');
}

describe('ZkIdServer challenge flow', () => {
  it('rejects proofs without issued challenge', async () => {
    const challengeStore = new InMemoryChallengeStore();
    const server = new ZkIdServer({
      verificationKeyPath: getVerificationKeyPath(),
      challengeStore,
      requireSignedCredentials: false,
      verboseErrors: true,
    });

    const requestTimestamp = new Date().toISOString();
    const proofResponse: ProofResponse = {
      credentialId: 'cred-1',
      claimType: 'age',
      proof: makeAgeProof('123', 18, 'nonce-1', Date.parse(requestTimestamp)),
      nonce: 'nonce-1',
      requestTimestamp,
    };

    const result = await server.verifyProof(proofResponse);
    expect(result.verified).to.equal(false);
    expect(result.error).to.equal('Unknown or expired challenge');
  });

  it('consumes issued challenge once', async () => {
    const challengeStore = new InMemoryChallengeStore();
    const server = new ZkIdServer({
      verificationKeyPath: getVerificationKeyPath(),
      challengeStore,
      requireSignedCredentials: false,
      verboseErrors: true,
    });

    const challenge = await server.createChallenge();
    const proofResponse: ProofResponse = {
      credentialId: 'cred-1',
      claimType: 'age',
      proof: makeAgeProof('123', 18, challenge.nonce, Date.parse(challenge.requestTimestamp)),
      nonce: challenge.nonce,
      requestTimestamp: challenge.requestTimestamp,
    };

    const firstAttempt = await server.verifyProof(proofResponse);
    expect(firstAttempt.verified).to.equal(false);
    expect(firstAttempt.error).to.not.equal('Unknown or expired challenge');

    const replayAttempt = await server.verifyProof(proofResponse);
    expect(replayAttempt.verified).to.equal(false);
    expect(replayAttempt.error).to.equal('Unknown or expired challenge');
  });
});
