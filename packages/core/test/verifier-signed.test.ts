import { expect } from 'chai';
import {
  verifyAgeProofSignedWithIssuer,
  verifyNationalityProofSignedWithIssuer,
} from '../src/verifier';
import { AgeProofSigned, NationalityProofSigned, VerificationKey } from '../src/types';

const dummyKey: VerificationKey = {
  protocol: 'groth16',
  curve: 'bn128',
  nPublic: 0,
  vk_alpha_1: [],
  vk_beta_2: [],
  vk_gamma_2: [],
  vk_delta_2: [],
  vk_alphabeta_12: [],
  IC: [],
};

describe('Signed Proof Issuer Matching', () => {
  it('should return false if issuer public key bits do not match (age)', async () => {
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
        requestTimestamp: Date.now(),
        issuerPublicKey: ['0', '1'],
      },
    };

    const ok = await verifyAgeProofSignedWithIssuer(proof, dummyKey, ['1', '1']);
    expect(ok).to.equal(false);
  });

  it('should return false if issuer public key bits do not match (nationality)', async () => {
    const proof: NationalityProofSigned = {
      proof: {
        pi_a: [],
        pi_b: [],
        pi_c: [],
        protocol: 'groth16',
        curve: 'bn128',
      },
      publicSignals: {
        targetNationality: 840,
        credentialHash: '123',
        nonce: 'nonce',
        requestTimestamp: Date.now(),
        issuerPublicKey: ['0', '1'],
      },
    };

    const ok = await verifyNationalityProofSignedWithIssuer(proof, dummyKey, ['1', '1']);
    expect(ok).to.equal(false);
  });
});
