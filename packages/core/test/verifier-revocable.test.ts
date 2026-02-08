import { expect } from 'chai';
import { validateAgeProofRevocableConstraints } from '../src/verifier';
import { AgeProofRevocable } from '../src/types';

describe('Revocable Verifier Tests', () => {
  describe('validateAgeProofRevocableConstraints', () => {
    const createMockProof = (overrides?: Partial<AgeProofRevocable>): AgeProofRevocable => {
      const currentYear = new Date().getFullYear();
      return {
        proof: {
          pi_a: ['1', '2'],
          pi_b: [['3', '4'], ['5', '6']],
          pi_c: ['7', '8'],
          protocol: 'groth16',
          curve: 'bn128',
        },
        publicSignals: {
          currentYear,
          minAge: 18,
          credentialHash: '12345678901234567890',
          merkleRoot: '98765432109876543210',
          nonce: 'nonce-1',
          requestTimestamp: Date.now(),
        },
        ...overrides,
      };
    };

    it('should validate a good proof', () => {
      const proof = createMockProof();
      const result = validateAgeProofRevocableConstraints(proof);

      expect(result.valid).to.be.true;
      expect(result.errors).to.have.lengthOf(0);
    });

    it('should reject proof with missing merkleRoot', () => {
      const proof = createMockProof({
        publicSignals: {
          currentYear: new Date().getFullYear(),
          minAge: 18,
          credentialHash: '12345',
          merkleRoot: '',
          nonce: 'nonce-1',
          requestTimestamp: Date.now(),
        },
      });

      const result = validateAgeProofRevocableConstraints(proof);
      expect(result.valid).to.be.false;
      expect(result.errors).to.include('Missing or invalid merkle root');
    });

    it('should reject proof with zero merkleRoot', () => {
      const proof = createMockProof({
        publicSignals: {
          currentYear: new Date().getFullYear(),
          minAge: 18,
          credentialHash: '12345',
          merkleRoot: '0',
          nonce: 'nonce-1',
          requestTimestamp: Date.now(),
        },
      });

      const result = validateAgeProofRevocableConstraints(proof);
      expect(result.valid).to.be.false;
      expect(result.errors).to.include('Missing or invalid merkle root');
    });

    it('should reject proof with invalid currentYear', () => {
      const proof = createMockProof({
        publicSignals: {
          currentYear: 2010,
          minAge: 18,
          credentialHash: '12345',
          merkleRoot: '98765',
          nonce: 'nonce-1',
          requestTimestamp: Date.now(),
        },
      });

      const result = validateAgeProofRevocableConstraints(proof);
      expect(result.valid).to.be.false;
      expect(result.errors).to.include('Invalid current year in proof');
    });

    it('should accumulate multiple errors', () => {
      const proof = createMockProof({
        publicSignals: {
          currentYear: 2010,
          minAge: -5,
          credentialHash: '',
          merkleRoot: '0',
          nonce: '',
          requestTimestamp: 0,
        },
      });

      const result = validateAgeProofRevocableConstraints(proof);
      expect(result.valid).to.be.false;
      expect(result.errors.length).to.be.greaterThan(1);
    });
  });
});
