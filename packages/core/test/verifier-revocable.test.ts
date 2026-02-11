import { expect } from 'chai';
import { validateAgeProofRevocableConstraints, verifyAgeProofRevocable } from '../src/verifier';
import { AgeProofRevocable, VerificationKey } from '../src/types';

describe('Revocable Verifier Tests', () => {
  describe('validateAgeProofRevocableConstraints', () => {
    const createMockProof = (overrides?: Partial<AgeProofRevocable>): AgeProofRevocable => {
      const currentYear = new Date().getFullYear();
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

    it('should reject proof with non-numeric merkleRoot', () => {
      const proof = createMockProof({
        publicSignals: {
          currentYear: new Date().getFullYear(),
          minAge: 18,
          credentialHash: '12345',
          merkleRoot: 'not-a-bigint',
          nonce: 'nonce-1',
          requestTimestamp: Date.now(),
        },
      });

      const result = validateAgeProofRevocableConstraints(proof);
      expect(result.valid).to.be.false;
      expect(result.errors).to.include('Missing or invalid merkle root');
    });

    it('should reject proof with non-numeric credentialHash', () => {
      const proof = createMockProof({
        publicSignals: {
          currentYear: new Date().getFullYear(),
          minAge: 18,
          credentialHash: 'abc-not-valid',
          merkleRoot: '98765',
          nonce: 'nonce-1',
          requestTimestamp: Date.now(),
        },
      });

      const result = validateAgeProofRevocableConstraints(proof);
      expect(result.valid).to.be.false;
      expect(result.errors).to.include('Missing or invalid credential hash');
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

  describe('verifyAgeProofRevocable', () => {
    const createMockProof = (overrides?: Partial<AgeProofRevocable>): AgeProofRevocable => {
      const currentYear = new Date().getFullYear();
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
          currentYear,
          minAge: 18,
          credentialHash: '12345678901234567890',
          merkleRoot: '1',
          nonce: 'nonce-1',
          requestTimestamp: Date.now(),
        },
        ...overrides,
      };
    };

    it('rejects when expected merkle root mismatches even if expected root is "0"', async () => {
      const proof = createMockProof({
        publicSignals: {
          currentYear: new Date().getFullYear(),
          minAge: 18,
          credentialHash: '12345678901234567890',
          merkleRoot: '1',
          nonce: 'nonce-1',
          requestTimestamp: Date.now(),
        },
      });

      const verified = await verifyAgeProofRevocable(proof, {} as VerificationKey, '0');
      expect(verified).to.equal(false);
    });
  });
});
