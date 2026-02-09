import { expect } from 'chai';
import { validateProofConstraints, validateNationalityProofConstraints } from '../src/verifier';
import { AgeProof, NationalityProof } from '../src/types';

describe('Verifier Tests', () => {
  describe('validateProofConstraints', () => {
    const createMockProof = (overrides?: Partial<AgeProof>): AgeProof => {
      const currentYear = new Date().getFullYear();
      return {
        proofType: 'age',
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
          nonce: 'nonce-1',
          requestTimestamp: Date.now(),
        },
        ...overrides,
      };
    };

    it('should validate a good proof', () => {
      const proof = createMockProof();
      const result = validateProofConstraints(proof);

      expect(result.valid).to.be.true;
      expect(result.errors).to.have.lengthOf(0);
    });

    it('should reject proof with invalid current year (too old)', () => {
      const proof = createMockProof({
        publicSignals: {
          currentYear: 2010,
          minAge: 18,
          credentialHash: '12345',
          nonce: 'nonce-1',
          requestTimestamp: Date.now(),
        },
      });

      const result = validateProofConstraints(proof);
      expect(result.valid).to.be.false;
      expect(result.errors).to.include('Invalid current year in proof');
    });

    it('should reject proof with invalid current year (future)', () => {
      const futureYear = new Date().getFullYear() + 5;
      const proof = createMockProof({
        publicSignals: {
          currentYear: futureYear,
          minAge: 18,
          credentialHash: '12345',
          nonce: 'nonce-1',
          requestTimestamp: Date.now(),
        },
      });

      const result = validateProofConstraints(proof);
      expect(result.valid).to.be.false;
      expect(result.errors).to.include('Invalid current year in proof');
    });

    it('should reject proof with negative minAge', () => {
      const proof = createMockProof({
        publicSignals: {
          currentYear: new Date().getFullYear(),
          minAge: -1,
          credentialHash: '12345',
          nonce: 'nonce-1',
          requestTimestamp: Date.now(),
        },
      });

      const result = validateProofConstraints(proof);
      expect(result.valid).to.be.false;
      expect(result.errors).to.include('Invalid minimum age requirement');
    });

    it('should reject proof with unreasonably high minAge', () => {
      const proof = createMockProof({
        publicSignals: {
          currentYear: new Date().getFullYear(),
          minAge: 200,
          credentialHash: '12345',
          nonce: 'nonce-1',
          requestTimestamp: Date.now(),
        },
      });

      const result = validateProofConstraints(proof);
      expect(result.valid).to.be.false;
      expect(result.errors).to.include('Invalid minimum age requirement');
    });

    it('should reject proof with missing credential hash', () => {
      const proof = createMockProof({
        publicSignals: {
          currentYear: new Date().getFullYear(),
          minAge: 18,
          credentialHash: '',
          nonce: 'nonce-1',
          requestTimestamp: Date.now(),
        },
      });

      const result = validateProofConstraints(proof);
      expect(result.valid).to.be.false;
      expect(result.errors).to.include('Missing or invalid credential hash');
    });

    it('should reject proof with zero credential hash', () => {
      const proof = createMockProof({
        publicSignals: {
          currentYear: new Date().getFullYear(),
          minAge: 18,
          credentialHash: '0',
          nonce: 'nonce-1',
          requestTimestamp: Date.now(),
        },
      });

      const result = validateProofConstraints(proof);
      expect(result.valid).to.be.false;
      expect(result.errors).to.include('Missing or invalid credential hash');
    });

    it('should validate proof with various valid minAge values', () => {
      const validAges = [13, 16, 18, 21, 65, 100];

      for (const age of validAges) {
        const proof = createMockProof({
          publicSignals: {
          currentYear: new Date().getFullYear(),
          minAge: age,
          credentialHash: '12345',
          nonce: 'nonce-1',
          requestTimestamp: Date.now(),
        },
      });

        const result = validateProofConstraints(proof);
        expect(result.valid).to.be.true;
        expect(result.errors).to.have.lengthOf(0);
      }
    });

    it('should accumulate multiple errors', () => {
      const proof = createMockProof({
        publicSignals: {
          currentYear: 2010,
          minAge: -5,
          credentialHash: '',
          nonce: '',
          requestTimestamp: 0,
        },
      });

      const result = validateProofConstraints(proof);
      expect(result.valid).to.be.false;
      expect(result.errors.length).to.be.greaterThan(1);
    });
  });

  describe('validateNationalityProofConstraints', () => {
    const createMockNationalityProof = (overrides?: Partial<NationalityProof>): NationalityProof => {
      const defaults: NationalityProof = {
        proofType: 'nationality',
        proof: {
          pi_a: ['1', '2'],
          pi_b: [['3', '4'], ['5', '6']],
          pi_c: ['7', '8'],
          protocol: 'groth16',
          curve: 'bn128',
        },
        publicSignals: {
          targetNationality: 840,
          credentialHash: '12345678901234567890',
          nonce: 'nonce-1',
          requestTimestamp: Date.now(),
        },
      };
      return {
        ...defaults,
        ...overrides,
        publicSignals: {
          ...defaults.publicSignals,
          ...overrides?.publicSignals,
        },
      };
    };

    it('should validate a good nationality proof', () => {
      const proof = createMockNationalityProof();
      const result = validateNationalityProofConstraints(proof);

      expect(result.valid).to.be.true;
      expect(result.errors).to.have.lengthOf(0);
    });

    it('should reject proof with invalid nationality code (too low)', () => {
      const proof = createMockNationalityProof({
        publicSignals: {
          targetNationality: 0,
          credentialHash: '12345',
          nonce: 'nonce-1',
          requestTimestamp: Date.now(),
        },
      });

      const result = validateNationalityProofConstraints(proof);
      expect(result.valid).to.be.false;
      expect(result.errors).to.include('Invalid nationality code in proof');
    });

    it('should reject proof with invalid nationality code (too high)', () => {
      const proof = createMockNationalityProof({
        publicSignals: {
          targetNationality: 1000,
          credentialHash: '12345',
          nonce: 'nonce-1',
          requestTimestamp: Date.now(),
        },
      });

      const result = validateNationalityProofConstraints(proof);
      expect(result.valid).to.be.false;
      expect(result.errors).to.include('Invalid nationality code in proof');
    });

    it('should reject proof with missing credential hash', () => {
      const proof = createMockNationalityProof({
        publicSignals: {
          targetNationality: 840,
          credentialHash: '',
          nonce: 'nonce-1',
          requestTimestamp: Date.now(),
        },
      });

      const result = validateNationalityProofConstraints(proof);
      expect(result.valid).to.be.false;
      expect(result.errors).to.include('Missing or invalid credential hash');
    });

    it('should reject proof with zero credential hash', () => {
      const proof = createMockNationalityProof({
        publicSignals: {
          targetNationality: 840,
          credentialHash: '0',
          nonce: 'nonce-1',
          requestTimestamp: Date.now(),
        },
      });

      const result = validateNationalityProofConstraints(proof);
      expect(result.valid).to.be.false;
      expect(result.errors).to.include('Missing or invalid credential hash');
    });

    it('should validate proof with various valid nationality codes', () => {
      const validCodes = [840, 826, 124, 276, 392]; // USA, UK, Canada, Germany, Japan

      for (const code of validCodes) {
        const proof = createMockNationalityProof({
          publicSignals: {
            targetNationality: code,
            credentialHash: '12345',
            nonce: 'nonce-1',
            requestTimestamp: Date.now(),
          },
        });

        const result = validateNationalityProofConstraints(proof);
        expect(result.valid).to.be.true;
        expect(result.errors).to.have.lengthOf(0);
      }
    });

    it('should accumulate multiple errors', () => {
      const proof = createMockNationalityProof({
        publicSignals: {
          targetNationality: 1500,
          credentialHash: '',
          nonce: '',
          requestTimestamp: 0,
        },
      });

      const result = validateNationalityProofConstraints(proof);
      expect(result.valid).to.be.false;
      expect(result.errors.length).to.be.greaterThan(1);
    });
  });
});
