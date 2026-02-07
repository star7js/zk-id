import { expect } from 'chai';
import { verifyBatch } from '../src/verifier';
import { AgeProof, NationalityProof, VerificationKey } from '../src/types';
import { readFileSync } from 'fs';
import { join } from 'path';

describe('Batch Verification Tests', () => {
  let ageVerificationKey: VerificationKey;
  let nationalityVerificationKey: VerificationKey;

  before(() => {
    // Load verification keys
    const ageVkPath = join(__dirname, '../../circuits/build/age-verify_verification_key.json');
    const nationalityVkPath = join(__dirname, '../../circuits/build/nationality-verify_verification_key.json');

    ageVerificationKey = JSON.parse(readFileSync(ageVkPath, 'utf8'));
    nationalityVerificationKey = JSON.parse(readFileSync(nationalityVkPath, 'utf8'));
  });

  describe('verifyBatch', () => {
    it('should handle empty array', async () => {
      const result = await verifyBatch([]);

      expect(result.results).to.deep.equal([]);
      expect(result.allVerified).to.be.true;
      expect(result.verifiedCount).to.equal(0);
      expect(result.totalCount).to.equal(0);
    });

    it('should return correct result structure', async () => {
      // Create a mock invalid proof
      const mockProof: AgeProof = {
        proof: {
          pi_a: ['1', '1'],
          pi_b: [['1', '1'], ['1', '1']],
          pi_c: ['1', '1'],
          protocol: 'groth16',
          curve: 'bn128',
        },
        publicSignals: {
          currentYear: 2026,
          minAge: 18,
          credentialHash: '12345',
        },
      };

      const result = await verifyBatch([
        {
          proof: mockProof,
          verificationKey: ageVerificationKey,
          type: 'age',
        },
      ]);

      expect(result).to.have.property('results');
      expect(result).to.have.property('allVerified');
      expect(result).to.have.property('verifiedCount');
      expect(result).to.have.property('totalCount');

      expect(result.results).to.be.an('array');
      expect(result.results.length).to.equal(1);
      expect(result.results[0]).to.have.property('index', 0);
      expect(result.results[0]).to.have.property('verified');
      expect(result.totalCount).to.equal(1);
    });

    it('should verify multiple invalid proofs and report all as failed', async () => {
      const mockAgeProof: AgeProof = {
        proof: {
          pi_a: ['1', '1'],
          pi_b: [['1', '1'], ['1', '1']],
          pi_c: ['1', '1'],
          protocol: 'groth16',
          curve: 'bn128',
        },
        publicSignals: {
          currentYear: 2026,
          minAge: 18,
          credentialHash: '12345',
        },
      };

      const mockNationalityProof: NationalityProof = {
        proof: {
          pi_a: ['1', '1'],
          pi_b: [['1', '1'], ['1', '1']],
          pi_c: ['1', '1'],
          protocol: 'groth16',
          curve: 'bn128',
        },
        publicSignals: {
          targetNationality: 840,
          credentialHash: '12345',
        },
      };

      const result = await verifyBatch([
        {
          proof: mockAgeProof,
          verificationKey: ageVerificationKey,
          type: 'age',
        },
        {
          proof: mockNationalityProof,
          verificationKey: nationalityVerificationKey,
          type: 'nationality',
        },
      ]);

      expect(result.allVerified).to.be.false;
      expect(result.verifiedCount).to.equal(0);
      expect(result.totalCount).to.equal(2);
      expect(result.results).to.have.lengthOf(2);
      expect(result.results[0].verified).to.be.false;
      expect(result.results[1].verified).to.be.false;
    });

    it('should include index in results', async () => {
      const mockProof: AgeProof = {
        proof: {
          pi_a: ['1', '1'],
          pi_b: [['1', '1'], ['1', '1']],
          pi_c: ['1', '1'],
          protocol: 'groth16',
          curve: 'bn128',
        },
        publicSignals: {
          currentYear: 2026,
          minAge: 18,
          credentialHash: '12345',
        },
      };

      const result = await verifyBatch([
        { proof: mockProof, verificationKey: ageVerificationKey, type: 'age' },
        { proof: mockProof, verificationKey: ageVerificationKey, type: 'age' },
        { proof: mockProof, verificationKey: ageVerificationKey, type: 'age' },
      ]);

      expect(result.results[0].index).to.equal(0);
      expect(result.results[1].index).to.equal(1);
      expect(result.results[2].index).to.equal(2);
    });
  });
});
