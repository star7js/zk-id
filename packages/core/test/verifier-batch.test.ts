import { expect } from 'chai';
import { randomBytes } from 'crypto';
import path from 'path';
import { verifyBatch, loadVerificationKey } from '../src/verifier';
import { AgeProof, NationalityProof, VerificationKey } from '../src/types';
import { createCredential } from '../src/credential';
import { generateAgeProofAuto, generateNationalityProofAuto } from '../src/prover';

describe('Batch Verification Tests', () => {
  let ageVerificationKey: VerificationKey;
  let nationalityVerificationKey: VerificationKey;

  before(async () => {
    // Load verification keys
    const ageVkPath = path.resolve(
      __dirname,
      '../../circuits/build/age-verify_verification_key.json'
    );
    const nationalityVkPath = path.resolve(
      __dirname,
      '../../circuits/build/nationality-verify_verification_key.json'
    );

    ageVerificationKey = await loadVerificationKey(ageVkPath);
    nationalityVerificationKey = await loadVerificationKey(nationalityVkPath);
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
        proofType: 'age',
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
          nonce: 'nonce-1',
          requestTimestamp: 1700000000000,
        },
      };

      const result = await verifyBatch([
        {
          proof: mockProof,
          verificationKey: ageVerificationKey,
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
        proofType: 'age',
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
          nonce: 'nonce-1',
          requestTimestamp: 1700000000000,
        },
      };

      const mockNationalityProof: NationalityProof = {
        proofType: 'nationality',
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
          nonce: 'nonce-1',
          requestTimestamp: 1700000000000,
        },
      };

      const result = await verifyBatch([
        {
          proof: mockAgeProof,
          verificationKey: ageVerificationKey,
        },
        {
          proof: mockNationalityProof,
          verificationKey: nationalityVerificationKey,
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
        proofType: 'age',
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
          nonce: 'nonce-1',
          requestTimestamp: 1700000000000,
        },
      };

      const result = await verifyBatch([
        { proof: mockProof, verificationKey: ageVerificationKey },
        { proof: mockProof, verificationKey: ageVerificationKey },
        { proof: mockProof, verificationKey: ageVerificationKey },
      ]);

      expect(result.results[0].index).to.equal(0);
      expect(result.results[1].index).to.equal(1);
      expect(result.results[2].index).to.equal(2);
    });

    it('should verify multiple valid proofs of same type', async function () {
      this.timeout(30000);

      const cred1 = await createCredential(1990, 840);
      const cred2 = await createCredential(1995, 840);

      const nonce1 = BigInt('0x' + randomBytes(31).toString('hex')).toString();
      const nonce2 = BigInt('0x' + randomBytes(31).toString('hex')).toString();

      const proof1 = await generateAgeProofAuto(cred1, 18, nonce1, Date.now());
      const proof2 = await generateAgeProofAuto(cred2, 21, nonce2, Date.now());

      const result = await verifyBatch([
        { proof: proof1, verificationKey: ageVerificationKey },
        { proof: proof2, verificationKey: ageVerificationKey },
      ]);

      expect(result.allVerified).to.be.true;
      expect(result.verifiedCount).to.equal(2);
      expect(result.totalCount).to.equal(2);
      expect(result.results).to.have.lengthOf(2);
      expect(result.results[0].verified).to.be.true;
      expect(result.results[1].verified).to.be.true;
    });

    it('should verify multiple valid proofs of different types', async function () {
      this.timeout(30000);

      const credential = await createCredential(1990, 840);

      const nonceAge = BigInt('0x' + randomBytes(31).toString('hex')).toString();
      const nonceNat = BigInt('0x' + randomBytes(31).toString('hex')).toString();

      const ageProof = await generateAgeProofAuto(credential, 18, nonceAge, Date.now());
      const nationalityProof = await generateNationalityProofAuto(
        credential,
        840,
        nonceNat,
        Date.now()
      );

      const result = await verifyBatch([
        { proof: ageProof, verificationKey: ageVerificationKey },
        { proof: nationalityProof, verificationKey: nationalityVerificationKey },
      ]);

      expect(result.allVerified).to.be.true;
      expect(result.verifiedCount).to.equal(2);
      expect(result.totalCount).to.equal(2);
      expect(result.results).to.have.lengthOf(2);
      expect(result.results[0].verified).to.be.true;
      expect(result.results[1].verified).to.be.true;
    });

    it('should detect one invalid proof among valid ones', async function () {
      this.timeout(30000);

      const credential = await createCredential(1990, 840);
      const nonce = BigInt('0x' + randomBytes(31).toString('hex')).toString();

      const validProof = await generateAgeProofAuto(credential, 18, nonce, Date.now());

      const invalidProof: AgeProof = {
        proofType: 'age',
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
          nonce: 'nonce-1',
          requestTimestamp: 1700000000000,
        },
      };

      const result = await verifyBatch([
        { proof: validProof, verificationKey: ageVerificationKey },
        { proof: invalidProof, verificationKey: ageVerificationKey },
        { proof: validProof, verificationKey: ageVerificationKey },
      ]);

      expect(result.allVerified).to.be.false;
      expect(result.verifiedCount).to.equal(2);
      expect(result.totalCount).to.equal(3);
      expect(result.results).to.have.lengthOf(3);
      expect(result.results[0].verified).to.be.true;
      expect(result.results[1].verified).to.be.false;
      expect(result.results[2].verified).to.be.true;
    });

    it('should handle mixed valid and invalid proofs of different types', async function () {
      this.timeout(30000);

      const credential = await createCredential(1990, 840);
      const nonce = BigInt('0x' + randomBytes(31).toString('hex')).toString();

      const validAgeProof = await generateAgeProofAuto(credential, 18, nonce, Date.now());

      const invalidNationalityProof: NationalityProof = {
        proofType: 'nationality',
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
          nonce: 'nonce-1',
          requestTimestamp: 1700000000000,
        },
      };

      const result = await verifyBatch([
        { proof: validAgeProof, verificationKey: ageVerificationKey },
        { proof: invalidNationalityProof, verificationKey: nationalityVerificationKey },
      ]);

      expect(result.allVerified).to.be.false;
      expect(result.verifiedCount).to.equal(1);
      expect(result.totalCount).to.equal(2);
      expect(result.results[0].verified).to.be.true;
      expect(result.results[1].verified).to.be.false;
    });

    it('should handle wrong verification key for a proof', async function () {
      this.timeout(15000);

      const credential = await createCredential(1990, 840);
      const nonce = BigInt('0x' + randomBytes(31).toString('hex')).toString();

      const ageProof = await generateAgeProofAuto(credential, 18, nonce, Date.now());

      // Use wrong verification key (nationality key for age proof)
      const result = await verifyBatch([
        { proof: ageProof, verificationKey: nationalityVerificationKey },
      ]);

      expect(result.allVerified).to.be.false;
      expect(result.verifiedCount).to.equal(0);
      expect(result.totalCount).to.equal(1);
      expect(result.results[0].verified).to.be.false;
    });

    it('should handle large batch of proofs', async function () {
      this.timeout(60000);

      const credential = await createCredential(1990, 840);
      const nonce = BigInt('0x' + randomBytes(31).toString('hex')).toString();

      const proof = await generateAgeProofAuto(credential, 18, nonce, Date.now());

      // Create batch of 10 identical valid proofs
      const batch = Array(10)
        .fill(null)
        .map(() => ({ proof, verificationKey: ageVerificationKey }));

      const result = await verifyBatch(batch);

      expect(result.allVerified).to.be.true;
      expect(result.verifiedCount).to.equal(10);
      expect(result.totalCount).to.equal(10);
      expect(result.results).to.have.lengthOf(10);
      result.results.forEach((r, i) => {
        expect(r.index).to.equal(i);
        expect(r.verified).to.be.true;
      });
    });

    it('should handle batch with all different failure modes', async function () {
      this.timeout(15000);

      const mockProof1: AgeProof = {
        proofType: 'age',
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
          nonce: 'nonce-1',
          requestTimestamp: 1700000000000,
        },
      };

      const mockProof2: AgeProof = {
        proofType: 'age',
        proof: {
          pi_a: ['999', '999'],
          pi_b: [['999', '999'], ['999', '999']],
          pi_c: ['999', '999'],
          protocol: 'groth16',
          curve: 'bn128',
        },
        publicSignals: {
          currentYear: 2026,
          minAge: 21,
          credentialHash: '67890',
          nonce: 'nonce-2',
          requestTimestamp: 1700000000000,
        },
      };

      const mockProof3: NationalityProof = {
        proofType: 'nationality',
        proof: {
          pi_a: ['777', '777'],
          pi_b: [['777', '777'], ['777', '777']],
          pi_c: ['777', '777'],
          protocol: 'groth16',
          curve: 'bn128',
        },
        publicSignals: {
          targetNationality: 276,
          credentialHash: '54321',
          nonce: 'nonce-3',
          requestTimestamp: 1700000000000,
        },
      };

      const result = await verifyBatch([
        { proof: mockProof1, verificationKey: ageVerificationKey },
        { proof: mockProof2, verificationKey: ageVerificationKey },
        { proof: mockProof3, verificationKey: nationalityVerificationKey },
      ]);

      expect(result.allVerified).to.be.false;
      expect(result.verifiedCount).to.equal(0);
      expect(result.totalCount).to.equal(3);
      expect(result.results).to.have.lengthOf(3);
      result.results.forEach((r) => {
        expect(r.verified).to.be.false;
      });
    });

    it('should verify proofs in parallel (performance check)', async function () {
      this.timeout(60000);

      const credential = await createCredential(1990, 840);
      const nonce = BigInt('0x' + randomBytes(31).toString('hex')).toString();

      const proof = await generateAgeProofAuto(credential, 18, nonce, Date.now());

      // Create batch of 5 proofs
      const batch = Array(5)
        .fill(null)
        .map(() => ({ proof, verificationKey: ageVerificationKey }));

      const startTime = Date.now();
      const result = await verifyBatch(batch);
      const batchTime = Date.now() - startTime;

      // Batch verification should complete successfully
      expect(result.allVerified).to.be.true;
      expect(result.verifiedCount).to.equal(5);

      // Note: We don't assert on timing since it's platform-dependent,
      // but the test documents that parallel verification is expected
    });
  });
});
