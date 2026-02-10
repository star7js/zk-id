import { expect } from 'chai';
import path from 'path';
import { randomBytes } from 'crypto';
import {
  generateAgeProof,
  generateAgeProofAuto,
  generateNationalityProof,
  generateNationalityProofAuto,
} from '../src/prover';
import { createCredential } from '../src/credential';
import { verifyAgeProof, verifyNationalityProof, loadVerificationKey } from '../src/verifier';

describe('Basic Prover Tests', () => {
  const wasmPathAge = path.resolve(
    __dirname,
    '../../circuits/build/age-verify_js/age-verify.wasm'
  );
  const zkeyPathAge = path.resolve(__dirname, '../../circuits/build/age-verify.zkey');
  const vkeyPathAge = path.resolve(
    __dirname,
    '../../circuits/build/age-verify_verification_key.json'
  );

  const wasmPathNationality = path.resolve(
    __dirname,
    '../../circuits/build/nationality-verify_js/nationality-verify.wasm'
  );
  const zkeyPathNationality = path.resolve(
    __dirname,
    '../../circuits/build/nationality-verify.zkey'
  );
  const vkeyPathNationality = path.resolve(
    __dirname,
    '../../circuits/build/nationality-verify_verification_key.json'
  );

  describe('generateAgeProof', () => {
    it('should generate a valid age proof for age >= 18', async function () {
      this.timeout(10000);

      const credential = await createCredential(1995, 840);
      const nonce = BigInt('0x' + randomBytes(31).toString('hex')).toString();
      const requestTimestampMs = Date.now();

      const proof = await generateAgeProof(
        credential,
        18,
        nonce,
        requestTimestampMs,
        wasmPathAge,
        zkeyPathAge
      );

      expect(proof).to.have.property('proof');
      expect(proof).to.have.property('publicSignals');
      expect(proof.publicSignals.minAge).to.equal(18);
      expect(proof.publicSignals.nonce).to.equal(nonce);

      const vkey = await loadVerificationKey(vkeyPathAge);
      const isValid = await verifyAgeProof(proof, vkey);
      expect(isValid).to.be.true;
    });

    it('should generate a valid age proof for age >= 21', async function () {
      this.timeout(10000);

      const credential = await createCredential(1990, 840);
      const nonce = BigInt('0x' + randomBytes(31).toString('hex')).toString();
      const requestTimestampMs = Date.now();

      const proof = await generateAgeProof(
        credential,
        21,
        nonce,
        requestTimestampMs,
        wasmPathAge,
        zkeyPathAge
      );

      expect(proof.publicSignals.minAge).to.equal(21);

      const vkey = await loadVerificationKey(vkeyPathAge);
      const isValid = await verifyAgeProof(proof, vkey);
      expect(isValid).to.be.true;
    });

    it('should generate a valid age proof for age >= 65', async function () {
      this.timeout(10000);

      const credential = await createCredential(1950, 840);
      const nonce = BigInt('0x' + randomBytes(31).toString('hex')).toString();
      const requestTimestampMs = Date.now();

      const proof = await generateAgeProof(
        credential,
        65,
        nonce,
        requestTimestampMs,
        wasmPathAge,
        zkeyPathAge
      );

      expect(proof.publicSignals.minAge).to.equal(65);

      const vkey = await loadVerificationKey(vkeyPathAge);
      const isValid = await verifyAgeProof(proof, vkey);
      expect(isValid).to.be.true;
    });

    it('should include correct public signals in the proof', async function () {
      this.timeout(10000);

      const credential = await createCredential(2000, 840);
      const nonce = BigInt('0x' + randomBytes(31).toString('hex')).toString();
      const requestTimestampMs = Date.now();
      const currentYear = new Date().getFullYear();

      const proof = await generateAgeProof(
        credential,
        18,
        nonce,
        requestTimestampMs,
        wasmPathAge,
        zkeyPathAge
      );

      expect(proof.publicSignals.currentYear).to.equal(currentYear);
      expect(proof.publicSignals.minAge).to.equal(18);
      expect(proof.publicSignals.credentialHash).to.equal(credential.commitment);
      expect(proof.publicSignals.nonce).to.equal(nonce);
      expect(proof.publicSignals.requestTimestamp).to.equal(requestTimestampMs);
    });

    it('should throw error with invalid minAge (negative)', async function () {
      this.timeout(5000);

      const credential = await createCredential(1995, 840);
      const nonce = BigInt('0x' + randomBytes(31).toString('hex')).toString();

      try {
        await generateAgeProof(
          credential,
          -1,
          nonce,
          Date.now(),
          wasmPathAge,
          zkeyPathAge
        );
        expect.fail('Should have thrown error');
      } catch (error: any) {
        expect(error.message).to.include('minAge');
      }
    });

    it('should throw error with invalid minAge (too large)', async function () {
      this.timeout(5000);

      const credential = await createCredential(1995, 840);
      const nonce = BigInt('0x' + randomBytes(31).toString('hex')).toString();

      try {
        await generateAgeProof(
          credential,
          200,
          nonce,
          Date.now(),
          wasmPathAge,
          zkeyPathAge
        );
        expect.fail('Should have thrown error');
      } catch (error: any) {
        expect(error.message).to.include('minAge');
      }
    });

    it('should throw error with empty nonce', async function () {
      this.timeout(5000);

      const credential = await createCredential(1995, 840);

      try {
        await generateAgeProof(credential, 18, '', Date.now(), wasmPathAge, zkeyPathAge);
        expect.fail('Should have thrown error');
      } catch (error: any) {
        expect(error.message).to.include('nonce');
      }
    });

    it('should throw error with invalid circuit path', async function () {
      this.timeout(5000);

      const credential = await createCredential(1995, 840);
      const nonce = BigInt('0x' + randomBytes(31).toString('hex')).toString();

      try {
        await generateAgeProof(
          credential,
          18,
          nonce,
          Date.now(),
          '/invalid/path.wasm',
          zkeyPathAge
        );
        expect.fail('Should have thrown error');
      } catch (error: any) {
        expect(error.message).to.match(/ENOENT|Cannot find|not found/i);
      }
    });
  });

  describe('generateAgeProofAuto', () => {
    it('should generate a valid age proof using auto path resolution', async function () {
      this.timeout(10000);

      const credential = await createCredential(1995, 840);
      const nonce = BigInt('0x' + randomBytes(31).toString('hex')).toString();
      const requestTimestampMs = Date.now();

      const proof = await generateAgeProofAuto(
        credential,
        18,
        nonce,
        requestTimestampMs
      );

      expect(proof).to.have.property('proof');
      expect(proof).to.have.property('publicSignals');
      expect(proof.publicSignals.minAge).to.equal(18);

      const vkey = await loadVerificationKey(vkeyPathAge);
      const isValid = await verifyAgeProof(proof, vkey);
      expect(isValid).to.be.true;
    });

    it('should produce same result as manual path version', async function () {
      this.timeout(10000);

      const credential = await createCredential(1995, 840);
      const nonce = BigInt('0x' + randomBytes(31).toString('hex')).toString();
      const requestTimestampMs = Date.now();

      const proofAuto = await generateAgeProofAuto(
        credential,
        18,
        nonce,
        requestTimestampMs
      );

      const proofManual = await generateAgeProof(
        credential,
        18,
        nonce,
        requestTimestampMs,
        wasmPathAge,
        zkeyPathAge
      );

      // Public signals should match
      expect(proofAuto.publicSignals).to.deep.equal(proofManual.publicSignals);
      expect(proofAuto.proofType).to.equal(proofManual.proofType);
    });
  });

  describe('generateNationalityProof', () => {
    it('should generate a valid nationality proof for USA (840)', async function () {
      this.timeout(10000);

      const credential = await createCredential(1995, 840);
      const nonce = BigInt('0x' + randomBytes(31).toString('hex')).toString();
      const requestTimestampMs = Date.now();

      const proof = await generateNationalityProof(
        credential,
        840,
        nonce,
        requestTimestampMs,
        wasmPathNationality,
        zkeyPathNationality
      );

      expect(proof).to.have.property('proof');
      expect(proof).to.have.property('publicSignals');
      expect(proof.publicSignals.targetNationality).to.equal(840);
      expect(proof.publicSignals.nonce).to.equal(nonce);

      const vkey = await loadVerificationKey(vkeyPathNationality);
      const isValid = await verifyNationalityProof(proof, vkey);
      expect(isValid).to.be.true;
    });

    it('should generate a valid nationality proof for Germany (276)', async function () {
      this.timeout(10000);

      const credential = await createCredential(1995, 276);
      const nonce = BigInt('0x' + randomBytes(31).toString('hex')).toString();
      const requestTimestampMs = Date.now();

      const proof = await generateNationalityProof(
        credential,
        276,
        nonce,
        requestTimestampMs,
        wasmPathNationality,
        zkeyPathNationality
      );

      expect(proof.publicSignals.targetNationality).to.equal(276);

      const vkey = await loadVerificationKey(vkeyPathNationality);
      const isValid = await verifyNationalityProof(proof, vkey);
      expect(isValid).to.be.true;
    });

    it('should include correct public signals in the proof', async function () {
      this.timeout(10000);

      const credential = await createCredential(1995, 840);
      const nonce = BigInt('0x' + randomBytes(31).toString('hex')).toString();
      const requestTimestampMs = Date.now();

      const proof = await generateNationalityProof(
        credential,
        840,
        nonce,
        requestTimestampMs,
        wasmPathNationality,
        zkeyPathNationality
      );

      expect(proof.publicSignals.targetNationality).to.equal(840);
      expect(proof.publicSignals.credentialHash).to.equal(credential.commitment);
      expect(proof.publicSignals.nonce).to.equal(nonce);
      expect(proof.publicSignals.requestTimestamp).to.equal(requestTimestampMs);
    });

    it('should throw error with invalid nationality code', async function () {
      this.timeout(5000);

      const credential = await createCredential(1995, 840);
      const nonce = BigInt('0x' + randomBytes(31).toString('hex')).toString();

      try {
        await generateNationalityProof(
          credential,
          9999,
          nonce,
          Date.now(),
          wasmPathNationality,
          zkeyPathNationality
        );
        expect.fail('Should have thrown error');
      } catch (error: any) {
        expect(error.message).to.include('nationality');
      }
    });
  });

  describe('generateNationalityProofAuto', () => {
    it('should generate a valid nationality proof using auto path resolution', async function () {
      this.timeout(10000);

      const credential = await createCredential(1995, 840);
      const nonce = BigInt('0x' + randomBytes(31).toString('hex')).toString();
      const requestTimestampMs = Date.now();

      const proof = await generateNationalityProofAuto(
        credential,
        840,
        nonce,
        requestTimestampMs
      );

      expect(proof).to.have.property('proof');
      expect(proof).to.have.property('publicSignals');
      expect(proof.publicSignals.targetNationality).to.equal(840);

      const vkey = await loadVerificationKey(vkeyPathNationality);
      const isValid = await verifyNationalityProof(proof, vkey);
      expect(isValid).to.be.true;
    });

    it('should produce same result as manual path version', async function () {
      this.timeout(10000);

      const credential = await createCredential(1995, 840);
      const nonce = BigInt('0x' + randomBytes(31).toString('hex')).toString();
      const requestTimestampMs = Date.now();

      const proofAuto = await generateNationalityProofAuto(
        credential,
        840,
        nonce,
        requestTimestampMs
      );

      const proofManual = await generateNationalityProof(
        credential,
        840,
        nonce,
        requestTimestampMs,
        wasmPathNationality,
        zkeyPathNationality
      );

      // Public signals should match
      expect(proofAuto.publicSignals).to.deep.equal(proofManual.publicSignals);
      expect(proofAuto.proofType).to.equal(proofManual.proofType);
    });
  });
});
