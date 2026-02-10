import { expect } from 'chai';
import path from 'path';
import { randomBytes } from 'crypto';
import { generateAgeProofRevocable, generateAgeProofRevocableAuto } from '../src/prover';
import { createCredential } from '../src/credential';
import { verifyAgeProofRevocable, loadVerificationKey } from '../src/verifier';
import { InMemoryValidCredentialTree } from '../src/valid-credential-tree';

describe('Revocable Prover Tests', () => {
  const wasmPath = path.resolve(
    __dirname,
    '../../circuits/build/age-verify-revocable_js/age-verify-revocable.wasm',
  );
  const zkeyPath = path.resolve(__dirname, '../../circuits/build/age-verify-revocable.zkey');
  const vkeyPath = path.resolve(
    __dirname,
    '../../circuits/build/age-verify-revocable_verification_key.json',
  );

  describe('generateAgeProofRevocable', () => {
    it('should generate a valid revocable age proof with Merkle inclusion', async function () {
      this.timeout(15000);

      const credential = await createCredential(1995, 840);
      const tree = new InMemoryValidCredentialTree();

      // Add credential to tree
      await tree.add(credential.commitment);

      // Get witness for Merkle proof
      const witness = await tree.getWitness(credential.commitment);
      if (!witness) {
        throw new Error('Failed to get witness');
      }

      const nonce = BigInt('0x' + randomBytes(31).toString('hex')).toString();
      const requestTimestampMs = Date.now();

      const proof = await generateAgeProofRevocable(
        credential,
        18,
        nonce,
        requestTimestampMs,
        witness,
        wasmPath,
        zkeyPath,
      );

      expect(proof).to.have.property('proof');
      expect(proof).to.have.property('publicSignals');
      expect(proof.publicSignals.minAge).to.equal(18);
      expect(proof.publicSignals.merkleRoot).to.equal(await tree.getRoot());

      const vkey = await loadVerificationKey(vkeyPath);
      const isValid = await verifyAgeProofRevocable(proof, vkey, await tree.getRoot());
      expect(isValid).to.be.true;
    });

    it('should verify proof at different tree positions', async function () {
      this.timeout(15000);

      const tree = new InMemoryValidCredentialTree();

      // Add multiple credentials
      const cred1 = await createCredential(1990, 840);
      const cred2 = await createCredential(1995, 840);
      const cred3 = await createCredential(2000, 840);

      await tree.add(cred1.commitment);
      await tree.add(cred2.commitment);
      await tree.add(cred3.commitment);

      // Generate proof for credential 2
      const witness = await tree.getWitness(cred2.commitment);
      if (!witness) {
        throw new Error('Failed to get witness');
      }

      const nonce = BigInt('0x' + randomBytes(31).toString('hex')).toString();

      const proof = await generateAgeProofRevocable(
        cred2,
        18,
        nonce,
        Date.now(),
        witness,
        wasmPath,
        zkeyPath,
      );

      const vkey = await loadVerificationKey(vkeyPath);
      const isValid = await verifyAgeProofRevocable(proof, vkey, await tree.getRoot());
      expect(isValid).to.be.true;
    });

    it('should include correct public signals including merkleRoot', async function () {
      this.timeout(15000);

      const credential = await createCredential(1995, 840);
      const tree = new InMemoryValidCredentialTree();
      await tree.add(credential.commitment);

      const witness = await tree.getWitness(credential.commitment);
      if (!witness) {
        throw new Error('Failed to get witness');
      }

      const nonce = BigInt('0x' + randomBytes(31).toString('hex')).toString();
      const requestTimestampMs = Date.now();
      const currentYear = new Date().getFullYear();

      const proof = await generateAgeProofRevocable(
        credential,
        21,
        nonce,
        requestTimestampMs,
        witness,
        wasmPath,
        zkeyPath,
      );

      expect(proof.publicSignals.currentYear).to.equal(currentYear);
      expect(proof.publicSignals.minAge).to.equal(21);
      expect(proof.publicSignals.credentialHash).to.equal(credential.commitment);
      expect(proof.publicSignals.nonce).to.equal(nonce);
      expect(proof.publicSignals.requestTimestamp).to.equal(requestTimestampMs);
      expect(proof.publicSignals.merkleRoot).to.equal(await tree.getRoot());
    });

    it('should fail verification with wrong merkle root', async function () {
      this.timeout(15000);

      const credential = await createCredential(1995, 840);
      const tree = new InMemoryValidCredentialTree();
      await tree.add(credential.commitment);

      const witness = await tree.getWitness(credential.commitment);
      if (!witness) {
        throw new Error('Failed to get witness');
      }

      const nonce = BigInt('0x' + randomBytes(31).toString('hex')).toString();

      const proof = await generateAgeProofRevocable(
        credential,
        18,
        nonce,
        Date.now(),
        witness,
        wasmPath,
        zkeyPath,
      );

      const vkey = await loadVerificationKey(vkeyPath);
      const wrongRoot = '12345678901234567890'; // Wrong root

      const isValid = await verifyAgeProofRevocable(proof, vkey, wrongRoot);
      expect(isValid).to.be.false;
    });

    it('should throw error with invalid minAge', async function () {
      this.timeout(10000);

      const credential = await createCredential(1995, 840);
      const tree = new InMemoryValidCredentialTree();
      await tree.add(credential.commitment);

      const witness = await tree.getWitness(credential.commitment);
      if (!witness) {
        throw new Error('Failed to get witness');
      }

      const nonce = BigInt('0x' + randomBytes(31).toString('hex')).toString();

      try {
        await generateAgeProofRevocable(
          credential,
          -1,
          nonce,
          Date.now(),
          witness,
          wasmPath,
          zkeyPath,
        );
        expect.fail('Should have thrown error');
      } catch (error: any) {
        expect(error.message).to.include('minAge');
      }
    });
  });

  describe('generateAgeProofRevocableAuto', () => {
    it('should generate a valid revocable proof using auto path resolution', async function () {
      this.timeout(15000);

      const credential = await createCredential(1995, 840);
      const tree = new InMemoryValidCredentialTree();
      await tree.add(credential.commitment);

      const witness = await tree.getWitness(credential.commitment);
      if (!witness) {
        throw new Error('Failed to get witness');
      }

      const nonce = BigInt('0x' + randomBytes(31).toString('hex')).toString();
      const requestTimestampMs = Date.now();

      const proof = await generateAgeProofRevocableAuto(
        credential,
        18,
        nonce,
        requestTimestampMs,
        witness,
      );

      expect(proof).to.have.property('proof');
      expect(proof).to.have.property('publicSignals');
      expect(proof.publicSignals.minAge).to.equal(18);
      expect(proof.publicSignals.merkleRoot).to.equal(await tree.getRoot());

      const vkey = await loadVerificationKey(vkeyPath);
      const isValid = await verifyAgeProofRevocable(proof, vkey, await tree.getRoot());
      expect(isValid).to.be.true;
    });

    it('should produce same result as manual path version', async function () {
      this.timeout(15000);

      const credential = await createCredential(1995, 840);
      const tree = new InMemoryValidCredentialTree();
      await tree.add(credential.commitment);

      const witness = await tree.getWitness(credential.commitment);
      if (!witness) {
        throw new Error('Failed to get witness');
      }

      const nonce = BigInt('0x' + randomBytes(31).toString('hex')).toString();
      const requestTimestampMs = Date.now();

      const proofAuto = await generateAgeProofRevocableAuto(
        credential,
        18,
        nonce,
        requestTimestampMs,
        witness,
      );

      const proofManual = await generateAgeProofRevocable(
        credential,
        18,
        nonce,
        requestTimestampMs,
        witness,
        wasmPath,
        zkeyPath,
      );

      // Public signals should match
      expect(proofAuto.publicSignals).to.deep.equal(proofManual.publicSignals);
      expect(proofAuto.proofType).to.equal(proofManual.proofType);
    });
  });
});
