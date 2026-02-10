import { expect } from 'chai';
import { strict as assert } from 'assert';
import path from 'path';
import { createCredential } from '../src/credential';
import { generateNullifierProof, generateNullifierProofAuto } from '../src/prover';
import { verifyNullifierProof, loadVerificationKey } from '../src/verifier';
import {
  createNullifierScope,
  computeNullifier,
  InMemoryNullifierStore,
  consumeNullifier,
} from '../src/nullifier';
import { BN128_FIELD_ORDER } from '../src/validation';

describe('Nullifier Prover Tests', () => {
  const wasmPath = path.resolve(
    __dirname,
    '../../circuits/build/nullifier_js/nullifier.wasm'
  );
  const zkeyPath = path.resolve(__dirname, '../../circuits/build/nullifier.zkey');
  const vkeyPath = path.resolve(
    __dirname,
    '../../circuits/build/nullifier_verification_key.json'
  );

  describe('generateNullifierProof', () => {
    it('should generate a valid nullifier proof', async function () {
      this.timeout(15000);

      const credential = await createCredential(1995, 840);
      const scope = await createNullifierScope('election-2026');

      const proof = await generateNullifierProof(
        credential,
        scope.scopeHash,
        wasmPath,
        zkeyPath
      );

      expect(proof).to.have.property('proof');
      expect(proof).to.have.property('publicSignals');
      expect(proof.proofType).to.equal('nullifier');
      expect(proof.publicSignals.credentialHash).to.equal(credential.commitment);
      expect(proof.publicSignals.scopeHash).to.equal(scope.scopeHash);
      expect(proof.publicSignals.nullifier).to.be.a('string');

      const vkey = await loadVerificationKey(vkeyPath);
      const isValid = await verifyNullifierProof(proof, vkey);
      expect(isValid).to.be.true;
    });

    it('should produce deterministic nullifiers for same credential and scope', async function () {
      this.timeout(20000);

      const credential = await createCredential(1995, 840);
      const scope = await createNullifierScope('voting-round-1');

      const proof1 = await generateNullifierProof(
        credential,
        scope.scopeHash,
        wasmPath,
        zkeyPath
      );

      const proof2 = await generateNullifierProof(
        credential,
        scope.scopeHash,
        wasmPath,
        zkeyPath
      );

      expect(proof1.publicSignals.nullifier).to.equal(proof2.publicSignals.nullifier);
      expect(proof1.publicSignals.credentialHash).to.equal(
        proof2.publicSignals.credentialHash
      );
      expect(proof1.publicSignals.scopeHash).to.equal(proof2.publicSignals.scopeHash);
    });

    it('should produce different nullifiers for different scopes', async function () {
      this.timeout(20000);

      const credential = await createCredential(1995, 840);
      const scope1 = await createNullifierScope('election-2026');
      const scope2 = await createNullifierScope('airdrop-round-3');

      const proof1 = await generateNullifierProof(
        credential,
        scope1.scopeHash,
        wasmPath,
        zkeyPath
      );

      const proof2 = await generateNullifierProof(
        credential,
        scope2.scopeHash,
        wasmPath,
        zkeyPath
      );

      expect(proof1.publicSignals.nullifier).to.not.equal(proof2.publicSignals.nullifier);
      expect(proof1.publicSignals.scopeHash).to.not.equal(proof2.publicSignals.scopeHash);
      // But credential hash should be the same
      expect(proof1.publicSignals.credentialHash).to.equal(
        proof2.publicSignals.credentialHash
      );
    });

    it('should produce different nullifiers for different credentials in same scope', async function () {
      this.timeout(20000);

      const cred1 = await createCredential(1995, 840);
      const cred2 = await createCredential(1990, 840);
      const scope = await createNullifierScope('forum-registration');

      const proof1 = await generateNullifierProof(cred1, scope.scopeHash, wasmPath, zkeyPath);
      const proof2 = await generateNullifierProof(cred2, scope.scopeHash, wasmPath, zkeyPath);

      expect(proof1.publicSignals.nullifier).to.not.equal(proof2.publicSignals.nullifier);
      expect(proof1.publicSignals.credentialHash).to.not.equal(
        proof2.publicSignals.credentialHash
      );
      // But scope should be the same
      expect(proof1.publicSignals.scopeHash).to.equal(proof2.publicSignals.scopeHash);
    });

    it('should match nullifier computed with computeNullifier utility', async function () {
      this.timeout(15000);

      const credential = await createCredential(1995, 840);
      const scope = await createNullifierScope('test-scope');

      const proof = await generateNullifierProof(
        credential,
        scope.scopeHash,
        wasmPath,
        zkeyPath
      );

      // Compute nullifier using the utility function
      const computed = await computeNullifier(credential.commitment, scope);

      expect(proof.publicSignals.nullifier).to.equal(computed.nullifier);
    });

    it('should enable sybil detection with nullifier store', async function () {
      this.timeout(15000);

      const credential = await createCredential(1995, 840);
      const scope = await createNullifierScope('voting-2026');
      const store = new InMemoryNullifierStore();

      const proof = await generateNullifierProof(
        credential,
        scope.scopeHash,
        wasmPath,
        zkeyPath
      );

      // First use should be fresh
      const result1 = await consumeNullifier(proof.publicSignals.nullifier, scope.id, store);
      expect(result1.fresh).to.be.true;

      // Second use should be detected as duplicate
      const result2 = await consumeNullifier(proof.publicSignals.nullifier, scope.id, store);
      expect(result2.fresh).to.be.false;
      expect(result2.error).to.include('already used');
    });

    it('should allow same nullifier in different scopes', async function () {
      this.timeout(20000);

      const credential = await createCredential(1995, 840);
      const scope1 = await createNullifierScope('voting-2026');
      const scope2 = await createNullifierScope('airdrop-2026');
      const store = new InMemoryNullifierStore();

      const proof1 = await generateNullifierProof(
        credential,
        scope1.scopeHash,
        wasmPath,
        zkeyPath
      );
      const proof2 = await generateNullifierProof(
        credential,
        scope2.scopeHash,
        wasmPath,
        zkeyPath
      );

      // Use in scope 1
      const result1 = await consumeNullifier(proof1.publicSignals.nullifier, scope1.id, store);
      expect(result1.fresh).to.be.true;

      // Use in scope 2 should also be fresh (different scope)
      const result2 = await consumeNullifier(proof2.publicSignals.nullifier, scope2.id, store);
      expect(result2.fresh).to.be.true;
    });

    it('rejects non-numeric scopeHash', async () => {
      const credential = await createCredential(1990, 840);
      await assert.rejects(
        () => generateNullifierProof(credential, 'not-a-number', 'missing', 'missing'),
        /scopeHash/
      );
    });

    it('rejects out-of-field scopeHash', async () => {
      const credential = await createCredential(1990, 840);
      const tooLarge = (BN128_FIELD_ORDER + 1n).toString();
      await assert.rejects(
        () => generateNullifierProof(credential, tooLarge, 'missing', 'missing'),
        /scopeHash/
      );
    });

    it('should throw error with invalid circuit path', async function () {
      this.timeout(5000);

      const credential = await createCredential(1995, 840);
      const scope = await createNullifierScope('test-scope');

      try {
        await generateNullifierProof(
          credential,
          scope.scopeHash,
          '/invalid/path.wasm',
          zkeyPath
        );
        expect.fail('Should have thrown error');
      } catch (error: any) {
        expect(error.message).to.match(/ENOENT|Cannot find|not found/i);
      }
    });
  });

  describe('generateNullifierProofAuto', () => {
    it('should generate a valid nullifier proof using auto path resolution', async function () {
      this.timeout(15000);

      const credential = await createCredential(1995, 840);
      const scope = await createNullifierScope('auto-test-scope');

      const proof = await generateNullifierProofAuto(credential, scope.scopeHash);

      expect(proof).to.have.property('proof');
      expect(proof).to.have.property('publicSignals');
      expect(proof.proofType).to.equal('nullifier');
      expect(proof.publicSignals.scopeHash).to.equal(scope.scopeHash);

      const vkey = await loadVerificationKey(vkeyPath);
      const isValid = await verifyNullifierProof(proof, vkey);
      expect(isValid).to.be.true;
    });

    it('should produce same result as manual path version', async function () {
      this.timeout(20000);

      const credential = await createCredential(1995, 840);
      const scope = await createNullifierScope('comparison-test');

      const proofAuto = await generateNullifierProofAuto(credential, scope.scopeHash);

      const proofManual = await generateNullifierProof(
        credential,
        scope.scopeHash,
        wasmPath,
        zkeyPath
      );

      // Public signals should match
      expect(proofAuto.publicSignals).to.deep.equal(proofManual.publicSignals);
      expect(proofAuto.proofType).to.equal(proofManual.proofType);
    });

    it('should work with various scope identifiers', async function () {
      this.timeout(20000);

      const credential = await createCredential(1995, 840);
      const scopes = [
        'election-2026',
        'airdrop-round-3',
        'forum-post-2026-01-15',
        'zkp-workshop',
      ];

      for (const scopeId of scopes) {
        const scope = await createNullifierScope(scopeId);
        const proof = await generateNullifierProofAuto(credential, scope.scopeHash);

        expect(proof.publicSignals.scopeHash).to.equal(scope.scopeHash);

        const vkey = await loadVerificationKey(vkeyPath);
        const isValid = await verifyNullifierProof(proof, vkey);
        expect(isValid).to.be.true;
      }
    });
  });
});
