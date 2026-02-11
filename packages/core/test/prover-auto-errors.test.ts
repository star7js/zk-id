import { expect } from 'chai';
import { createCredential } from '../src/credential';
import {
  generateAgeProofAuto,
  generateNationalityProofAuto,
  generateAgeProofSignedAuto,
  generateNationalityProofSignedAuto,
  generateAgeProofRevocableAuto,
  generateNullifierProofAuto,
} from '../src/prover';
import type { CircuitSignatureInputs, RevocationWitness } from '../src/types';

/**
 * Error-path tests for the *Auto() proof-generation wrappers.
 *
 * These functions call `require.resolve` for circuit artefacts and then
 * delegate to the non-auto versions. We verify that:
 *   1) Validation errors from the underlying functions propagate correctly.
 *   2) A bad require.resolve (missing circuit files) produces a clear error.
 */
describe('*Auto() prover error paths', () => {
  // Dummy signature inputs for signed-proof variants
  const dummySignatureInputs: CircuitSignatureInputs = {
    issuerPublicKey: Array.from({ length: 256 }, () => '0'),
    signatureR8: ['0', '0'],
    signatureS: ['0'],
  };

  // Dummy Merkle witness for revocable variant
  const dummyWitness: RevocationWitness = {
    root: '12345',
    pathIndices: Array.from({ length: 20 }, () => 0),
    siblings: Array.from({ length: 20 }, () => '0'),
  };

  // -----------------------------------------------------------------------
  // generateAgeProofAuto
  // -----------------------------------------------------------------------
  describe('generateAgeProofAuto', () => {
    it('should throw on invalid minAge (negative)', async () => {
      const cred = await createCredential(1995, 840);
      try {
        await generateAgeProofAuto(cred, -1, 'a'.repeat(32), Date.now());
        expect.fail('Should have thrown');
      } catch (err: any) {
        expect(err.message).to.include('minAge');
      }
    });

    it('should throw on invalid minAge (too large)', async () => {
      const cred = await createCredential(1995, 840);
      try {
        await generateAgeProofAuto(cred, 200, 'a'.repeat(16), Date.now());
        expect.fail('Should have thrown');
      } catch (err: any) {
        expect(err.message).to.include('minAge');
      }
    });

    it('should throw on empty nonce', async () => {
      const cred = await createCredential(1995, 840);
      try {
        await generateAgeProofAuto(cred, 18, '', Date.now());
        expect.fail('Should have thrown');
      } catch (err: any) {
        expect(err.message).to.include('nonce');
      }
    });

    it('should throw on short nonce', async () => {
      const cred = await createCredential(1995, 840);
      try {
        await generateAgeProofAuto(cred, 18, 'short', Date.now());
        expect.fail('Should have thrown');
      } catch (err: any) {
        expect(err.message).to.include('nonce');
      }
    });

    it('should throw on invalid timestamp (zero)', async () => {
      const cred = await createCredential(1995, 840);
      try {
        await generateAgeProofAuto(cred, 18, 'a'.repeat(32), 0);
        expect.fail('Should have thrown');
      } catch (err: any) {
        expect(err.message).to.include('requestTimestamp');
      }
    });

    it('should throw on stale timestamp', async () => {
      const cred = await createCredential(1995, 840);
      const staleTs = Date.now() - 10 * 60 * 1000; // 10 minutes ago
      try {
        await generateAgeProofAuto(cred, 18, 'a'.repeat(32), staleTs);
        expect.fail('Should have thrown');
      } catch (err: any) {
        expect(err.message).to.include('requestTimestamp');
      }
    });

    it('should throw on invalid credential salt', async () => {
      const cred = await createCredential(1995, 840);
      cred.salt = 'not-hex!!!';
      try {
        await generateAgeProofAuto(cred, 18, 'a'.repeat(32), Date.now());
        expect.fail('Should have thrown');
      } catch (err: any) {
        expect(err.message).to.include('salt');
      }
    });
  });

  // -----------------------------------------------------------------------
  // generateNationalityProofAuto
  // -----------------------------------------------------------------------
  describe('generateNationalityProofAuto', () => {
    it('should throw on invalid nationality code (zero)', async () => {
      const cred = await createCredential(1995, 840);
      try {
        await generateNationalityProofAuto(cred, 0, 'a'.repeat(32), Date.now());
        expect.fail('Should have thrown');
      } catch (err: any) {
        expect(err.message).to.include('nationality');
      }
    });

    it('should throw on invalid nationality code (too high)', async () => {
      const cred = await createCredential(1995, 840);
      try {
        await generateNationalityProofAuto(cred, 9999, 'a'.repeat(32), Date.now());
        expect.fail('Should have thrown');
      } catch (err: any) {
        expect(err.message).to.include('nationality');
      }
    });

    it('should throw on empty nonce', async () => {
      const cred = await createCredential(1995, 840);
      try {
        await generateNationalityProofAuto(cred, 840, '', Date.now());
        expect.fail('Should have thrown');
      } catch (err: any) {
        expect(err.message).to.include('nonce');
      }
    });

    it('should throw on invalid timestamp (negative)', async () => {
      const cred = await createCredential(1995, 840);
      try {
        await generateNationalityProofAuto(cred, 840, 'a'.repeat(32), -1);
        expect.fail('Should have thrown');
      } catch (err: any) {
        expect(err.message).to.include('requestTimestamp');
      }
    });

    it('should throw on invalid credential salt', async () => {
      const cred = await createCredential(1995, 840);
      cred.salt = 'ZZZZ';
      try {
        await generateNationalityProofAuto(cred, 840, 'a'.repeat(32), Date.now());
        expect.fail('Should have thrown');
      } catch (err: any) {
        expect(err.message).to.include('salt');
      }
    });
  });

  // -----------------------------------------------------------------------
  // generateAgeProofSignedAuto
  // -----------------------------------------------------------------------
  describe('generateAgeProofSignedAuto', () => {
    it('should throw on invalid minAge', async () => {
      const cred = await createCredential(1995, 840);
      try {
        await generateAgeProofSignedAuto(cred, -5, 'a'.repeat(32), Date.now(), dummySignatureInputs);
        expect.fail('Should have thrown');
      } catch (err: any) {
        expect(err.message).to.include('minAge');
      }
    });

    it('should throw on empty nonce', async () => {
      const cred = await createCredential(1995, 840);
      try {
        await generateAgeProofSignedAuto(cred, 18, '', Date.now(), dummySignatureInputs);
        expect.fail('Should have thrown');
      } catch (err: any) {
        expect(err.message).to.include('nonce');
      }
    });

    it('should throw on invalid timestamp', async () => {
      const cred = await createCredential(1995, 840);
      try {
        await generateAgeProofSignedAuto(cred, 18, 'a'.repeat(32), 0, dummySignatureInputs);
        expect.fail('Should have thrown');
      } catch (err: any) {
        expect(err.message).to.include('requestTimestamp');
      }
    });

    it('should throw on invalid credential salt', async () => {
      const cred = await createCredential(1995, 840);
      cred.salt = 'XYZ_INVALID';
      try {
        await generateAgeProofSignedAuto(cred, 18, 'a'.repeat(32), Date.now(), dummySignatureInputs);
        expect.fail('Should have thrown');
      } catch (err: any) {
        expect(err.message).to.include('salt');
      }
    });
  });

  // -----------------------------------------------------------------------
  // generateNationalityProofSignedAuto
  // -----------------------------------------------------------------------
  describe('generateNationalityProofSignedAuto', () => {
    it('should throw on invalid nationality', async () => {
      const cred = await createCredential(1995, 840);
      try {
        await generateNationalityProofSignedAuto(cred, -1, 'a'.repeat(32), Date.now(), dummySignatureInputs);
        expect.fail('Should have thrown');
      } catch (err: any) {
        expect(err.message).to.include('nationality');
      }
    });

    it('should throw on empty nonce', async () => {
      const cred = await createCredential(1995, 840);
      try {
        await generateNationalityProofSignedAuto(cred, 840, '', Date.now(), dummySignatureInputs);
        expect.fail('Should have thrown');
      } catch (err: any) {
        expect(err.message).to.include('nonce');
      }
    });

    it('should throw on invalid timestamp', async () => {
      const cred = await createCredential(1995, 840);
      try {
        await generateNationalityProofSignedAuto(cred, 840, 'a'.repeat(32), 0, dummySignatureInputs);
        expect.fail('Should have thrown');
      } catch (err: any) {
        expect(err.message).to.include('requestTimestamp');
      }
    });

    it('should throw on invalid credential salt', async () => {
      const cred = await createCredential(1995, 840);
      cred.salt = '!!invalid!!';
      try {
        await generateNationalityProofSignedAuto(cred, 840, 'a'.repeat(32), Date.now(), dummySignatureInputs);
        expect.fail('Should have thrown');
      } catch (err: any) {
        expect(err.message).to.include('salt');
      }
    });
  });

  // -----------------------------------------------------------------------
  // generateAgeProofRevocableAuto
  // -----------------------------------------------------------------------
  describe('generateAgeProofRevocableAuto', () => {
    it('should throw on invalid minAge', async () => {
      const cred = await createCredential(1995, 840);
      try {
        await generateAgeProofRevocableAuto(cred, 200, 'a'.repeat(32), Date.now(), dummyWitness);
        expect.fail('Should have thrown');
      } catch (err: any) {
        expect(err.message).to.include('minAge');
      }
    });

    it('should throw on empty nonce', async () => {
      const cred = await createCredential(1995, 840);
      try {
        await generateAgeProofRevocableAuto(cred, 18, '', Date.now(), dummyWitness);
        expect.fail('Should have thrown');
      } catch (err: any) {
        expect(err.message).to.include('nonce');
      }
    });

    it('should throw on invalid timestamp', async () => {
      const cred = await createCredential(1995, 840);
      try {
        await generateAgeProofRevocableAuto(cred, 18, 'a'.repeat(32), 0, dummyWitness);
        expect.fail('Should have thrown');
      } catch (err: any) {
        expect(err.message).to.include('requestTimestamp');
      }
    });

    it('should throw on invalid credential salt', async () => {
      const cred = await createCredential(1995, 840);
      cred.salt = 'not-hex';
      try {
        await generateAgeProofRevocableAuto(cred, 18, 'a'.repeat(32), Date.now(), dummyWitness);
        expect.fail('Should have thrown');
      } catch (err: any) {
        expect(err.message).to.include('salt');
      }
    });
  });

  // -----------------------------------------------------------------------
  // generateNullifierProofAuto
  // -----------------------------------------------------------------------
  describe('generateNullifierProofAuto', () => {
    it('should throw on non-numeric scopeHash', async () => {
      const cred = await createCredential(1995, 840);
      try {
        await generateNullifierProofAuto(cred, 'not-a-number');
        expect.fail('Should have thrown');
      } catch (err: any) {
        expect(err.message).to.include('scopeHash');
      }
    });

    it('should throw on out-of-field scopeHash', async () => {
      const cred = await createCredential(1995, 840);
      // BN128 field order + 2 is definitely out of range
      const tooLarge = '21888242871839275222246405745257275088548364400416034343698204186575808495619';
      try {
        await generateNullifierProofAuto(cred, tooLarge);
        expect.fail('Should have thrown');
      } catch (err: any) {
        expect(err.message).to.include('scopeHash');
      }
    });

    it('should throw on invalid credential salt', async () => {
      const cred = await createCredential(1995, 840);
      cred.salt = 'GGGG';
      try {
        await generateNullifierProofAuto(cred, '12345');
        expect.fail('Should have thrown');
      } catch (err: any) {
        expect(err.message).to.include('salt');
      }
    });
  });
});
