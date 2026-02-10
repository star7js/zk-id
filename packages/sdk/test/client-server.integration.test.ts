import { expect } from 'chai';
import { randomBytes } from 'crypto';
import path from 'path';
import {
  createCredential,
  generateAgeProofAuto,
  generateNationalityProofAuto,
  loadVerificationKey,
  ProofResponse,
  SignedCredential,
} from '@zk-id/core';
import { ZkIdServer, InMemoryNonceStore, InMemoryIssuerRegistry } from '../src/server';

/**
 * SDK Server Integration Tests
 *
 * These tests verify server-side verification with real circuit-generated proofs,
 * testing the full validation pipeline including nonce checking, proof verification,
 * and policy enforcement.
 */
describe('SDK Server Integration', () => {
  let server: ZkIdServer;
  let nonceStore: InMemoryNonceStore;
  let issuerRegistry: InMemoryIssuerRegistry;

  before(async () => {
    // Setup server with real verification keys
    const ageVkPath = path.resolve(
      __dirname,
      '../../circuits/build/age-verify_verification_key.json'
    );
    const nationalityVkPath = path.resolve(
      __dirname,
      '../../circuits/build/nationality-verify_verification_key.json'
    );

    const ageVkey = await loadVerificationKey(ageVkPath);
    const nationalityVkey = await loadVerificationKey(nationalityVkPath);

    nonceStore = new InMemoryNonceStore({ ttlMs: 300000 }); // 5 minutes
    issuerRegistry = new InMemoryIssuerRegistry();

    server = new ZkIdServer({
      verificationKeys: {
        age: ageVkey,
        nationality: nationalityVkey,
      },
      nonceStore,
      issuerRegistry,
      requireSignedCredentials: false, // Don't require signatures for integration tests
    });
  });

  after(() => {
    nonceStore.stop();
  });

  describe('Age Proof Verification with Real Proofs', () => {
    it('should verify valid age proof end-to-end', async function () {
      this.timeout(20000);

      const credential = await createCredential(1990, 840);
      const nonce = BigInt('0x' + randomBytes(31).toString('hex')).toString();
      const requestTimestamp = Date.now();

      const proof = await generateAgeProofAuto(credential, 18, nonce, requestTimestamp);

      const signedCredential: SignedCredential = {
        credential,
        issuer: 'TestIssuer',
        signature: 'test-signature',
        issuedAt: new Date().toISOString(),
      };

      const proofResponse: ProofResponse = {
        credentialId: credential.id,
        claimType: 'age',
        proof,
        signedCredential,
        nonce,
        requestTimestamp: new Date(requestTimestamp).toISOString(),
      };

      const result = await server.verifyProof(proofResponse);

      expect(result.verified).to.be.true;
      expect(result.claimType).to.equal('age');
      expect(result.minAge).to.equal(18);
    });

    it('should reject proof with invalid minAge', async function () {
      this.timeout(20000);

      const credential = await createCredential(2010, 840); // 16 years old
      const nonce = BigInt('0x' + randomBytes(31).toString('hex')).toString();
      const requestTimestamp = Date.now();

      try {
        // Try to prove age >= 18 (should fail in circuit)
        await generateAgeProofAuto(credential, 18, nonce, requestTimestamp);
        expect.fail('Should have thrown error');
      } catch (error: any) {
        // Circuit should reject invalid age constraint
        expect(error.message).to.match(/constraint|age|assert/i);
      }
    });

    it('should verify multiple age thresholds for same credential', async function () {
      this.timeout(30000);

      const credential = await createCredential(1970, 840); // 56 years old

      // Prove age >= 18
      const nonce1 = BigInt('0x' + randomBytes(31).toString('hex')).toString();
      const timestamp1 = Date.now();
      const proof1 = await generateAgeProofAuto(credential, 18, nonce1, timestamp1);
      const response1: ProofResponse = {
        credentialId: credential.id,
        claimType: 'age',
        proof: proof1,
        signedCredential: {
          credential,
          issuer: 'TestIssuer',
          signature: 'test-sig',
          issuedAt: new Date().toISOString(),
        },
        nonce: nonce1,
        requestTimestamp: new Date(timestamp1).toISOString(),
      };

      const result1 = await server.verifyProof(response1);
      expect(result1.verified).to.be.true;
      expect(result1.minAge).to.equal(18);

      // Prove age >= 21
      const nonce2 = BigInt('0x' + randomBytes(31).toString('hex')).toString();
      const timestamp2 = Date.now();
      const proof2 = await generateAgeProofAuto(credential, 21, nonce2, timestamp2);
      const response2: ProofResponse = {
        credentialId: credential.id,
        claimType: 'age',
        proof: proof2,
        signedCredential: {
          credential,
          issuer: 'TestIssuer',
          signature: 'test-sig',
          issuedAt: new Date().toISOString(),
        },
        nonce: nonce2,
        requestTimestamp: new Date(timestamp2).toISOString(),
      };

      const result2 = await server.verifyProof(response2);
      expect(result2.verified).to.be.true;
      expect(result2.minAge).to.equal(21);

      // Prove age >= 50 (realistic for 56-year-old)
      const nonce3 = BigInt('0x' + randomBytes(31).toString('hex')).toString();
      const timestamp3 = Date.now();
      const proof3 = await generateAgeProofAuto(credential, 50, nonce3, timestamp3);
      const response3: ProofResponse = {
        credentialId: credential.id,
        claimType: 'age',
        proof: proof3,
        signedCredential: {
          credential,
          issuer: 'TestIssuer',
          signature: 'test-sig',
          issuedAt: new Date().toISOString(),
        },
        nonce: nonce3,
        requestTimestamp: new Date(timestamp3).toISOString(),
      };

      const result3 = await server.verifyProof(response3);
      expect(result3.verified).to.be.true;
      expect(result3.minAge).to.equal(50);

      // All should have same commitment
      expect(proof1.publicSignals.credentialHash).to.equal(
        proof2.publicSignals.credentialHash
      );
      expect(proof2.publicSignals.credentialHash).to.equal(
        proof3.publicSignals.credentialHash
      );
    });
  });

  describe('Nationality Proof Verification with Real Proofs', () => {
    it('should verify valid nationality proof end-to-end', async function () {
      this.timeout(20000);

      const credential = await createCredential(1990, 840); // USA
      const nonce = BigInt('0x' + randomBytes(31).toString('hex')).toString();
      const requestTimestamp = Date.now();

      const proof = await generateNationalityProofAuto(
        credential,
        840,
        nonce,
        requestTimestamp
      );

      const proofResponse: ProofResponse = {
        credentialId: credential.id,
        claimType: 'nationality',
        proof,
        signedCredential: {
          credential,
          issuer: 'TestIssuer',
          signature: 'test-signature',
          issuedAt: new Date().toISOString(),
        },
        nonce,
        requestTimestamp: new Date(requestTimestamp).toISOString(),
      };

      const result = await server.verifyProof(proofResponse);

      expect(result.verified).to.be.true;
      expect(result.claimType).to.equal('nationality');
      expect(result.targetNationality).to.equal(840);
    });

    it('should reject proof with wrong nationality', async function () {
      this.timeout(20000);

      const credential = await createCredential(1990, 840); // USA
      const nonce = BigInt('0x' + randomBytes(31).toString('hex')).toString();
      const requestTimestamp = Date.now();

      try {
        // Try to prove Germany (276) when user is USA (840)
        await generateNationalityProofAuto(credential, 276, nonce, requestTimestamp);
        expect.fail('Should have thrown error');
      } catch (error: any) {
        // Circuit should reject invalid nationality constraint
        expect(error.message).to.match(/constraint|nationality|assert/i);
      }
    });
  });

  describe('Nonce Replay Protection', () => {
    it('should reject reused nonce', async function () {
      this.timeout(20000);

      const credential = await createCredential(1990, 840);
      const nonce = BigInt('0x' + randomBytes(31).toString('hex')).toString();
      const requestTimestamp = Date.now();

      const proof = await generateAgeProofAuto(credential, 18, nonce, requestTimestamp);

      const proofResponse: ProofResponse = {
        credentialId: credential.id,
        claimType: 'age',
        proof,
        signedCredential: {
          credential,
          issuer: 'TestIssuer',
          signature: 'test-signature',
          issuedAt: new Date().toISOString(),
        },
        nonce,
        requestTimestamp: new Date(requestTimestamp).toISOString(),
      };

      // First verification should succeed
      const result1 = await server.verifyProof(proofResponse);
      expect(result1.verified).to.be.true;

      // Second verification with same nonce should fail
      const result2 = await server.verifyProof(proofResponse);
      expect(result2.verified).to.be.false;
      expect(result2.error).to.match(/nonce|already used|replay|expired|invalid/i);
    });

    it('should allow different nonces for same credential', async function () {
      this.timeout(30000);

      const credential = await createCredential(1990, 840);

      // First proof with nonce1
      const nonce1 = BigInt('0x' + randomBytes(31).toString('hex')).toString();
      const timestamp1 = Date.now();
      const proof1 = await generateAgeProofAuto(credential, 18, nonce1, timestamp1);
      const response1: ProofResponse = {
        credentialId: credential.id,
        claimType: 'age',
        proof: proof1,
        signedCredential: {
          credential,
          issuer: 'TestIssuer',
          signature: 'test-sig',
          issuedAt: new Date().toISOString(),
        },
        nonce: nonce1,
        requestTimestamp: new Date(timestamp1).toISOString(),
      };

      const result1 = await server.verifyProof(response1);
      expect(result1.verified).to.be.true;

      // Second proof with nonce2 (should also succeed)
      const nonce2 = BigInt('0x' + randomBytes(31).toString('hex')).toString();
      const timestamp2 = Date.now();
      const proof2 = await generateAgeProofAuto(credential, 18, nonce2, timestamp2);
      const response2: ProofResponse = {
        credentialId: credential.id,
        claimType: 'age',
        proof: proof2,
        signedCredential: {
          credential,
          issuer: 'TestIssuer',
          signature: 'test-sig',
          issuedAt: new Date().toISOString(),
        },
        nonce: nonce2,
        requestTimestamp: new Date(timestamp2).toISOString(),
      };

      const result2 = await server.verifyProof(response2);
      expect(result2.verified).to.be.true;
    });
  });

  describe('Challenge Flow', () => {
    it('should create challenge and verify proof with challenge nonce', async function () {
      this.timeout(20000);

      // 1. Server creates challenge
      const challenge = await server.createChallenge();

      expect(challenge).to.have.property('nonce');
      expect(challenge).to.have.property('requestTimestamp');
      expect(challenge.nonce).to.be.a('string');
      expect(challenge.nonce.length).to.be.greaterThan(32);

      // 2. Client generates proof using challenge nonce
      const credential = await createCredential(1990, 840);
      const proof = await generateAgeProofAuto(
        credential,
        18,
        challenge.nonce,
        new Date(challenge.requestTimestamp).getTime()
      );

      // 3. Server verifies proof with challenge nonce
      const proofResponse: ProofResponse = {
        credentialId: credential.id,
        claimType: 'age',
        proof,
        signedCredential: {
          credential,
          issuer: 'TestIssuer',
          signature: 'test-signature',
          issuedAt: new Date().toISOString(),
        },
        nonce: challenge.nonce,
        requestTimestamp: challenge.requestTimestamp,
      };

      const result = await server.verifyProof(proofResponse);

      expect(result.verified).to.be.true;
    });
  });

  describe('Error Handling', () => {
    it('should reject proof with expired timestamp', async function () {
      this.timeout(15000);

      const credential = await createCredential(1990, 840);
      const nonce = BigInt('0x' + randomBytes(31).toString('hex')).toString();
      const validTimestamp = Date.now();

      // Generate proof with valid timestamp
      const proof = await generateAgeProofAuto(credential, 18, nonce, validTimestamp);

      // But submit it with an expired requestTimestamp
      const expiredTimestamp = new Date(Date.now() - 10 * 60 * 1000).toISOString();

      const proofResponse: ProofResponse = {
        credentialId: credential.id,
        claimType: 'age',
        proof,
        signedCredential: {
          credential,
          issuer: 'TestIssuer',
          signature: 'test-signature',
          issuedAt: new Date().toISOString(),
        },
        nonce,
        requestTimestamp: expiredTimestamp, // Expired timestamp in request
      };

      const result = await server.verifyProof(proofResponse);

      expect(result.verified).to.be.false;
      expect(result.error).to.match(/timestamp|expired|too old/i);
    });

    it('should handle malformed proof gracefully', async function () {
      this.timeout(5000);

      const credential = await createCredential(1990, 840);

      // Create a malformed proof response
      const proofResponse: any = {
        credentialId: credential.id,
        claimType: 'age',
        proof: {
          proofType: 'age',
          proof: {
            pi_a: ['invalid', 'data'],
            pi_b: [['1', '2'], ['3', '4']],
            pi_c: ['5', '6'],
          },
          publicSignals: {
            currentYear: 2026,
            minAge: 18,
            credentialHash: 'invalid',
            nonce: 'test-nonce',
            requestTimestamp: Date.now(),
          },
        },
        signedCredential: {
          credential,
          issuer: 'TestIssuer',
          signature: 'test-sig',
          issuedAt: new Date().toISOString(),
        },
        nonce: 'test-nonce',
        requestTimestamp: new Date().toISOString(),
      };

      const result = await server.verifyProof(proofResponse);

      expect(result.verified).to.be.false;
      expect(result.error).to.exist;
    });
  });

  describe('Mixed Proof Types', () => {
    it('should verify both age and nationality proofs for same credential', async function () {
      this.timeout(30000);

      const credential = await createCredential(1990, 840);

      // Generate age proof
      const nonceAge = BigInt('0x' + randomBytes(31).toString('hex')).toString();
      const timestampAge = Date.now();
      const ageProof = await generateAgeProofAuto(credential, 21, nonceAge, timestampAge);
      const ageResponse: ProofResponse = {
        credentialId: credential.id,
        claimType: 'age',
        proof: ageProof,
        signedCredential: {
          credential,
          issuer: 'TestIssuer',
          signature: 'test-sig',
          issuedAt: new Date().toISOString(),
        },
        nonce: nonceAge,
        requestTimestamp: new Date(timestampAge).toISOString(),
      };

      // Generate nationality proof
      const nonceNat = BigInt('0x' + randomBytes(31).toString('hex')).toString();
      const timestampNat = Date.now();
      const natProof = await generateNationalityProofAuto(
        credential,
        840,
        nonceNat,
        timestampNat
      );
      const natResponse: ProofResponse = {
        credentialId: credential.id,
        claimType: 'nationality',
        proof: natProof,
        signedCredential: {
          credential,
          issuer: 'TestIssuer',
          signature: 'test-sig',
          issuedAt: new Date().toISOString(),
        },
        nonce: nonceNat,
        requestTimestamp: new Date(timestampNat).toISOString(),
      };

      // Verify both proofs
      const ageResult = await server.verifyProof(ageResponse);
      const natResult = await server.verifyProof(natResponse);

      expect(ageResult.verified).to.be.true;
      expect(ageResult.minAge).to.equal(21);

      expect(natResult.verified).to.be.true;
      expect(natResult.targetNationality).to.equal(840);

      // Both proofs should share same commitment
      expect(ageProof.publicSignals.credentialHash).to.equal(
        natProof.publicSignals.credentialHash
      );
    });
  });
});
