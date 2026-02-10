import { expect } from 'chai';
import {
  deriveBBSDisclosureProof,
  verifyBBSDisclosureProof,
  verifyBBSSignature,
  getDisclosedFields,
  InMemoryAuditLogger,
} from '@zk-id/core';
import { BBSCredentialIssuer } from '../src/bbs-issuer';

describe('BBSCredentialIssuer', () => {
  let issuer: BBSCredentialIssuer;
  let auditLogger: InMemoryAuditLogger;

  before(async () => {
    auditLogger = new InMemoryAuditLogger();
    issuer = await BBSCredentialIssuer.create({
      name: 'Test BBS Authority',
      auditLogger,
    });
  });

  describe('create', () => {
    it('should create an issuer with generated keys', () => {
      expect(issuer.getIssuerName()).to.equal('Test BBS Authority');
      expect(issuer.getPublicKey()).to.be.instanceOf(Uint8Array);
      expect(issuer.getPublicKey().length).to.be.greaterThan(0);
    });
  });

  describe('issueCredential', () => {
    it('should issue a BBS-signed credential', async () => {
      const cred = await issuer.issueCredential(1990, 840);

      expect(cred.id).to.be.a('string');
      expect(cred.messages).to.have.length(6);
      expect(cred.signature).to.be.instanceOf(Uint8Array);
      expect(cred.issuerPublicKey).to.deep.equal(issuer.getPublicKey());
      expect(cred.fieldValues.birthYear).to.equal(1990);
      expect(cred.fieldValues.nationality).to.equal(840);
      expect(cred.fieldValues.issuer).to.equal('Test BBS Authority');
    });

    it('should produce a valid BBS signature', async () => {
      const cred = await issuer.issueCredential(1985, 276);

      const valid = await verifyBBSSignature(
        cred.issuerPublicKey,
        cred.signature,
        cred.messages,
        cred.header,
      );
      expect(valid).to.be.true;
    });

    it('should log issuance to audit logger', async () => {
      auditLogger.clear();
      await issuer.issueCredential(2000, 392, 'user-42');

      const entries = auditLogger.filter('issue');
      expect(entries).to.have.length(1);
      expect(entries[0].actor).to.equal('Test BBS Authority');
      expect(entries[0].success).to.be.true;
      expect(entries[0].metadata!.userId).to.equal('user-42');
      expect(entries[0].metadata!.signatureScheme).to.equal('BBS-BLS12-381-SHA-256');
    });
  });

  describe('End-to-end selective disclosure', () => {
    it('should enable holder to selectively disclose nationality', async () => {
      const cred = await issuer.issueCredential(1990, 840);

      // Holder derives proof revealing only nationality
      const proof = await deriveBBSDisclosureProof(cred, {
        disclose: ['nationality'],
      });

      // Verifier checks the proof
      const valid = await verifyBBSDisclosureProof(proof);
      expect(valid).to.be.true;

      // Verifier sees only nationality
      const fields = getDisclosedFields(proof);
      expect(fields).to.have.property('nationality', '840');
      expect(fields).to.not.have.property('birthYear');
      expect(fields).to.not.have.property('salt');
      expect(fields).to.not.have.property('id');
    });

    it('should enable holder to disclose id and issuer', async () => {
      const cred = await issuer.issueCredential(1975, 826);

      const proof = await deriveBBSDisclosureProof(cred, {
        disclose: ['id', 'issuer'],
        nonce: 'verifier-session-xyz',
      });

      const valid = await verifyBBSDisclosureProof(proof);
      expect(valid).to.be.true;

      const fields = getDisclosedFields(proof);
      expect(fields).to.have.property('id');
      expect(fields).to.have.property('issuer', 'Test BBS Authority');
      expect(Object.keys(fields)).to.have.length(2);
    });

    it('should reject proof verified against wrong issuer key', async () => {
      const cred = await issuer.issueCredential(1990, 840);

      const proof = await deriveBBSDisclosureProof(cred, {
        disclose: ['nationality'],
      });

      // Create a different issuer with different keys
      const otherIssuer = await BBSCredentialIssuer.create({
        name: 'Other Authority',
      });

      // Swap the public key in the proof
      proof.issuerPublicKey = otherIssuer.getPublicKey();

      const valid = await verifyBBSDisclosureProof(proof);
      expect(valid).to.be.false;
    });

    it('should enable disclosing multiple fields', async () => {
      const cred = await issuer.issueCredential(1995, 840);

      const proof = await deriveBBSDisclosureProof(cred, {
        disclose: ['birthYear', 'nationality', 'issuer'],
      });

      const valid = await verifyBBSDisclosureProof(proof);
      expect(valid).to.be.true;

      const fields = getDisclosedFields(proof);
      expect(fields).to.have.property('birthYear', '1995');
      expect(fields).to.have.property('nationality', '840');
      expect(fields).to.have.property('issuer', 'Test BBS Authority');
      expect(fields).to.not.have.property('salt');
      expect(fields).to.not.have.property('id');
    });

    it('should handle nonce in proofs', async () => {
      const cred = await issuer.issueCredential(1990, 840);

      const nonce1 = 'session-123';
      const nonce2 = 'session-456';

      const proof1 = await deriveBBSDisclosureProof(cred, {
        disclose: ['nationality'],
        nonce: nonce1,
      });

      const proof2 = await deriveBBSDisclosureProof(cred, {
        disclose: ['nationality'],
        nonce: nonce2,
      });

      // Different nonces produce different proofs
      expect(proof1.proof).to.not.deep.equal(proof2.proof);

      // But both verify successfully
      expect(await verifyBBSDisclosureProof(proof1)).to.be.true;
      expect(await verifyBBSDisclosureProof(proof2)).to.be.true;
    });

    it('should reject proof with tampered disclosed data', async () => {
      const cred = await issuer.issueCredential(1990, 840);

      const proof = await deriveBBSDisclosureProof(cred, {
        disclose: ['nationality'],
      });

      // Tamper with disclosed message
      if (proof.disclosedMessages && proof.disclosedMessages.size > 0) {
        const firstIndex = Array.from(proof.disclosedMessages.keys())[0];
        proof.disclosedMessages.set(firstIndex, new Uint8Array([1, 2, 3]));

        const valid = await verifyBBSDisclosureProof(proof);
        expect(valid).to.be.false;
      }
    });

    it('should reject empty disclosure list', async () => {
      const cred = await issuer.issueCredential(1990, 840);

      // Empty disclosure is not supported - at least one field must be disclosed
      try {
        await deriveBBSDisclosureProof(cred, {
          disclose: [],
        });
        expect.fail('Should have thrown');
      } catch (error: any) {
        expect(error.message).to.match(/No valid fields/i);
      }
    });

    it('should handle disclosing all fields', async () => {
      const cred = await issuer.issueCredential(1995, 840);

      const proof = await deriveBBSDisclosureProof(cred, {
        disclose: ['id', 'birthYear', 'nationality', 'salt', 'issuedAt', 'issuer'],
      });

      const valid = await verifyBBSDisclosureProof(proof);
      expect(valid).to.be.true;

      const fields = getDisclosedFields(proof);
      expect(fields).to.have.property('birthYear', '1995');
      expect(fields).to.have.property('nationality', '840');
      expect(fields).to.have.property('issuer', 'Test BBS Authority');
      expect(Object.keys(fields).length).to.equal(6);
    });
  });

  describe('Multiple Credentials', () => {
    it('should issue unique credentials with same attributes', async () => {
      const cred1 = await issuer.issueCredential(1990, 840);
      const cred2 = await issuer.issueCredential(1990, 840);

      expect(cred1.id).to.not.equal(cred2.id);
      expect(cred1.fieldValues.salt).to.not.equal(cred2.fieldValues.salt);
      expect(cred1.signature).to.not.deep.equal(cred2.signature);
    });

    it('should verify multiple credentials independently', async () => {
      const creds = await Promise.all([
        issuer.issueCredential(1980, 840),
        issuer.issueCredential(1990, 826),
        issuer.issueCredential(2000, 276),
      ]);

      for (const cred of creds) {
        const valid = await verifyBBSSignature(
          cred.issuerPublicKey,
          cred.signature,
          cred.messages,
          cred.header
        );
        expect(valid).to.be.true;
      }
    });
  });

  describe('Error Handling', () => {
    it('should reject invalid birth year', async () => {
      try {
        await issuer.issueCredential(-1, 840);
        expect.fail('Should have thrown');
      } catch (error: any) {
        expect(error.message).to.match(/birth.*year/i);
      }
    });

    it('should reject invalid nationality code', async () => {
      try {
        await issuer.issueCredential(1990, 9999);
        expect.fail('Should have thrown');
      } catch (error: any) {
        expect(error.message).to.match(/nationality/i);
      }
    });

    it('should reject tampered signature', async () => {
      const cred = await issuer.issueCredential(1990, 840);

      // Tamper with signature
      cred.signature[0] = cred.signature[0] ^ 0xff;

      try {
        await verifyBBSSignature(
          cred.issuerPublicKey,
          cred.signature,
          cred.messages,
          cred.header
        );
        expect.fail('Should have thrown or returned false');
      } catch (error: any) {
        // Tampered signature may throw during deserialization
        expect(error.message).to.match(/invalid|point|signature/i);
      }
    });

    it('should reject signature with wrong messages', async () => {
      const cred = await issuer.issueCredential(1990, 840);

      // Modify one of the messages
      const wrongMessages = [...cred.messages];
      wrongMessages[0] = new Uint8Array([1, 2, 3]);

      const valid = await verifyBBSSignature(
        cred.issuerPublicKey,
        cred.signature,
        wrongMessages,
        cred.header
      );
      expect(valid).to.be.false;
    });
  });

  describe('Issuer Key Management', () => {
    it('should create multiple issuers with unique keys', async () => {
      const issuer1 = await BBSCredentialIssuer.create({ name: 'Authority 1' });
      const issuer2 = await BBSCredentialIssuer.create({ name: 'Authority 2' });

      expect(issuer1.getPublicKey()).to.not.deep.equal(issuer2.getPublicKey());

      // Credentials from each issuer should verify with respective keys
      const cred1 = await issuer1.issueCredential(1990, 840);
      const cred2 = await issuer2.issueCredential(1990, 840);

      const valid1 = await verifyBBSSignature(
        issuer1.getPublicKey(),
        cred1.signature,
        cred1.messages,
        cred1.header
      );
      const valid2 = await verifyBBSSignature(
        issuer2.getPublicKey(),
        cred2.signature,
        cred2.messages,
        cred2.header
      );

      expect(valid1).to.be.true;
      expect(valid2).to.be.true;

      // Cross-verification should fail
      const cross1 = await verifyBBSSignature(
        issuer2.getPublicKey(),
        cred1.signature,
        cred1.messages,
        cred1.header
      );
      const cross2 = await verifyBBSSignature(
        issuer1.getPublicKey(),
        cred2.signature,
        cred2.messages,
        cred2.header
      );

      expect(cross1).to.be.false;
      expect(cross2).to.be.false;
    });
  });
});
