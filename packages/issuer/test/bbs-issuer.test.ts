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
  });
});
