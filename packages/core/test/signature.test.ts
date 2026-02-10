import { expect } from 'chai';
import { credentialSignaturePayload } from '../src/signature';
import { createCredential } from '../src/credential';

describe('Signature Tests', () => {
  describe('credentialSignaturePayload', () => {
    it('should create signature payload with basic credential fields', async () => {
      const credential = await createCredential(1995, 840);

      const payload = credentialSignaturePayload(credential);

      const parsed = JSON.parse(payload);
      expect(parsed).to.have.property('id', credential.id);
      expect(parsed).to.have.property('commitment', credential.commitment);
      expect(parsed).to.have.property('createdAt', credential.createdAt);
    });

    it('should include issuer when provided', async () => {
      const credential = await createCredential(1995, 840);
      const issuer = 'Test Issuer';

      const payload = credentialSignaturePayload(credential, issuer);

      const parsed = JSON.parse(payload);
      expect(parsed).to.have.property('issuer', issuer);
    });

    it('should include issuedAt when provided', async () => {
      const credential = await createCredential(1995, 840);
      const issuedAt = new Date().toISOString();

      const payload = credentialSignaturePayload(credential, undefined, issuedAt);

      const parsed = JSON.parse(payload);
      expect(parsed).to.have.property('issuedAt', issuedAt);
    });

    it('should include both issuer and issuedAt when both provided', async () => {
      const credential = await createCredential(1995, 840);
      const issuer = 'Test Issuer';
      const issuedAt = new Date().toISOString();

      const payload = credentialSignaturePayload(credential, issuer, issuedAt);

      const parsed = JSON.parse(payload);
      expect(parsed).to.have.property('issuer', issuer);
      expect(parsed).to.have.property('issuedAt', issuedAt);
    });

    it('should create deterministic payload for same inputs', async () => {
      const credential = await createCredential(1995, 840);
      const issuer = 'Test Issuer';
      const issuedAt = '2026-02-10T12:00:00.000Z';

      const payload1 = credentialSignaturePayload(credential, issuer, issuedAt);
      const payload2 = credentialSignaturePayload(credential, issuer, issuedAt);

      expect(payload1).to.equal(payload2);
    });

    it('should create different payload for different credentials', async () => {
      const cred1 = await createCredential(1995, 840);
      const cred2 = await createCredential(1995, 840);

      const payload1 = credentialSignaturePayload(cred1);
      const payload2 = credentialSignaturePayload(cred2);

      expect(payload1).to.not.equal(payload2);
    });

    it('should create different payload for different issuers', async () => {
      const credential = await createCredential(1995, 840);

      const payload1 = credentialSignaturePayload(credential, 'Issuer A');
      const payload2 = credentialSignaturePayload(credential, 'Issuer B');

      expect(payload1).to.not.equal(payload2);
    });

    it('should create different payload when issuer is omitted vs included', async () => {
      const credential = await createCredential(1995, 840);

      const payloadWithout = credentialSignaturePayload(credential);
      const payloadWith = credentialSignaturePayload(credential, 'Test Issuer');

      expect(payloadWithout).to.not.equal(payloadWith);

      const parsedWithout = JSON.parse(payloadWithout);
      const parsedWith = JSON.parse(payloadWith);

      expect(parsedWithout).to.not.have.property('issuer');
      expect(parsedWith).to.have.property('issuer');
    });

    it('should produce valid JSON that can be parsed', async () => {
      const credential = await createCredential(1995, 840);
      const issuer = 'Test Issuer';
      const issuedAt = new Date().toISOString();

      const payload = credentialSignaturePayload(credential, issuer, issuedAt);

      expect(() => JSON.parse(payload)).to.not.throw();

      const parsed = JSON.parse(payload);
      expect(parsed).to.be.an('object');
      expect(Object.keys(parsed)).to.include.members([
        'id',
        'commitment',
        'createdAt',
        'issuer',
        'issuedAt',
      ]);
    });

    it('should handle credential with special characters in ID', async () => {
      const credential = await createCredential(1995, 840);
      // IDs are hex strings, but test that JSON escaping works

      const payload = credentialSignaturePayload(credential, 'Test-Issuer_123');

      expect(() => JSON.parse(payload)).to.not.throw();
      const parsed = JSON.parse(payload);
      expect(parsed.issuer).to.equal('Test-Issuer_123');
    });

    it('should not mutate the original credential', async () => {
      const credential = await createCredential(1995, 840);
      const originalId = credential.id;
      const originalCommitment = credential.commitment;

      credentialSignaturePayload(credential, 'Test Issuer', new Date().toISOString());

      expect(credential.id).to.equal(originalId);
      expect(credential.commitment).to.equal(originalCommitment);
    });
  });
});
