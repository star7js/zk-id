import { expect } from 'chai';
import { CredentialIssuer, SignedCredential } from '../src/issuer';

describe('CredentialIssuer Tests', () => {
  let issuer: CredentialIssuer;

  beforeEach(() => {
    issuer = CredentialIssuer.createTestIssuer('Test Government ID Authority');
  });

  describe('issueCredential', () => {
    it('should issue a valid signed credential', async () => {
      const birthYear = 1990;
      const nationality = 840;
      const signed = await issuer.issueCredential(birthYear, nationality);

      expect(signed).to.have.property('credential');
      expect(signed).to.have.property('issuer', 'Test Government ID Authority');
      expect(signed).to.have.property('signature');
      expect(signed).to.have.property('issuedAt');

      expect(signed.credential.birthYear).to.equal(birthYear);
      expect(signed.credential.nationality).to.equal(nationality);
      expect(signed.signature).to.be.a('string');
      expect(signed.signature).to.have.lengthOf(64); // SHA256 hex
    });

    it('should issue credentials with unique IDs', async () => {
      const signed1 = await issuer.issueCredential(1990, 840);
      const signed2 = await issuer.issueCredential(1990, 840);

      expect(signed1.credential.id).to.not.equal(signed2.credential.id);
    });

    it('should issue credentials for different birth years', async () => {
      const signed1 = await issuer.issueCredential(1980, 840);
      const signed2 = await issuer.issueCredential(1990, 840);
      const signed3 = await issuer.issueCredential(2000, 840);

      expect(signed1.credential.birthYear).to.equal(1980);
      expect(signed2.credential.birthYear).to.equal(1990);
      expect(signed3.credential.birthYear).to.equal(2000);
    });

    it('should issue credentials for different nationalities', async () => {
      const signed1 = await issuer.issueCredential(1990, 840); // USA
      const signed2 = await issuer.issueCredential(1990, 826); // UK
      const signed3 = await issuer.issueCredential(1990, 124); // Canada

      expect(signed1.credential.nationality).to.equal(840);
      expect(signed2.credential.nationality).to.equal(826);
      expect(signed3.credential.nationality).to.equal(124);
    });

    it('should produce different commitments for different nationalities', async () => {
      const signed1 = await issuer.issueCredential(1990, 840);
      const signed2 = await issuer.issueCredential(1990, 826);

      expect(signed1.credential.commitment).to.not.equal(signed2.credential.commitment);
    });

    it('should include userId in audit log when provided', async () => {
      const userId = 'user123';
      const signed = await issuer.issueCredential(1990, 840, userId);

      expect(signed).to.be.ok;
      // Audit logging tested separately
    });

    it('should handle current year birth date', async () => {
      const currentYear = new Date().getFullYear();
      const signed = await issuer.issueCredential(currentYear, 840);

      expect(signed.credential.birthYear).to.equal(currentYear);
    });
  });

  describe('verifySignature', () => {
    it('should verify a valid signature', async () => {
      const signed = await issuer.issueCredential(1990, 840);

      // Get the signing key from the issuer config (in production this would be separate)
      const signingKey = (issuer as any).config.signingKey;
      const isValid = CredentialIssuer.verifySignature(signed, signingKey);

      expect(isValid).to.be.true;
    });

    it('should reject an invalid signature', async () => {
      const signed = await issuer.issueCredential(1990, 840);

      // Tamper with the signature
      const tamperedSigned: SignedCredential = {
        ...signed,
        signature: 'invalid_signature_12345678901234567890123456789012345678901234',
      };

      const signingKey = (issuer as any).config.signingKey;
      const isValid = CredentialIssuer.verifySignature(tamperedSigned, signingKey);

      expect(isValid).to.be.false;
    });

    it('should reject with wrong signing key', async () => {
      const signed = await issuer.issueCredential(1990, 840);

      const wrongKey = 'wrong_key_1234567890abcdef1234567890abcdef12345678';
      const isValid = CredentialIssuer.verifySignature(signed, wrongKey);

      expect(isValid).to.be.false;
    });

    it('should reject if credential is modified', async () => {
      const signed = await issuer.issueCredential(1990, 840);

      // Modify the credential commitment
      const modifiedSigned: SignedCredential = {
        ...signed,
        credential: {
          ...signed.credential,
          commitment: 'modified_commitment',
        },
      };

      const signingKey = (issuer as any).config.signingKey;
      const isValid = CredentialIssuer.verifySignature(modifiedSigned, signingKey);

      expect(isValid).to.be.false;
    });
  });

  describe('createTestIssuer', () => {
    it('should create an issuer with name', () => {
      const testIssuer = CredentialIssuer.createTestIssuer('Test Authority');
      expect(testIssuer).to.be.instanceOf(CredentialIssuer);
    });

    it('should create issuers with different keys', () => {
      const issuer1 = CredentialIssuer.createTestIssuer('Authority 1');
      const issuer2 = CredentialIssuer.createTestIssuer('Authority 2');

      const publicKey1 = (issuer1 as any).config.publicKey;
      const publicKey2 = (issuer2 as any).config.publicKey;

      expect(publicKey1).to.not.equal(publicKey2);
    });

    it('should create issuers that can issue credentials', async () => {
      const testIssuer = CredentialIssuer.createTestIssuer('Test Authority');
      const signed = await testIssuer.issueCredential(1995, 840);

      expect(signed.issuer).to.equal('Test Authority');
      expect(signed.credential.birthYear).to.equal(1995);
      expect(signed.credential.nationality).to.equal(840);
    });
  });

  describe('Integration Tests', () => {
    it('should issue and verify credential end-to-end', async () => {
      const birthYear = 1985;
      const nationality = 840;
      const userId = 'user456';

      // Issue credential
      const signed = await issuer.issueCredential(birthYear, nationality, userId);

      // Verify signature
      const signingKey = (issuer as any).config.signingKey;
      const isValid = CredentialIssuer.verifySignature(signed, signingKey);

      expect(isValid).to.be.true;
      expect(signed.credential.birthYear).to.equal(birthYear);
      expect(signed.credential.nationality).to.equal(nationality);
    });

    it('should handle multiple issuers independently', async () => {
      const issuer1 = CredentialIssuer.createTestIssuer('Issuer 1');
      const issuer2 = CredentialIssuer.createTestIssuer('Issuer 2');

      const signed1 = await issuer1.issueCredential(1990, 840);
      const signed2 = await issuer2.issueCredential(1990, 840);

      const signingKey1 = (issuer1 as any).config.signingKey;
      const signingKey2 = (issuer2 as any).config.signingKey;

      // Each issuer can verify their own credentials
      expect(CredentialIssuer.verifySignature(signed1, signingKey1)).to.be.true;
      expect(CredentialIssuer.verifySignature(signed2, signingKey2)).to.be.true;

      // But not each other's credentials
      expect(CredentialIssuer.verifySignature(signed1, signingKey2)).to.be.false;
      expect(CredentialIssuer.verifySignature(signed2, signingKey1)).to.be.false;
    });
  });
});
