import { expect } from 'chai';
import { generateKeyPairSync } from 'crypto';
import { CredentialIssuer } from '../src/issuer';
import { InMemoryIssuerKeyManager, ManagedCredentialIssuer } from '../src/index';
import { SignedCredential } from '@zk-id/core';
import { InMemoryRevocationStore } from '@zk-id/core';

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
      expect(signed.signature.length).to.be.approximately(88, 2); // ~88 chars base64 (64 bytes Ed25519 signature)
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

      // Get the public key from the issuer config
      const publicKey = (issuer as any).config.publicKey;
      const isValid = CredentialIssuer.verifySignature(signed, publicKey);

      expect(isValid).to.be.true;
    });

    it('should reject an invalid signature', async () => {
      const signed = await issuer.issueCredential(1990, 840);

      // Tamper with the signature
      const tamperedSigned: SignedCredential = {
        ...signed,
        signature: 'invalid_signature_12345678901234567890123456789012345678901234',
      };

      const publicKey = (issuer as any).config.publicKey;
      const isValid = CredentialIssuer.verifySignature(tamperedSigned, publicKey);

      expect(isValid).to.be.false;
    });

    it('should reject with wrong public key', async () => {
      const signed = await issuer.issueCredential(1990, 840);

      // Create a different issuer with a different key pair
      const wrongIssuer = CredentialIssuer.createTestIssuer('Wrong Authority');
      const wrongPublicKey = (wrongIssuer as any).config.publicKey;
      const isValid = CredentialIssuer.verifySignature(signed, wrongPublicKey);

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

      const publicKey = (issuer as any).config.publicKey;
      const isValid = CredentialIssuer.verifySignature(modifiedSigned, publicKey);

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

  describe('ManagedCredentialIssuer', () => {
    it('should issue a credential using a key manager', async () => {
      const { privateKey, publicKey } = generateKeyPairSync('ed25519');
      const keyManager = new InMemoryIssuerKeyManager('Managed Authority', privateKey, publicKey);
      const managedIssuer = new ManagedCredentialIssuer(keyManager);

      const signed = await managedIssuer.issueCredential(1991, 840);

      expect(signed.issuer).to.equal('Managed Authority');
      expect(CredentialIssuer.verifySignature(signed, publicKey)).to.be.true;
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
      const publicKey = (issuer as any).config.publicKey;
      const isValid = CredentialIssuer.verifySignature(signed, publicKey);

      expect(isValid).to.be.true;
      expect(signed.credential.birthYear).to.equal(birthYear);
      expect(signed.credential.nationality).to.equal(nationality);
    });

    it('should handle multiple issuers independently', async () => {
      const issuer1 = CredentialIssuer.createTestIssuer('Issuer 1');
      const issuer2 = CredentialIssuer.createTestIssuer('Issuer 2');

      const signed1 = await issuer1.issueCredential(1990, 840);
      const signed2 = await issuer2.issueCredential(1990, 840);

      const publicKey1 = (issuer1 as any).config.publicKey;
      const publicKey2 = (issuer2 as any).config.publicKey;

      // Each issuer can verify their own credentials
      expect(CredentialIssuer.verifySignature(signed1, publicKey1)).to.be.true;
      expect(CredentialIssuer.verifySignature(signed2, publicKey2)).to.be.true;

      // But not each other's credentials
      expect(CredentialIssuer.verifySignature(signed1, publicKey2)).to.be.false;
      expect(CredentialIssuer.verifySignature(signed2, publicKey1)).to.be.false;
    });
  });

  describe('Revocation', () => {
    it('should revoke a credential', async () => {
      const store = new InMemoryRevocationStore();
      issuer.setRevocationStore(store);

      const signed = await issuer.issueCredential(1990, 840);
      const commitment = signed.credential.commitment;

      await issuer.revokeCredential(commitment);

      const isRevoked = await issuer.isCredentialRevoked(commitment);
      expect(isRevoked).to.be.true;
    });

    it('should return false for revoked check without revocation store', async () => {
      const signed = await issuer.issueCredential(1990, 840);
      const isRevoked = await issuer.isCredentialRevoked(signed.credential.commitment);

      expect(isRevoked).to.be.false;
    });

    it('should throw error when revoking without revocation store', async () => {
      const signed = await issuer.issueCredential(1990, 840);

      try {
        await issuer.revokeCredential(signed.credential.commitment);
        expect.fail('Should have thrown an error');
      } catch (error) {
        expect(error).to.be.instanceOf(Error);
        expect((error as Error).message).to.include('Revocation store not configured');
      }
    });

    it('should log revocation events', async () => {
      const store = new InMemoryRevocationStore();
      issuer.setRevocationStore(store);

      const signed = await issuer.issueCredential(1990, 840);
      await issuer.revokeCredential(signed.credential.commitment);

      // Audit logging is tested through console output
      expect(await store.isRevoked(signed.credential.commitment)).to.be.true;
    });
  });
});
