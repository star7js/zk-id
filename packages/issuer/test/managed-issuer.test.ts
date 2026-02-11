import { expect } from 'chai';
import { generateKeyPairSync, verify } from 'crypto';
import { ManagedCredentialIssuer } from '../src/managed-issuer';
import { InMemoryIssuerKeyManager } from '../src/key-management';
import { InMemoryRevocationStore, AuditLogger, credentialSignaturePayload } from '@zk-id/core';

describe('ManagedCredentialIssuer', () => {
  let keyManager: InMemoryIssuerKeyManager;
  let issuer: ManagedCredentialIssuer;

  beforeEach(() => {
    const { privateKey, publicKey } = generateKeyPairSync('ed25519');
    keyManager = new InMemoryIssuerKeyManager('test-issuer', privateKey, publicKey);
    issuer = new ManagedCredentialIssuer(keyManager);
  });

  describe('issueCredential', () => {
    it('should return a signed credential', async () => {
      const signedCred = await issuer.issueCredential(1990, 840);

      expect(signedCred).to.have.property('credential');
      expect(signedCred).to.have.property('issuer', 'test-issuer');
      expect(signedCred).to.have.property('signature');
      expect(signedCred).to.have.property('issuedAt');
    });

    it('should produce a valid signature', async () => {
      const signedCred = await issuer.issueCredential(1990, 840);
      const message = credentialSignaturePayload(
        signedCred.credential,
        signedCred.issuer,
        signedCred.issuedAt,
      );
      const signatureBuffer = Buffer.from(signedCred.signature, 'base64');
      const isValid = verify(
        null,
        Buffer.from(message),
        keyManager.getPublicKey(),
        signatureBuffer,
      );

      expect(isValid).to.be.true;
    });

    it('should use key manager issuer name', async () => {
      const signedCred = await issuer.issueCredential(1990, 840);
      expect(signedCred.issuer).to.equal('test-issuer');
    });

    it('should generate unique credential IDs', async () => {
      const cred1 = await issuer.issueCredential(1990, 840);
      const cred2 = await issuer.issueCredential(1990, 840);

      expect(cred1.credential.id).to.not.equal(cred2.credential.id);
    });

    it('should include userId in audit metadata', async () => {
      const auditLogs: unknown[] = [];
      const mockLogger: AuditLogger = {
        log: (entry) => auditLogs.push(entry),
      };
      const issuerWithLogger = new ManagedCredentialIssuer(keyManager, mockLogger);

      await issuerWithLogger.issueCredential(1990, 840, 'user-123');

      expect(auditLogs).to.have.lengthOf(1);
      expect(auditLogs[0]).to.have.nested.property('metadata.userId', 'user-123');
    });
  });

  describe('revokeCredential', () => {
    it('should revoke credential when store is configured', async () => {
      const store = new InMemoryRevocationStore();
      issuer.setRevocationStore(store);

      await issuer.revokeCredential('test-commitment');
      const isRevoked = await issuer.isCredentialRevoked('test-commitment');

      expect(isRevoked).to.be.true;
    });

    it('should throw error when store is not configured', async () => {
      try {
        await issuer.revokeCredential('test-commitment');
        expect.fail('Expected error to be thrown');
      } catch (error: any) {
        expect(error.message).to.match(/Revocation store not configured/);
      }
    });

    it('should log revocation to audit logger', async () => {
      const auditLogs: unknown[] = [];
      const mockLogger: AuditLogger = {
        log: (entry) => auditLogs.push(entry),
      };
      const issuerWithLogger = new ManagedCredentialIssuer(keyManager, mockLogger);
      const store = new InMemoryRevocationStore();
      issuerWithLogger.setRevocationStore(store);

      await issuerWithLogger.revokeCredential('test-commitment');

      const revocationLog = auditLogs.find((log: any) => log.action === 'revoke');
      expect(revocationLog).to.exist;
      expect(revocationLog).to.have.property('target', 'test-commitment');
    });
  });

  describe('isCredentialRevoked', () => {
    it('should return true for revoked credentials', async () => {
      const store = new InMemoryRevocationStore();
      issuer.setRevocationStore(store);

      await issuer.revokeCredential('revoked-commitment');
      const isRevoked = await issuer.isCredentialRevoked('revoked-commitment');

      expect(isRevoked).to.be.true;
    });

    it('should return false for non-revoked credentials', async () => {
      const store = new InMemoryRevocationStore();
      issuer.setRevocationStore(store);

      const isRevoked = await issuer.isCredentialRevoked('valid-commitment');

      expect(isRevoked).to.be.false;
    });

    it('should return false when no store is configured', async () => {
      const isRevoked = await issuer.isCredentialRevoked('any-commitment');
      expect(isRevoked).to.be.false;
    });
  });

  describe('getPublicKey', () => {
    it('should delegate to key manager', () => {
      const publicKey = issuer.getPublicKey();
      expect(publicKey).to.equal(keyManager.getPublicKey());
    });
  });

  describe('getIssuerName', () => {
    it('should delegate to key manager', () => {
      expect(issuer.getIssuerName()).to.equal('test-issuer');
    });
  });

  describe('constructor', () => {
    it('should use ConsoleAuditLogger by default', async () => {
      // Create issuer without explicit logger
      const defaultIssuer = new ManagedCredentialIssuer(keyManager);

      // Should not throw - implies logger is working
      const result = await defaultIssuer.issueCredential(1990, 840);
      expect(result).to.have.property('credential');
    });

    it('should use provided audit logger', async () => {
      const auditLogs: unknown[] = [];
      const customLogger: AuditLogger = {
        log: (entry) => auditLogs.push(entry),
      };

      const customIssuer = new ManagedCredentialIssuer(keyManager, customLogger);
      await customIssuer.issueCredential(1990, 840);

      expect(auditLogs).to.have.lengthOf(1);
    });
  });
});
