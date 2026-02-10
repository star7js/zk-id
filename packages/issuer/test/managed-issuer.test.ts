/**
 * Tests for ManagedCredentialIssuer
 */

import { describe, test, expect, beforeEach } from 'vitest';
import { generateKeyPairSync, verify } from 'crypto';
import { ManagedCredentialIssuer } from '../src/managed-issuer';
import { InMemoryIssuerKeyManager } from '../src/key-management';
import { InMemoryRevocationStore, AuditLogger, credentialSignaturePayload } from '@zk-id/core';

// Test audit logger that captures log entries
class TestAuditLogger implements AuditLogger {
  public entries: Array<{
    timestamp: string;
    action: string;
    actor: string;
    target: string;
    success: boolean;
    metadata?: Record<string, unknown>;
  }> = [];

  log(entry: {
    timestamp: string;
    action: string;
    actor: string;
    target: string;
    success: boolean;
    metadata?: Record<string, unknown>;
  }): void {
    this.entries.push(entry);
  }
}

describe('ManagedCredentialIssuer', () => {
  let keyManager: InMemoryIssuerKeyManager;
  let issuer: ManagedCredentialIssuer;
  let auditLogger: TestAuditLogger;

  beforeEach(() => {
    const { privateKey, publicKey } = generateKeyPairSync('ed25519');
    keyManager = new InMemoryIssuerKeyManager('test-issuer', privateKey, publicKey);
    auditLogger = new TestAuditLogger();
    issuer = new ManagedCredentialIssuer(keyManager, auditLogger);
  });

  describe('issueCredential', () => {
    test('issues credential with correct issuer name', async () => {
      const signed = await issuer.issueCredential(1990, 840);
      expect(signed.issuer).toBe('test-issuer');
    });

    test('issues credential with valid Ed25519 signature', async () => {
      const signed = await issuer.issueCredential(1990, 840);

      // Verify signature
      const message = credentialSignaturePayload(
        signed.credential,
        signed.issuer,
        signed.issuedAt,
      );
      const signatureBuffer = Buffer.from(signed.signature, 'base64');
      const isValid = verify(
        null,
        Buffer.from(message),
        keyManager.getPublicKey(),
        signatureBuffer,
      );

      expect(isValid).toBe(true);
    });

    test('generates unique credential IDs', async () => {
      const cred1 = await issuer.issueCredential(1990, 840);
      const cred2 = await issuer.issueCredential(1990, 840);

      expect(cred1.credential.id).not.toBe(cred2.credential.id);
    });

    test('logs issuance with userId in metadata', async () => {
      await issuer.issueCredential(1990, 840, 'user-123');

      expect(auditLogger.entries).toHaveLength(1);
      expect(auditLogger.entries[0].action).toBe('issue');
      expect(auditLogger.entries[0].success).toBe(true);
      expect(auditLogger.entries[0].metadata?.userId).toBe('user-123');
    });

    test('defaults to anonymous when no userId provided', async () => {
      await issuer.issueCredential(1990, 840);

      expect(auditLogger.entries[0].metadata?.userId).toBe('anonymous');
    });
  });

  describe('revokeCredential', () => {
    test('revokes credential successfully', async () => {
      const store = new InMemoryRevocationStore();
      issuer.setRevocationStore(store);

      const commitment = 'test-commitment-hash';
      await issuer.revokeCredential(commitment);

      const isRevoked = await issuer.isCredentialRevoked(commitment);
      expect(isRevoked).toBe(true);
    });

    test('throws error when revocation store not configured', async () => {
      await expect(issuer.revokeCredential('test-commitment')).rejects.toThrow(
        'Revocation store not configured',
      );
    });

    test('logs revocation in audit log', async () => {
      const store = new InMemoryRevocationStore();
      issuer.setRevocationStore(store);

      const commitment = 'test-commitment-hash';
      await issuer.revokeCredential(commitment);

      const revokeEntry = auditLogger.entries.find((e) => e.action === 'revoke');
      expect(revokeEntry).toBeDefined();
      expect(revokeEntry?.target).toBe(commitment);
      expect(revokeEntry?.success).toBe(true);
    });
  });

  describe('isCredentialRevoked', () => {
    test('returns true for revoked credential', async () => {
      const store = new InMemoryRevocationStore();
      issuer.setRevocationStore(store);

      const commitment = 'test-commitment';
      await issuer.revokeCredential(commitment);

      expect(await issuer.isCredentialRevoked(commitment)).toBe(true);
    });

    test('returns false for non-revoked credential', async () => {
      const store = new InMemoryRevocationStore();
      issuer.setRevocationStore(store);

      expect(await issuer.isCredentialRevoked('never-revoked')).toBe(false);
    });

    test('returns false when no revocation store configured', async () => {
      expect(await issuer.isCredentialRevoked('any-commitment')).toBe(false);
    });
  });

  describe('getPublicKey', () => {
    test('returns the key manager public key', () => {
      const publicKey = issuer.getPublicKey();
      expect(publicKey).toBe(keyManager.getPublicKey());
    });
  });

  describe('getIssuerName', () => {
    test('returns the issuer name from key manager', () => {
      expect(issuer.getIssuerName()).toBe('test-issuer');
    });
  });

  describe('error propagation', () => {
    test('propagates errors from key manager', async () => {
      // Create a key manager that throws
      const failingKeyManager: InMemoryIssuerKeyManager = {
        getIssuerName: () => 'failing-issuer',
        getPublicKey: () => keyManager.getPublicKey(),
        sign: async () => {
          throw new Error('KMS unavailable');
        },
      } as InMemoryIssuerKeyManager;

      const failingIssuer = new ManagedCredentialIssuer(failingKeyManager);

      await expect(failingIssuer.issueCredential(1990, 840)).rejects.toThrow('KMS unavailable');
    });
  });

  describe('custom audit logger', () => {
    test('uses custom audit logger when provided', async () => {
      const customLogger = new TestAuditLogger();
      const customIssuer = new ManagedCredentialIssuer(keyManager, customLogger);

      await customIssuer.issueCredential(1990, 840, 'user-456');

      expect(customLogger.entries).toHaveLength(1);
      expect(customLogger.entries[0].metadata?.userId).toBe('user-456');
    });
  });
});
