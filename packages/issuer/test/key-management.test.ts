/**
 * Tests for InMemoryIssuerKeyManager
 */

import { describe, test, expect, beforeEach } from 'vitest';
import { generateKeyPairSync, verify } from 'crypto';
import { InMemoryIssuerKeyManager } from '../src/key-management';

describe('InMemoryIssuerKeyManager', () => {
  let keyManager: InMemoryIssuerKeyManager;
  let privateKey: ReturnType<typeof generateKeyPairSync>['privateKey'];
  let publicKey: ReturnType<typeof generateKeyPairSync>['publicKey'];

  beforeEach(() => {
    const keys = generateKeyPairSync('ed25519');
    privateKey = keys.privateKey;
    publicKey = keys.publicKey;
    keyManager = new InMemoryIssuerKeyManager('test-issuer', privateKey, publicKey);
  });

  describe('getIssuerName', () => {
    test('returns the configured issuer name', () => {
      expect(keyManager.getIssuerName()).toBe('test-issuer');
    });

    test('supports different issuer names', () => {
      const km2 = new InMemoryIssuerKeyManager('different-issuer', privateKey, publicKey);
      expect(km2.getIssuerName()).toBe('different-issuer');
    });
  });

  describe('getPublicKey', () => {
    test('returns the public key', () => {
      const pubKey = keyManager.getPublicKey();
      expect(pubKey).toBe(publicKey);
    });
  });

  describe('sign', () => {
    test('produces valid Ed25519 signatures', async () => {
      const payload = Buffer.from('test message');
      const signature = await keyManager.sign(payload);

      const isValid = verify(null, payload, publicKey, signature);
      expect(isValid).toBe(true);
    });

    test('produces different signatures for different payloads', async () => {
      const payload1 = Buffer.from('message 1');
      const payload2 = Buffer.from('message 2');

      const sig1 = await keyManager.sign(payload1);
      const sig2 = await keyManager.sign(payload2);

      expect(sig1).not.toEqual(sig2);
    });

    test('produces signatures that verify with correct public key', async () => {
      const payload = Buffer.from('verify me');
      const signature = await keyManager.sign(payload);

      // Correct public key should verify
      const valid = verify(null, payload, publicKey, signature);
      expect(valid).toBe(true);
    });

    test('signatures do not verify with wrong public key', async () => {
      const payload = Buffer.from('verify me');
      const signature = await keyManager.sign(payload);

      // Different public key should not verify
      const otherKeys = generateKeyPairSync('ed25519');
      const wrongPublic = otherKeys.publicKey;

      const valid = verify(null, payload, wrongPublic, signature);
      expect(valid).toBe(false);
    });
  });

  describe('multiple key managers', () => {
    test('different key managers produce unique keys', () => {
      const keys1 = generateKeyPairSync('ed25519');
      const keys2 = generateKeyPairSync('ed25519');

      const km1 = new InMemoryIssuerKeyManager('issuer1', keys1.privateKey, keys1.publicKey);
      const km2 = new InMemoryIssuerKeyManager('issuer2', keys2.privateKey, keys2.publicKey);

      expect(km1.getPublicKey()).not.toBe(km2.getPublicKey());
    });

    test('signatures from one key manager do not verify with another public key', async () => {
      const keys1 = generateKeyPairSync('ed25519');
      const keys2 = generateKeyPairSync('ed25519');

      const km1 = new InMemoryIssuerKeyManager('issuer1', keys1.privateKey, keys1.publicKey);
      const km2 = new InMemoryIssuerKeyManager('issuer2', keys2.privateKey, keys2.publicKey);

      const payload = Buffer.from('cross-check');
      const sig1 = await km1.sign(payload);

      // km1's signature should not verify with km2's public key
      const valid = verify(null, payload, km2.getPublicKey(), sig1);
      expect(valid).toBe(false);
    });
  });

  describe('edge cases', () => {
    test('handles empty payload', async () => {
      const empty = Buffer.from('');
      const signature = await keyManager.sign(empty);

      const isValid = verify(null, empty, publicKey, signature);
      expect(isValid).toBe(true);
    });

    test('handles large payload', async () => {
      const large = Buffer.alloc(10000).fill('a');
      const signature = await keyManager.sign(large);

      const isValid = verify(null, large, publicKey, signature);
      expect(isValid).toBe(true);
    });

    test('handles rapid successive signing', async () => {
      const payloads = Array.from({ length: 100 }, (_, i) => Buffer.from(`msg-${i}`));

      const signatures = await Promise.all(payloads.map((p) => keyManager.sign(p)));

      // All signatures should be valid
      for (let i = 0; i < signatures.length; i++) {
        const valid = verify(null, payloads[i], publicKey, signatures[i]);
        expect(valid).toBe(true);
      }
    });
  });
});
