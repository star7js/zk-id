/**
 * Tests for mobile wallet
 */

import { describe, it, expect, beforeEach } from '@jest/globals';
import { MobileWallet } from '../src/mobile-wallet.js';
import { InMemoryCredentialStore } from '../src/credential-store.js';
import type { SignedCredential } from '@zk-id/core';

const mockCredential: SignedCredential = {
  credential: {
    id: 'cred-123',
    birthYear: 1990,
    nationality: 840, // ISO 3166-1 numeric code for US
    salt: 'mock-salt-12345',
    commitment: 'mock-commitment',
    createdAt: new Date().toISOString(),
  },
  issuer: 'mock-issuer',
  signature: 'mock-signature',
  issuedAt: new Date().toISOString(),
};

describe('MobileWallet', () => {
  let wallet: MobileWallet;

  beforeEach(() => {
    wallet = new MobileWallet({
      credentialStore: new InMemoryCredentialStore(),
      circuitPaths: {
        ageWasm: '/mock/age.wasm',
        ageZkey: '/mock/age.zkey',
      },
    });
  });

  describe('Credential Management', () => {
    it('should add credentials', async () => {
      await wallet.addCredential(mockCredential);
      const credentials = await wallet.listCredentials();
      expect(credentials).toHaveLength(1);
      expect(credentials[0]).toEqual(mockCredential);
    });

    it('should remove credentials', async () => {
      await wallet.addCredential(mockCredential);
      await wallet.removeCredential('cred-123');

      const credentials = await wallet.listCredentials();
      expect(credentials).toHaveLength(0);
    });

    it('should get specific credentials', async () => {
      await wallet.addCredential(mockCredential);
      const credential = await wallet.getCredential('cred-123');
      expect(credential).toEqual(mockCredential);
    });

    it('should return null for non-existent credentials', async () => {
      const credential = await wallet.getCredential('non-existent');
      expect(credential).toBeNull();
    });
  });

  describe('Export/Import', () => {
    it('should export credentials as JSON', async () => {
      await wallet.addCredential(mockCredential);
      const exported = await wallet.exportCredentials();

      const parsed = JSON.parse(exported);
      expect(parsed).toHaveLength(1);
      expect(parsed[0]).toEqual(mockCredential);
    });

    it('should import credentials from JSON', async () => {
      const json = JSON.stringify([mockCredential]);
      await wallet.importCredentials(json);

      const credentials = await wallet.listCredentials();
      expect(credentials).toHaveLength(1);
      expect(credentials[0]).toEqual(mockCredential);
    });

    it('should handle multiple credentials in export/import', async () => {
      const cred2 = {
        ...mockCredential,
        credential: { ...mockCredential.credential, id: 'cred-456' },
      };

      await wallet.addCredential(mockCredential);
      await wallet.addCredential(cred2);

      const exported = await wallet.exportCredentials();
      await wallet.removeCredential('cred-123');
      await wallet.removeCredential('cred-456');

      await wallet.importCredentials(exported);

      const credentials = await wallet.listCredentials();
      expect(credentials).toHaveLength(2);
    });
  });

  describe('Proof Generation', () => {
    it('should throw error when no credentials available', async () => {
      await expect(wallet.generateAgeProof(null, 18, 'nonce')).rejects.toThrow(
        'No credentials available',
      );
    });

    it('should throw error when credential not found', async () => {
      await expect(wallet.generateAgeProof('non-existent', 18, 'nonce')).rejects.toThrow(
        'Credential not found',
      );
    });

    // Note: Full proof generation tests require mock circuit files
    // These would be integration tests rather than unit tests
  });
});
