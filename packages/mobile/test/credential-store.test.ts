/**
 * Tests for mobile credential storage
 */

import { describe, it, expect, beforeEach } from '@jest/globals';
import {
  InMemoryCredentialStore,
  InMemoryBBSCredentialStore,
  MobileCredentialStore,
  type SecureStorageAdapter,
} from '../src/credential-store.js';
import type { SignedCredential, SerializedBBSCredential } from '@zk-id/core';

// Mock credential
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

// Mock BBS+ credential
const mockBBSCredential: SerializedBBSCredential = {
  schemaId: 'age-verification',
  fields: {
    id: 'bbs-123',
    birthYear: 1990,
    nationality: 840,
    salt: 'mock-bbs-salt',
    issuedAt: new Date().toISOString(),
    issuer: 'mock-bbs-issuer',
  },
  signature: 'mock-bbs-signature',
  publicKey: 'mock-bbs-public-key',
  issuer: 'mock-bbs-issuer',
  issuedAt: new Date().toISOString(),
};

describe('InMemoryCredentialStore', () => {
  let store: InMemoryCredentialStore;

  beforeEach(() => {
    store = new InMemoryCredentialStore();
  });

  it('should store and retrieve credentials', async () => {
    await store.put(mockCredential);
    const retrieved = await store.get('cred-123');
    expect(retrieved).toEqual(mockCredential);
  });

  it('should return null for non-existent credentials', async () => {
    const retrieved = await store.get('non-existent');
    expect(retrieved).toBeNull();
  });

  it('should list all credentials', async () => {
    await store.put(mockCredential);
    await store.put({
      ...mockCredential,
      credential: { ...mockCredential.credential, id: 'cred-456' },
    });

    const all = await store.getAll();
    expect(all).toHaveLength(2);
  });

  it('should delete credentials', async () => {
    await store.put(mockCredential);
    await store.delete('cred-123');

    const retrieved = await store.get('cred-123');
    expect(retrieved).toBeNull();
  });

  it('should clear all credentials', async () => {
    await store.put(mockCredential);
    await store.put({
      ...mockCredential,
      credential: { ...mockCredential.credential, id: 'cred-456' },
    });

    await store.clear();

    const all = await store.getAll();
    expect(all).toHaveLength(0);
  });
});

describe('InMemoryBBSCredentialStore', () => {
  let store: InMemoryBBSCredentialStore;

  beforeEach(() => {
    store = new InMemoryBBSCredentialStore();
  });

  it('should store and retrieve BBS+ credentials', async () => {
    await store.put(mockBBSCredential);
    const retrieved = await store.get('bbs-123');
    expect(retrieved).toEqual(mockBBSCredential);
  });

  it('should auto-generate ID if missing', async () => {
    const credWithoutId = { ...mockBBSCredential };
    delete credWithoutId.fields.id;

    await store.put(credWithoutId);

    const all = await store.getAll();
    expect(all).toHaveLength(1);
    expect(all[0].fields.id).toBeDefined();
  });
});

describe('MobileCredentialStore', () => {
  let store: MobileCredentialStore;
  let mockStorage: Map<string, string>;
  let adapter: SecureStorageAdapter;

  beforeEach(() => {
    mockStorage = new Map();
    adapter = {
      getItem: async (key) => mockStorage.get(key) ?? null,
      setItem: async (key, value) => {
        mockStorage.set(key, value);
      },
      removeItem: async (key) => {
        mockStorage.delete(key);
      },
      getAllKeys: async () => Array.from(mockStorage.keys()),
    };
    store = new MobileCredentialStore(adapter);
  });

  it('should use key prefix for storage', async () => {
    await store.put(mockCredential);
    expect(mockStorage.has('zkid:cred:cred-123')).toBe(true);
  });

  it('should store and retrieve credentials', async () => {
    await store.put(mockCredential);
    const retrieved = await store.get('cred-123');
    expect(retrieved).toEqual(mockCredential);
  });

  it('should list only credential keys', async () => {
    await store.put(mockCredential);
    await adapter.setItem('other:key', 'value'); // Not a credential

    const all = await store.getAll();
    expect(all).toHaveLength(1);
  });

  it('should clear only credential keys', async () => {
    await store.put(mockCredential);
    await adapter.setItem('other:key', 'value');

    await store.clear();

    expect(await store.getAll()).toHaveLength(0);
    expect(await adapter.getItem('other:key')).toBe('value');
  });
});
