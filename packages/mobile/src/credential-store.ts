/**
 * Mobile credential storage with pluggable secure storage adapters
 *
 * No DOM dependencies - all storage is injected via platform-specific adapters.
 */

import type { SignedCredential, SerializedBBSCredential } from '@zk-id/core';

/**
 * Platform-agnostic secure storage adapter interface.
 *
 * Implementations:
 * - React Native: Use @react-native-async-storage/async-storage or expo-secure-store
 * - iOS: Keychain Services wrapper
 * - Android: EncryptedSharedPreferences wrapper
 */
export interface SecureStorageAdapter {
  /**
   * Retrieve a value by key
   */
  getItem(key: string): Promise<string | null>;

  /**
   * Store a value by key
   */
  setItem(key: string, value: string): Promise<void>;

  /**
   * Delete a value by key
   */
  removeItem(key: string): Promise<void>;

  /**
   * Get all keys (for listing credentials)
   */
  getAllKeys(): Promise<string[]>;
}

/**
 * Mobile credential store for EdDSA-signed credentials.
 *
 * Uses injected SecureStorageAdapter for platform-specific persistence.
 */
export class MobileCredentialStore {
  private readonly keyPrefix = 'zkid:cred:';

  constructor(private storage: SecureStorageAdapter) {}

  async get(id: string): Promise<SignedCredential | null> {
    const json = await this.storage.getItem(this.keyPrefix + id);
    if (!json) return null;
    return JSON.parse(json) as SignedCredential;
  }

  async getAll(): Promise<SignedCredential[]> {
    const keys = await this.storage.getAllKeys();
    const credKeys = keys.filter((k) => k.startsWith(this.keyPrefix));

    const credentials: SignedCredential[] = [];
    for (const key of credKeys) {
      const json = await this.storage.getItem(key);
      if (json) {
        credentials.push(JSON.parse(json) as SignedCredential);
      }
    }

    return credentials;
  }

  async put(credential: SignedCredential): Promise<void> {
    const key = this.keyPrefix + credential.credential.id;
    await this.storage.setItem(key, JSON.stringify(credential));
  }

  async delete(id: string): Promise<void> {
    await this.storage.removeItem(this.keyPrefix + id);
  }

  async clear(): Promise<void> {
    const keys = await this.storage.getAllKeys();
    const credKeys = keys.filter((k) => k.startsWith(this.keyPrefix));

    for (const key of credKeys) {
      await this.storage.removeItem(key);
    }
  }
}

/**
 * Mobile BBS+ credential store for selective disclosure.
 *
 * Uses injected SecureStorageAdapter for platform-specific persistence.
 */
export class MobileBBSCredentialStore {
  private readonly keyPrefix = 'zkid:bbs:';

  constructor(private storage: SecureStorageAdapter) {}

  async get(id: string): Promise<SerializedBBSCredential | null> {
    const json = await this.storage.getItem(this.keyPrefix + id);
    if (!json) return null;
    return JSON.parse(json) as SerializedBBSCredential;
  }

  async getAll(): Promise<SerializedBBSCredential[]> {
    const keys = await this.storage.getAllKeys();
    const credKeys = keys.filter((k) => k.startsWith(this.keyPrefix));

    const credentials: SerializedBBSCredential[] = [];
    for (const key of credKeys) {
      const json = await this.storage.getItem(key);
      if (json) {
        credentials.push(JSON.parse(json) as SerializedBBSCredential);
      }
    }

    return credentials;
  }

  async put(credential: SerializedBBSCredential): Promise<void> {
    const id = String(credential.fields.id || `bbs-${Date.now()}`);
    const key = this.keyPrefix + id;
    await this.storage.setItem(key, JSON.stringify(credential));
  }

  async delete(id: string): Promise<void> {
    await this.storage.removeItem(this.keyPrefix + id);
  }

  async clear(): Promise<void> {
    const keys = await this.storage.getAllKeys();
    const credKeys = keys.filter((k) => k.startsWith(this.keyPrefix));

    for (const key of credKeys) {
      await this.storage.removeItem(key);
    }
  }
}

/**
 * In-memory credential store for testing (no persistence).
 */
export class InMemoryCredentialStore {
  private store = new Map<string, SignedCredential>();

  async get(id: string): Promise<SignedCredential | null> {
    return this.store.get(id) ?? null;
  }

  async getAll(): Promise<SignedCredential[]> {
    return Array.from(this.store.values());
  }

  async put(credential: SignedCredential): Promise<void> {
    this.store.set(credential.credential.id, credential);
  }

  async delete(id: string): Promise<void> {
    this.store.delete(id);
  }

  async clear(): Promise<void> {
    this.store.clear();
  }
}

/**
 * In-memory BBS+ credential store for testing (no persistence).
 */
export class InMemoryBBSCredentialStore {
  private store = new Map<string, SerializedBBSCredential>();

  async get(id: string): Promise<SerializedBBSCredential | null> {
    return this.store.get(id) ?? null;
  }

  async getAll(): Promise<SerializedBBSCredential[]> {
    return Array.from(this.store.values());
  }

  async put(credential: SerializedBBSCredential): Promise<void> {
    const id = String(credential.fields.id || `bbs-${Date.now()}`);
    this.store.set(id, credential);
  }

  async delete(id: string): Promise<void> {
    this.store.delete(id);
  }

  async clear(): Promise<void> {
    this.store.clear();
  }
}
