import { RevocationStore } from './types';

/**
 * In-memory implementation of RevocationStore
 * For production, use a persistent store (database, Redis, etc.)
 */
export class InMemoryRevocationStore implements RevocationStore {
  private revoked: Set<string>;

  constructor() {
    this.revoked = new Set();
  }

  /**
   * Check if a credential has been revoked
   */
  async isRevoked(credentialId: string): Promise<boolean> {
    return this.revoked.has(credentialId);
  }

  /**
   * Revoke a credential
   */
  async revoke(credentialId: string): Promise<void> {
    this.revoked.add(credentialId);
  }

  /**
   * Get the count of revoked credentials
   */
  async getRevokedCount(): Promise<number> {
    return this.revoked.size;
  }
}
