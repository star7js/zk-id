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
   * Check if a credential commitment has been revoked
   */
  async isRevoked(commitment: string): Promise<boolean> {
    return this.revoked.has(commitment);
  }

  /**
   * Revoke a credential commitment
   */
  async revoke(commitment: string): Promise<void> {
    this.revoked.add(commitment);
  }

  /**
   * Get the count of revoked credentials
   */
  async getRevokedCount(): Promise<number> {
    return this.revoked.size;
  }
}
