import type { RevocationStore } from '@zk-id/core';
import { ZkIdValidationError } from '@zk-id/core';
import type { RedisClient } from './types';

export interface RedisRevocationStoreOptions {
  /** Redis key for the revoked commitments set (default: "zkid:revoked") */
  key?: string;
}

/**
 * Redis-backed revocation store using a single SET for all revoked commitments.
 * Revocations are permanent (no TTL).
 */
export class RedisRevocationStore implements RevocationStore {
  private readonly client: RedisClient;
  private readonly key: string;

  constructor(client: RedisClient, options: RedisRevocationStoreOptions = {}) {
    this.client = client;
    this.key = options.key ?? 'zkid:revoked';
  }

  private validateCommitment(commitment: string): void {
    if (!commitment || commitment.length === 0) {
      throw new ZkIdValidationError('commitment must be a non-empty string', 'commitment');
    }
    if (commitment.length > 512) {
      throw new ZkIdValidationError('commitment must be at most 512 characters', 'commitment');
    }
  }

  async isRevoked(commitment: string): Promise<boolean> {
    this.validateCommitment(commitment);
    const result = await this.client.sismember(this.key, commitment);
    return result === 1;
  }

  async revoke(commitment: string): Promise<void> {
    this.validateCommitment(commitment);
    await this.client.sadd(this.key, commitment);
  }

  async getRevokedCount(): Promise<number> {
    return await this.client.scard(this.key);
  }
}
