import type { ChallengeStore } from '@zk-id/sdk';
import type { RedisClient } from './types';

export interface RedisChallengeStoreOptions {
  /** Key prefix for challenge keys (default: "zkid:challenge:") */
  keyPrefix?: string;
}

/**
 * Redis-backed challenge store for nonce issuance and consumption.
 * Challenges are stored with millisecond-precision TTL.
 */
export class RedisChallengeStore implements ChallengeStore {
  private readonly client: RedisClient;
  private readonly keyPrefix: string;

  constructor(client: RedisClient, options: RedisChallengeStoreOptions = {}) {
    this.client = client;
    this.keyPrefix = options.keyPrefix ?? 'zkid:challenge:';
  }

  async issue(nonce: string, requestTimestampMs: number, ttlMs: number): Promise<void> {
    const key = this.keyPrefix + nonce;
    await this.client.set(key, String(requestTimestampMs), 'PX', ttlMs);
  }

  async consume(nonce: string): Promise<number | null> {
    const key = this.keyPrefix + nonce;
    const value = await this.client.get(key);

    if (value === null) {
      return null;
    }

    await this.client.del(key);
    const timestamp = parseInt(value, 10);
    return isNaN(timestamp) ? null : timestamp;
  }
}
