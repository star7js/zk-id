import type { ChallengeStore } from '@zk-id/sdk';
import type { RedisClient } from './types';
import { ZkIdValidationError } from '@zk-id/core';

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
    if (!nonce || nonce.length === 0) {
      throw new ZkIdValidationError('nonce must be a non-empty string', 'nonce');
    }
    if (!Number.isInteger(requestTimestampMs) || requestTimestampMs <= 0) {
      throw new ZkIdValidationError(
        'requestTimestampMs must be a positive integer',
        'requestTimestampMs',
      );
    }
    if (!Number.isInteger(ttlMs) || ttlMs <= 0) {
      throw new ZkIdValidationError('ttlMs must be a positive integer', 'ttlMs');
    }
    const key = this.keyPrefix + nonce;
    await this.client.set(key, String(requestTimestampMs), 'PX', ttlMs);
  }

  async consume(nonce: string): Promise<number | null> {
    const key = this.keyPrefix + nonce;

    // Atomic get-and-delete to prevent double-consume race conditions.
    // Uses GETDEL if available (Redis 6.2+), otherwise falls back to GET+DEL.
    let value: string | null;
    if (this.client.getdel) {
      value = await this.client.getdel(key);
    } else {
      value = await this.client.get(key);
      if (value !== null) {
        await this.client.del(key);
      }
    }

    if (value === null) {
      return null;
    }

    const timestamp = parseInt(value, 10);
    return isNaN(timestamp) ? null : timestamp;
  }
}
