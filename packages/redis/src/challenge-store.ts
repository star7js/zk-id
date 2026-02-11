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

    if (typeof this.keyPrefix !== 'string' || this.keyPrefix.length === 0) {
      throw new ZkIdValidationError('keyPrefix must be a non-empty string', 'keyPrefix');
    }
    if (this.keyPrefix.length > 128) {
      throw new ZkIdValidationError('keyPrefix must be at most 128 characters', 'keyPrefix');
    }
  }

  async issue(nonce: string, requestTimestampMs: number, ttlMs: number): Promise<void> {
    if (!nonce || nonce.length === 0) {
      throw new ZkIdValidationError('nonce must be a non-empty string', 'nonce');
    }
    if (nonce.length > 512) {
      throw new ZkIdValidationError('nonce must be at most 512 characters', 'nonce');
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

  /** Lua script that atomically GETs and DELs a key, returning the value or nil. */
  private static readonly GETDEL_LUA = `local v = redis.call('GET', KEYS[1]) if v then redis.call('DEL', KEYS[1]) end return v`;

  async consume(nonce: string): Promise<number | null> {
    if (!nonce || nonce.length === 0 || nonce.length > 512) {
      return null;
    }
    const key = this.keyPrefix + nonce;

    // Atomic get-and-delete to prevent double-consume race conditions.
    // Preference order: GETDEL (Redis 6.2+) > EVAL Lua > GET+DEL (last resort).
    let value: string | null;
    if (this.client.getdel) {
      value = await this.client.getdel(key);
    } else if (this.client.eval) {
      const result = await this.client.eval(RedisChallengeStore.GETDEL_LUA, 1, key);
      value = typeof result === 'string' ? result : null;
    } else {
      // Non-atomic fallback for clients that support neither GETDEL nor EVAL.
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
