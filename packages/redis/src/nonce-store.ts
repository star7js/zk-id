import type { NonceStore } from '@zk-id/sdk';
import type { RedisClient } from './types';
import { ZkIdValidationError } from '@zk-id/core';

export interface RedisNonceStoreOptions {
  /** Key prefix for nonce keys (default: "zkid:nonce:") */
  keyPrefix?: string;
  /** TTL in seconds for nonce entries (default: 300) */
  ttlSeconds?: number;
}

/**
 * Redis-backed nonce store for replay attack prevention.
 * Stores nonces with automatic expiration.
 */
export class RedisNonceStore implements NonceStore {
  private readonly client: RedisClient;
  private readonly keyPrefix: string;
  private readonly ttlSeconds: number;

  constructor(client: RedisClient, options: RedisNonceStoreOptions = {}) {
    this.client = client;
    this.keyPrefix = options.keyPrefix ?? 'zkid:nonce:';
    this.ttlSeconds = options.ttlSeconds ?? 300;

    if (!Number.isInteger(this.ttlSeconds) || this.ttlSeconds <= 0) {
      throw new ZkIdValidationError('ttlSeconds must be a positive integer', 'ttlSeconds');
    }
  }

  async has(nonce: string): Promise<boolean> {
    const key = this.keyPrefix + nonce;
    const result = await this.client.get(key);
    return result !== null;
  }

  async add(nonce: string): Promise<void> {
    const key = this.keyPrefix + nonce;
    await this.client.set(key, '1', 'EX', this.ttlSeconds);
  }
}
