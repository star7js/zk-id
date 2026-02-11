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

    if (typeof this.keyPrefix !== 'string' || this.keyPrefix.length === 0) {
      throw new ZkIdValidationError('keyPrefix must be a non-empty string', 'keyPrefix');
    }
    if (this.keyPrefix.length > 128) {
      throw new ZkIdValidationError('keyPrefix must be at most 128 characters', 'keyPrefix');
    }
    if (!Number.isInteger(this.ttlSeconds) || this.ttlSeconds <= 0) {
      throw new ZkIdValidationError('ttlSeconds must be a positive integer', 'ttlSeconds');
    }
  }

  private validateNonce(nonce: string): void {
    if (!nonce || nonce.length === 0) {
      throw new ZkIdValidationError('nonce must be a non-empty string', 'nonce');
    }
    if (nonce.length > 512) {
      throw new ZkIdValidationError('nonce must be at most 512 characters', 'nonce');
    }
  }

  async has(nonce: string): Promise<boolean> {
    this.validateNonce(nonce);
    const key = this.keyPrefix + nonce;
    const result = await this.client.get(key);
    return result !== null;
  }

  async add(nonce: string): Promise<void> {
    this.validateNonce(nonce);
    const key = this.keyPrefix + nonce;
    await this.client.set(key, '1', 'EX', this.ttlSeconds);
  }
}
