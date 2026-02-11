import type { RateLimiter } from '@zk-id/sdk';
import type { RedisClient } from './types';
import { ZkIdValidationError, ZkIdConfigError } from '@zk-id/core';

export interface RedisRateLimiterOptions {
  /** Key prefix for rate limit keys (default: "zkid:rate:") */
  keyPrefix?: string;
  /** Maximum requests per window (default: 10) */
  limit?: number;
  /** Time window in milliseconds (default: 60000) */
  windowMs?: number;
}

/**
 * Redis-backed rate limiter using sliding window log with sorted sets.
 * Each request is added as a timestamped entry; old entries are pruned on each check.
 */
export class RedisRateLimiter implements RateLimiter {
  private readonly client: RedisClient;
  private readonly keyPrefix: string;
  private readonly limit: number;
  private readonly windowMs: number;

  constructor(client: RedisClient, options: RedisRateLimiterOptions = {}) {
    this.client = client;
    this.keyPrefix = options.keyPrefix ?? 'zkid:rate:';
    this.limit = options.limit ?? 10;
    this.windowMs = options.windowMs ?? 60000;

    if (typeof this.keyPrefix !== 'string' || this.keyPrefix.length === 0) {
      throw new ZkIdConfigError('keyPrefix must be a non-empty string');
    }
    if (this.keyPrefix.length > 128) {
      throw new ZkIdConfigError('keyPrefix must be at most 128 characters');
    }
    if (!Number.isInteger(this.limit) || this.limit <= 0) {
      throw new ZkIdConfigError('limit must be a positive integer');
    }
    if (!Number.isInteger(this.windowMs) || this.windowMs <= 0) {
      throw new ZkIdConfigError('windowMs must be a positive integer');
    }
  }

  async allowRequest(identifier: string): Promise<boolean> {
    if (!identifier || identifier.length === 0) {
      throw new ZkIdValidationError('identifier must be a non-empty string', 'identifier');
    }
    if (identifier.length > 512) {
      throw new ZkIdValidationError('identifier must be at most 512 characters', 'identifier');
    }
    const key = this.keyPrefix + identifier;
    const now = Date.now();
    const windowStart = now - this.windowMs;
    const windowSec = Math.ceil(this.windowMs / 1000);
    const member = `${now}:${Math.random()}`;

    // Use pipeline for atomicity if available
    if (this.client.pipeline) {
      const pipeline = this.client.pipeline();
      pipeline.zremrangebyscore(key, '-inf', windowStart);
      pipeline.zadd(key, now, member);
      pipeline.zcard(key);
      pipeline.expire(key, windowSec);

      const results = await pipeline.exec();
      if (!results) {
        throw new ZkIdConfigError('Pipeline execution failed');
      }

      const count = results[2]?.[1] as number;

      if (count > this.limit) {
        // Remove the entry we just added
        await this.client.zremrangebyscore(key, now, now);
        return false;
      }

      return true;
    }

    // Fallback: sequential commands
    await this.client.zremrangebyscore(key, '-inf', windowStart);
    await this.client.zadd(key, now, member);
    const count = await this.client.zcard(key);
    await this.client.expire(key, windowSec);

    if (count > this.limit) {
      // Remove the entry we just added
      await this.client.zremrangebyscore(key, now, now);
      return false;
    }

    return true;
  }
}
