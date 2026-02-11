/**
 * Minimal Redis client interface covering only the commands used by our stores.
 * Compatible with ioredis, node-redis, and mock implementations.
 */
export interface RedisClient {
  get(key: string): Promise<string | null>;
  /** Atomically get and delete a key (Redis 6.2+). Optional; stores fall back to GET+DEL if absent. */
  getdel?(key: string): Promise<string | null>;
  set(key: string, value: string, ...args: (string | number)[]): Promise<string | null>;
  del(...keys: string[]): Promise<number>;
  sadd(key: string, ...members: string[]): Promise<number>;
  sismember(key: string, member: string): Promise<number>;
  scard(key: string): Promise<number>;
  zadd(key: string, ...args: (string | number)[]): Promise<number>;
  zremrangebyscore(key: string, min: string | number, max: string | number): Promise<number>;
  zcard(key: string): Promise<number>;
  expire(key: string, seconds: number): Promise<number>;
  pipeline?(): RedisPipeline;
}

/**
 * Minimal Redis pipeline interface for atomic operations.
 */
export interface RedisPipeline {
  zremrangebyscore(key: string, min: string | number, max: string | number): this;
  zadd(key: string, ...args: (string | number)[]): this;
  zcard(key: string): this;
  expire(key: string, seconds: number): this;
  exec(): Promise<Array<[Error | null, unknown]> | null>;
}
