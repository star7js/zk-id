import { expect } from 'chai';
import { RedisChallengeStore } from '../src/challenge-store';
import type { RedisClient } from '../src/types';

// ---------------------------------------------------------------------------
// Minimal in-memory mock that simulates the three consume() code paths
// ---------------------------------------------------------------------------

function createMockClient(opts: {
  hasGetdel?: boolean;
  hasEval?: boolean;
}): RedisClient & { store: Map<string, string> } {
  const store = new Map<string, string>();

  const base: RedisClient & { store: Map<string, string> } = {
    store,
    async get(key: string) {
      return store.get(key) ?? null;
    },
    async set(key: string, value: string) {
      store.set(key, value);
      return 'OK';
    },
    async del(...keys: string[]) {
      let count = 0;
      for (const k of keys) {
        if (store.delete(k)) count++;
      }
      return count;
    },
    // Unused stubs required by RedisClient interface
    async sadd() {
      return 0;
    },
    async sismember() {
      return 0;
    },
    async scard() {
      return 0;
    },
    async zadd() {
      return 0;
    },
    async zremrangebyscore() {
      return 0;
    },
    async zcard() {
      return 0;
    },
    async expire() {
      return 0;
    },
  };

  if (opts.hasGetdel) {
    base.getdel = async (key: string) => {
      const val = store.get(key) ?? null;
      if (val !== null) store.delete(key);
      return val;
    };
  }

  if (opts.hasEval) {
    base.eval = async (script: string, numkeys: number, ...args: string[]) => {
      // Simulate the GETDEL Lua script behaviour
      const key = args[0];
      const val = store.get(key) ?? null;
      if (val !== null) store.delete(key);
      return val;
    };
  }

  return base;
}

// ---------------------------------------------------------------------------
// Unit tests for the three consume() code paths (no Redis required)
// ---------------------------------------------------------------------------

describe('RedisChallengeStore (mock)', () => {
  const keyPrefix = 'mock:challenge:';

  describe('consume via GETDEL (Redis 6.2+)', () => {
    it('issues and consumes atomically', async () => {
      const client = createMockClient({ hasGetdel: true });
      const store = new RedisChallengeStore(client, { keyPrefix });

      await store.issue('n1', 1000, 5000);
      expect(await store.consume('n1')).to.equal(1000);
      expect(await store.consume('n1')).to.equal(null);
    });
  });

  describe('consume via Lua EVAL fallback', () => {
    it('issues and consumes atomically without getdel', async () => {
      const client = createMockClient({ hasGetdel: false, hasEval: true });
      const store = new RedisChallengeStore(client, { keyPrefix });

      await store.issue('n2', 2000, 5000);
      expect(await store.consume('n2')).to.equal(2000);
      expect(await store.consume('n2')).to.equal(null);
    });

    it('returns null for non-existent nonce', async () => {
      const client = createMockClient({ hasGetdel: false, hasEval: true });
      const store = new RedisChallengeStore(client, { keyPrefix });
      expect(await store.consume('does-not-exist')).to.equal(null);
    });
  });

  describe('consume via GET+DEL fallback (no getdel, no eval)', () => {
    it('falls back to GET+DEL', async () => {
      const client = createMockClient({ hasGetdel: false, hasEval: false });
      const store = new RedisChallengeStore(client, { keyPrefix });

      await store.issue('n3', 3000, 5000);
      expect(await store.consume('n3')).to.equal(3000);
      expect(await store.consume('n3')).to.equal(null);
    });
  });

  describe('consume edge cases', () => {
    it('returns null for empty nonce', async () => {
      const client = createMockClient({ hasGetdel: true });
      const store = new RedisChallengeStore(client, { keyPrefix });
      expect(await store.consume('')).to.equal(null);
    });

    it('returns null for nonce longer than 512 chars', async () => {
      const client = createMockClient({ hasGetdel: true });
      const store = new RedisChallengeStore(client, { keyPrefix });
      expect(await store.consume('x'.repeat(513))).to.equal(null);
    });

    it('returns null when stored value is non-numeric', async () => {
      const client = createMockClient({ hasGetdel: true });
      const store = new RedisChallengeStore(client, { keyPrefix });
      // Manually put a bad value
      client.store.set(keyPrefix + 'bad', 'not-a-number');
      expect(await store.consume('bad')).to.equal(null);
    });
  });
});

// ---------------------------------------------------------------------------
// Integration tests (require a running Redis instance)
// ---------------------------------------------------------------------------

const REDIS_URL = process.env.ZKID_REDIS_URL || process.env.REDIS_URL;

describe('RedisChallengeStore', function () {
  if (!REDIS_URL) {
    it.skip('requires ZKID_REDIS_URL or REDIS_URL to run', () => {});
    return;
  }

  let Redis: any;
  try {
    Redis = require('ioredis');
  } catch {
    it.skip('requires ioredis package to run integration tests', () => {});
    return;
  }

  this.timeout(10000);

  let client: any;
  const keyPrefix = `zkid:test:${Date.now()}:challenge:`;

  before(async () => {
    client = new Redis(REDIS_URL);
  });

  after(async () => {
    // Clean up test keys
    const keys = await client.keys(`${keyPrefix}*`);
    if (keys.length > 0) {
      await client.del(...keys);
    }
    await client.quit();
  });

  it('returns null for challenges that have not been issued', async () => {
    const store = new RedisChallengeStore(client, { keyPrefix });
    expect(await store.consume('nonexistent')).to.equal(null);
  });

  it('issues and consumes challenges with correct timestamp', async () => {
    const store = new RedisChallengeStore(client, { keyPrefix });
    const nonce = 'test-challenge-1';
    const timestamp = Date.now();

    await store.issue(nonce, timestamp, 5000);
    const consumed = await store.consume(nonce);

    expect(consumed).to.equal(timestamp);
  });

  it('returns null after challenge is consumed', async () => {
    const store = new RedisChallengeStore(client, { keyPrefix });
    const nonce = 'test-challenge-2';
    const timestamp = Date.now();

    await store.issue(nonce, timestamp, 5000);
    await store.consume(nonce);

    // Second consume should return null
    expect(await store.consume(nonce)).to.equal(null);
  });

  it('expires challenges after TTL', async () => {
    const store = new RedisChallengeStore(client, { keyPrefix });
    const nonce = 'expiring-challenge';
    const timestamp = Date.now();

    await store.issue(nonce, timestamp, 100); // 100ms TTL

    // Wait for expiration
    await new Promise((resolve) => setTimeout(resolve, 150));

    expect(await store.consume(nonce)).to.equal(null);
  });

  it('handles multiple challenges independently', async () => {
    const store = new RedisChallengeStore(client, { keyPrefix });
    const nonce1 = 'multi-challenge-1';
    const nonce2 = 'multi-challenge-2';
    const ts1 = Date.now();
    const ts2 = ts1 + 1000;

    await store.issue(nonce1, ts1, 5000);
    await store.issue(nonce2, ts2, 5000);

    expect(await store.consume(nonce1)).to.equal(ts1);
    expect(await store.consume(nonce2)).to.equal(ts2);
  });

  it('preserves timestamp precision', async () => {
    const store = new RedisChallengeStore(client, { keyPrefix });
    const nonce = 'precision-test';
    const timestamp = 1234567890123; // Specific millisecond timestamp

    await store.issue(nonce, timestamp, 5000);
    expect(await store.consume(nonce)).to.equal(timestamp);
  });
});
