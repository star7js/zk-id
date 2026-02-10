import { expect } from 'chai';
import { RedisNonceStore } from '../src/nonce-store';

const REDIS_URL = process.env.ZKID_REDIS_URL || process.env.REDIS_URL;

describe('RedisNonceStore', function () {
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
  const keyPrefix = `zkid:test:${Date.now()}:nonce:`;

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

  it('returns false for nonces that have not been added', async () => {
    const store = new RedisNonceStore(client, { keyPrefix });
    expect(await store.has('nonexistent')).to.equal(false);
  });

  it('returns true for nonces that have been added', async () => {
    const store = new RedisNonceStore(client, { keyPrefix });
    await store.add('test-nonce-1');
    expect(await store.has('test-nonce-1')).to.equal(true);
  });

  it('prevents replay with same nonce', async () => {
    const store = new RedisNonceStore(client, { keyPrefix });
    const nonce = 'test-nonce-2';

    expect(await store.has(nonce)).to.equal(false);
    await store.add(nonce);
    expect(await store.has(nonce)).to.equal(true);
    // Second check should still return true
    expect(await store.has(nonce)).to.equal(true);
  });

  it('expires nonces after TTL', async () => {
    const store = new RedisNonceStore(client, {
      keyPrefix,
      ttlSeconds: 1, // 1 second TTL for testing
    });

    await store.add('expiring-nonce');
    expect(await store.has('expiring-nonce')).to.equal(true);

    // Wait for expiration
    await new Promise((resolve) => setTimeout(resolve, 1100));

    expect(await store.has('expiring-nonce')).to.equal(false);
  });

  it('handles multiple nonces independently', async () => {
    const store = new RedisNonceStore(client, { keyPrefix });
    const nonce1 = 'multi-1';
    const nonce2 = 'multi-2';

    await store.add(nonce1);
    expect(await store.has(nonce1)).to.equal(true);
    expect(await store.has(nonce2)).to.equal(false);

    await store.add(nonce2);
    expect(await store.has(nonce1)).to.equal(true);
    expect(await store.has(nonce2)).to.equal(true);
  });
});
