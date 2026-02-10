import { expect } from 'chai';
import { RedisChallengeStore } from '../src/challenge-store';

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
