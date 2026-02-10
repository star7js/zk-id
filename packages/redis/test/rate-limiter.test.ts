import { expect } from 'chai';
import { RedisRateLimiter } from '../src/rate-limiter';

const REDIS_URL = process.env.ZKID_REDIS_URL || process.env.REDIS_URL;

describe('RedisRateLimiter', function () {
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
  const keyPrefix = `zkid:test:${Date.now()}:rate:`;

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

  it('allows requests under the limit', async () => {
    const limiter = new RedisRateLimiter(client, {
      keyPrefix,
      limit: 5,
      windowMs: 1000,
    });

    for (let i = 0; i < 5; i++) {
      expect(await limiter.allowRequest('user1')).to.equal(true);
    }
  });

  it('blocks requests over the limit', async () => {
    const limiter = new RedisRateLimiter(client, {
      keyPrefix,
      limit: 3,
      windowMs: 1000,
    });

    const id = 'user2';

    expect(await limiter.allowRequest(id)).to.equal(true);
    expect(await limiter.allowRequest(id)).to.equal(true);
    expect(await limiter.allowRequest(id)).to.equal(true);

    // Fourth request should be blocked
    expect(await limiter.allowRequest(id)).to.equal(false);
    expect(await limiter.allowRequest(id)).to.equal(false);
  });

  it('resets after the window expires', async () => {
    const limiter = new RedisRateLimiter(client, {
      keyPrefix,
      limit: 2,
      windowMs: 200, // Short window for testing
    });

    const id = 'user3';

    expect(await limiter.allowRequest(id)).to.equal(true);
    expect(await limiter.allowRequest(id)).to.equal(true);
    expect(await limiter.allowRequest(id)).to.equal(false);

    // Wait for window to expire
    await new Promise((resolve) => setTimeout(resolve, 250));

    // Should allow requests again
    expect(await limiter.allowRequest(id)).to.equal(true);
    expect(await limiter.allowRequest(id)).to.equal(true);
  });

  it('tracks different identifiers independently', async () => {
    const limiter = new RedisRateLimiter(client, {
      keyPrefix,
      limit: 2,
      windowMs: 1000,
    });

    expect(await limiter.allowRequest('user4a')).to.equal(true);
    expect(await limiter.allowRequest('user4a')).to.equal(true);
    expect(await limiter.allowRequest('user4a')).to.equal(false);

    // Different user should have their own limit
    expect(await limiter.allowRequest('user4b')).to.equal(true);
    expect(await limiter.allowRequest('user4b')).to.equal(true);
    expect(await limiter.allowRequest('user4b')).to.equal(false);
  });

  it('uses sliding window', async () => {
    const limiter = new RedisRateLimiter(client, {
      keyPrefix,
      limit: 3,
      windowMs: 500,
    });

    const id = 'user5';

    // Make 3 requests
    expect(await limiter.allowRequest(id)).to.equal(true);
    expect(await limiter.allowRequest(id)).to.equal(true);
    expect(await limiter.allowRequest(id)).to.equal(true);

    // Wait for first request to exit the window
    await new Promise((resolve) => setTimeout(resolve, 250));

    // Still blocked because window hasn't fully elapsed
    expect(await limiter.allowRequest(id)).to.equal(false);

    // Wait for more of the window to pass
    await new Promise((resolve) => setTimeout(resolve, 300));

    // Now should allow again
    expect(await limiter.allowRequest(id)).to.equal(true);
  });

  it('handles default options', async () => {
    const limiter = new RedisRateLimiter(client, { keyPrefix });
    const id = 'user6';

    // Default is 10 requests per 60 seconds
    for (let i = 0; i < 10; i++) {
      expect(await limiter.allowRequest(id)).to.equal(true);
    }

    expect(await limiter.allowRequest(id)).to.equal(false);
  });
});
