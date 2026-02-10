import { expect } from 'chai';
import { RedisRevocationStore } from '../src/revocation-store';

const REDIS_URL = process.env.ZKID_REDIS_URL || process.env.REDIS_URL;

describe('RedisRevocationStore', function () {
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
  const key = `zkid:test:${Date.now()}:revoked`;

  before(async () => {
    client = new Redis(REDIS_URL);
  });

  after(async () => {
    // Clean up test key
    await client.del(key);
    await client.quit();
  });

  it('returns false for commitments that have not been revoked', async () => {
    const store = new RedisRevocationStore(client, { key });
    expect(await store.isRevoked('nonexistent')).to.equal(false);
  });

  it('returns true for commitments that have been revoked', async () => {
    const store = new RedisRevocationStore(client, { key });
    const commitment = 'test-commitment-1';

    await store.revoke(commitment);
    expect(await store.isRevoked(commitment)).to.equal(true);
  });

  it('handles multiple revocations', async () => {
    const store = new RedisRevocationStore(client, { key });
    const commitments = ['commit-1', 'commit-2', 'commit-3'];

    for (const commitment of commitments) {
      await store.revoke(commitment);
    }

    for (const commitment of commitments) {
      expect(await store.isRevoked(commitment)).to.equal(true);
    }
  });

  it('returns correct revoked count', async () => {
    const store = new RedisRevocationStore(client, { key });

    // Start fresh
    await client.del(key);

    expect(await store.getRevokedCount()).to.equal(0);

    await store.revoke('count-1');
    expect(await store.getRevokedCount()).to.equal(1);

    await store.revoke('count-2');
    expect(await store.getRevokedCount()).to.equal(2);

    await store.revoke('count-3');
    expect(await store.getRevokedCount()).to.equal(3);
  });

  it('handles duplicate revocations idempotently', async () => {
    const store = new RedisRevocationStore(client, { key });
    const commitment = 'duplicate-test';

    await client.del(key);

    await store.revoke(commitment);
    expect(await store.getRevokedCount()).to.equal(1);

    // Revoking again should not increase count
    await store.revoke(commitment);
    expect(await store.getRevokedCount()).to.equal(1);
    expect(await store.isRevoked(commitment)).to.equal(true);
  });

  it('revocations persist (no TTL)', async () => {
    const store = new RedisRevocationStore(client, { key });
    const commitment = 'persistent-test';

    await store.revoke(commitment);

    // Wait a bit to ensure no auto-expiration
    await new Promise((resolve) => setTimeout(resolve, 200));

    expect(await store.isRevoked(commitment)).to.equal(true);
  });

  it('handles empty revocation list', async () => {
    const store = new RedisRevocationStore(client, { key });

    await client.del(key);

    expect(await store.getRevokedCount()).to.equal(0);
    expect(await store.isRevoked('anything')).to.equal(false);
  });
});
