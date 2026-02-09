import { expect } from 'chai';
import { generateKeyPairSync } from 'crypto';
import { RedisIssuerRegistry } from '../src/issuer-registry';
import type { IssuerRecord } from '@zk-id/sdk';

const REDIS_URL =
  process.env.ZKID_REDIS_URL || process.env.REDIS_URL;

describe('RedisIssuerRegistry', function () {
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
  const keyPrefix = `zkid:test:${Date.now()}:issuer:`;

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

  it('returns null for issuers that do not exist', async () => {
    const registry = new RedisIssuerRegistry(client, { keyPrefix });
    expect(await registry.getIssuer('nonexistent')).to.equal(null);
  });

  it('stores and retrieves issuer records', async () => {
    const registry = new RedisIssuerRegistry(client, { keyPrefix });
    const { publicKey } = generateKeyPairSync('ed25519');

    const record: IssuerRecord = {
      issuer: 'test-issuer-1',
      publicKey,
      status: 'active',
    };

    await registry.setIssuer(record);
    const retrieved = await registry.getIssuer('test-issuer-1');

    expect(retrieved).to.not.equal(null);
    expect(retrieved!.issuer).to.equal('test-issuer-1');
    expect(retrieved!.status).to.equal('active');
    expect(retrieved!.publicKey.asymmetricKeyType).to.equal('ed25519');
  });

  it('preserves all optional fields', async () => {
    const registry = new RedisIssuerRegistry(client, { keyPrefix });
    const { publicKey } = generateKeyPairSync('ed25519');

    const record: IssuerRecord = {
      issuer: 'test-issuer-2',
      publicKey,
      status: 'active',
      validFrom: '2024-01-01T00:00:00Z',
      validTo: '2025-12-31T23:59:59Z',
      jurisdiction: 'US',
      policyUrl: 'https://example.com/policy',
      auditUrl: 'https://example.com/audit',
    };

    await registry.setIssuer(record);
    const retrieved = await registry.getIssuer('test-issuer-2');

    expect(retrieved).to.not.equal(null);
    expect(retrieved!.issuer).to.equal('test-issuer-2');
    expect(retrieved!.status).to.equal('active');
    expect(retrieved!.validFrom).to.equal('2024-01-01T00:00:00Z');
    expect(retrieved!.validTo).to.equal('2025-12-31T23:59:59Z');
    expect(retrieved!.jurisdiction).to.equal('US');
    expect(retrieved!.policyUrl).to.equal('https://example.com/policy');
    expect(retrieved!.auditUrl).to.equal('https://example.com/audit');
  });

  it('handles different status values', async () => {
    const registry = new RedisIssuerRegistry(client, { keyPrefix });
    const { publicKey } = generateKeyPairSync('ed25519');

    const statuses: Array<'active' | 'revoked' | 'suspended'> = ['active', 'revoked', 'suspended'];

    for (const status of statuses) {
      const record: IssuerRecord = {
        issuer: `issuer-${status}`,
        publicKey,
        status,
      };

      await registry.setIssuer(record);
      const retrieved = await registry.getIssuer(`issuer-${status}`);

      expect(retrieved!.status).to.equal(status);
    }
  });

  it('updates existing issuer records', async () => {
    const registry = new RedisIssuerRegistry(client, { keyPrefix });
    const { publicKey: key1 } = generateKeyPairSync('ed25519');
    const { publicKey: key2 } = generateKeyPairSync('ed25519');

    const record1: IssuerRecord = {
      issuer: 'update-test',
      publicKey: key1,
      status: 'active',
    };

    await registry.setIssuer(record1);

    const record2: IssuerRecord = {
      issuer: 'update-test',
      publicKey: key2,
      status: 'suspended',
    };

    await registry.setIssuer(record2);
    const retrieved = await registry.getIssuer('update-test');

    expect(retrieved!.status).to.equal('suspended');
    // Keys should be different
    expect(retrieved!.publicKey.export({ type: 'spki', format: 'pem' }))
      .to.equal(key2.export({ type: 'spki', format: 'pem' }));
  });

  it('removes issuer records', async () => {
    const registry = new RedisIssuerRegistry(client, { keyPrefix });
    const { publicKey } = generateKeyPairSync('ed25519');

    const record: IssuerRecord = {
      issuer: 'remove-test',
      publicKey,
      status: 'active',
    };

    await registry.setIssuer(record);
    expect(await registry.getIssuer('remove-test')).to.not.equal(null);

    await registry.removeIssuer('remove-test');
    expect(await registry.getIssuer('remove-test')).to.equal(null);
  });

  it('handles multiple issuers independently', async () => {
    const registry = new RedisIssuerRegistry(client, { keyPrefix });

    const issuers = ['issuer-a', 'issuer-b', 'issuer-c'];

    for (const issuer of issuers) {
      const { publicKey } = generateKeyPairSync('ed25519');
      await registry.setIssuer({ issuer, publicKey });
    }

    for (const issuer of issuers) {
      const retrieved = await registry.getIssuer(issuer);
      expect(retrieved).to.not.equal(null);
      expect(retrieved!.issuer).to.equal(issuer);
    }
  });

  it('correctly serializes and deserializes public keys', async () => {
    const registry = new RedisIssuerRegistry(client, { keyPrefix });
    const { publicKey } = generateKeyPairSync('ed25519');

    const originalPem = publicKey.export({ type: 'spki', format: 'pem' });

    await registry.setIssuer({ issuer: 'key-test', publicKey });
    const retrieved = await registry.getIssuer('key-test');

    const retrievedPem = retrieved!.publicKey.export({ type: 'spki', format: 'pem' });
    expect(retrievedPem).to.equal(originalPem);
  });
});
