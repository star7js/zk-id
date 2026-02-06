import { expect } from 'chai';
import { InMemoryNonceStore, SimpleRateLimiter } from '../src/server';

describe('SDK Server Tests', () => {
  describe('InMemoryNonceStore', () => {
    let store: InMemoryNonceStore;

    beforeEach(() => {
      store = new InMemoryNonceStore();
    });

    it('should not have unused nonce', async () => {
      const nonce = 'test-nonce-123';
      const has = await store.has(nonce);
      expect(has).to.be.false;
    });

    it('should store and retrieve nonce', async () => {
      const nonce = 'test-nonce-456';

      await store.add(nonce);
      const has = await store.has(nonce);

      expect(has).to.be.true;
    });

    it('should handle multiple nonces', async () => {
      const nonce1 = 'nonce-1';
      const nonce2 = 'nonce-2';
      const nonce3 = 'nonce-3';

      await store.add(nonce1);
      await store.add(nonce2);

      expect(await store.has(nonce1)).to.be.true;
      expect(await store.has(nonce2)).to.be.true;
      expect(await store.has(nonce3)).to.be.false;
    });
  });

  describe('SimpleRateLimiter', () => {
    it('should allow requests within limit', async () => {
      const limiter = new SimpleRateLimiter(5, 60000);
      const identifier = 'user-123';

      for (let i = 0; i < 5; i++) {
        const allowed = await limiter.allowRequest(identifier);
        expect(allowed).to.be.true;
      }
    });

    it('should block requests exceeding limit', async () => {
      const limiter = new SimpleRateLimiter(3, 60000);
      const identifier = 'user-456';

      // First 3 should be allowed
      for (let i = 0; i < 3; i++) {
        const allowed = await limiter.allowRequest(identifier);
        expect(allowed).to.be.true;
      }

      // 4th should be blocked
      const blocked = await limiter.allowRequest(identifier);
      expect(blocked).to.be.false;
    });

    it('should track different identifiers independently', async () => {
      const limiter = new SimpleRateLimiter(2, 60000);

      await limiter.allowRequest('user-1');
      await limiter.allowRequest('user-1');

      await limiter.allowRequest('user-2');
      await limiter.allowRequest('user-2');

      // Both should be at limit
      expect(await limiter.allowRequest('user-1')).to.be.false;
      expect(await limiter.allowRequest('user-2')).to.be.false;
    });
  });
});
