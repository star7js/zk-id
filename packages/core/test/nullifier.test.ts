import { expect } from 'chai';
import {
  createNullifierScope,
  computeNullifier,
  consumeNullifier,
  InMemoryNullifierStore,
  NullifierScope,
} from '../src/nullifier';
import { createCredential } from '../src/credential';

describe('Nullifier System', () => {
  describe('createNullifierScope', () => {
    it('should create a scope from a string identifier', async () => {
      const scope = await createNullifierScope('election-2026');
      expect(scope.id).to.equal('election-2026');
      expect(scope.scopeHash).to.be.a('string');
      expect(BigInt(scope.scopeHash)).to.be.a('bigint');
    });

    it('should produce deterministic scope hashes', async () => {
      const scope1 = await createNullifierScope('test-scope');
      const scope2 = await createNullifierScope('test-scope');
      expect(scope1.scopeHash).to.equal(scope2.scopeHash);
    });

    it('should produce different hashes for different scopes', async () => {
      const scope1 = await createNullifierScope('scope-a');
      const scope2 = await createNullifierScope('scope-b');
      expect(scope1.scopeHash).to.not.equal(scope2.scopeHash);
    });

    it('should reject empty scope ID', async () => {
      try {
        await createNullifierScope('');
        expect.fail('Should have thrown');
      } catch (e: any) {
        expect(e.message).to.match(/non-empty/);
      }
    });
  });

  describe('computeNullifier', () => {
    let scope: NullifierScope;

    before(async () => {
      scope = await createNullifierScope('test-election');
    });

    it('should compute a nullifier from commitment and scope', async () => {
      const credential = await createCredential(1990, 840);
      const result = await computeNullifier(credential.commitment, scope);

      expect(result.nullifier).to.be.a('string');
      expect(result.scope.id).to.equal('test-election');
      expect(result.commitment).to.equal(credential.commitment);
    });

    it('should be deterministic for same credential and scope', async () => {
      const credential = await createCredential(1985, 276);
      const result1 = await computeNullifier(credential.commitment, scope);
      const result2 = await computeNullifier(credential.commitment, scope);
      expect(result1.nullifier).to.equal(result2.nullifier);
    });

    it('should produce different nullifiers for different scopes', async () => {
      const credential = await createCredential(1995, 840);
      const scope2 = await createNullifierScope('different-scope');

      const result1 = await computeNullifier(credential.commitment, scope);
      const result2 = await computeNullifier(credential.commitment, scope2);

      expect(result1.nullifier).to.not.equal(result2.nullifier);
    });

    it('should produce different nullifiers for different credentials', async () => {
      const cred1 = await createCredential(1990, 840);
      const cred2 = await createCredential(1991, 840);

      const result1 = await computeNullifier(cred1.commitment, scope);
      const result2 = await computeNullifier(cred2.commitment, scope);

      expect(result1.nullifier).to.not.equal(result2.nullifier);
    });
  });

  describe('consumeNullifier', () => {
    it('should accept a fresh nullifier', async () => {
      const store = new InMemoryNullifierStore();
      const result = await consumeNullifier('nullifier-123', 'scope-1', store);
      expect(result.fresh).to.be.true;
      expect(result.error).to.be.undefined;
    });

    it('should reject a duplicate nullifier in the same scope', async () => {
      const store = new InMemoryNullifierStore();
      await consumeNullifier('nullifier-456', 'scope-1', store);
      const result = await consumeNullifier('nullifier-456', 'scope-1', store);
      expect(result.fresh).to.be.false;
      expect(result.error).to.match(/duplicate/i);
    });

    it('should allow the same nullifier in different scopes', async () => {
      const store = new InMemoryNullifierStore();
      await consumeNullifier('nullifier-789', 'scope-1', store);
      const result = await consumeNullifier('nullifier-789', 'scope-2', store);
      expect(result.fresh).to.be.true;
    });
  });

  describe('InMemoryNullifierStore', () => {
    it('should track used nullifiers per scope', async () => {
      const store = new InMemoryNullifierStore();

      expect(await store.hasBeenUsed('n1', 'scope-a')).to.be.false;
      await store.markUsed('n1', 'scope-a');
      expect(await store.hasBeenUsed('n1', 'scope-a')).to.be.true;
      expect(await store.hasBeenUsed('n1', 'scope-b')).to.be.false;
    });

    it('should count used nullifiers per scope', async () => {
      const store = new InMemoryNullifierStore();

      expect(await store.getUsedCount('scope-x')).to.equal(0);
      await store.markUsed('n1', 'scope-x');
      await store.markUsed('n2', 'scope-x');
      expect(await store.getUsedCount('scope-x')).to.equal(2);
      expect(await store.getUsedCount('scope-y')).to.equal(0);
    });

    it('should not double-count duplicate markUsed calls', async () => {
      const store = new InMemoryNullifierStore();
      await store.markUsed('n1', 'scope-z');
      await store.markUsed('n1', 'scope-z');
      expect(await store.getUsedCount('scope-z')).to.equal(1);
    });
  });

  describe('End-to-end: credential -> nullifier -> consume', () => {
    it('should prevent double-voting with same credential', async () => {
      const credential = await createCredential(1992, 840);
      const scope = await createNullifierScope('presidential-election-2026');
      const store = new InMemoryNullifierStore();

      const { nullifier } = await computeNullifier(credential.commitment, scope);

      // First vote: should succeed
      const vote1 = await consumeNullifier(nullifier, scope.id, store);
      expect(vote1.fresh).to.be.true;

      // Second vote with same credential: should fail
      const vote2 = await consumeNullifier(nullifier, scope.id, store);
      expect(vote2.fresh).to.be.false;
    });

    it('should allow same credential in different elections', async () => {
      const credential = await createCredential(1988, 276);
      const store = new InMemoryNullifierStore();

      const scope1 = await createNullifierScope('election-A');
      const scope2 = await createNullifierScope('election-B');

      const { nullifier: n1 } = await computeNullifier(credential.commitment, scope1);
      const { nullifier: n2 } = await computeNullifier(credential.commitment, scope2);

      // Different scopes produce different nullifiers
      expect(n1).to.not.equal(n2);

      // Both should succeed (different scopes)
      const r1 = await consumeNullifier(n1, scope1.id, store);
      const r2 = await consumeNullifier(n2, scope2.id, store);
      expect(r1.fresh).to.be.true;
      expect(r2.fresh).to.be.true;
    });
  });
});
