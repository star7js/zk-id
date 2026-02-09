import { strict as assert } from 'assert';
import { InMemoryValidCredentialTree } from '../src/valid-credential-tree';
import { UnifiedRevocationManager, InMemoryIssuedCredentialIndex } from '../src/unified-revocation';
import { createCredential } from '../src/credential';
import { poseidonHash } from '../src/poseidon';

describe('Boundary and Concurrency Tests', () => {
  describe('InMemoryValidCredentialTree - boundary conditions', () => {
    it('handles depth=1 tree (2 leaves max)', async () => {
      const tree = new InMemoryValidCredentialTree(1);
      const c1 = await createCredential(1990, 840);
      const c2 = await createCredential(1991, 826);

      await tree.add(c1.commitment);
      await tree.add(c2.commitment);

      assert.strictEqual(await tree.size(), 2);
      assert.strictEqual(await tree.contains(c1.commitment), true);
      assert.strictEqual(await tree.contains(c2.commitment), true);
    });

    it('rejects when depth=1 tree is full', async () => {
      const tree = new InMemoryValidCredentialTree(1);
      const c1 = await createCredential(1990, 840);
      const c2 = await createCredential(1991, 826);
      const c3 = await createCredential(1992, 276);

      await tree.add(c1.commitment);
      await tree.add(c2.commitment);

      await assert.rejects(
        () => tree.add(c3.commitment),
        /tree is full/
      );
    });

    it('allows re-adding after removal in a full tree', async () => {
      const tree = new InMemoryValidCredentialTree(1);
      const c1 = await createCredential(1990, 840);
      const c2 = await createCredential(1991, 826);
      const c3 = await createCredential(1992, 276);

      await tree.add(c1.commitment);
      await tree.add(c2.commitment);
      await tree.remove(c1.commitment);

      // Should succeed — freed slot
      await tree.add(c3.commitment);
      assert.strictEqual(await tree.size(), 2);
      assert.strictEqual(await tree.contains(c3.commitment), true);
    });

    it('handles empty tree operations', async () => {
      const tree = new InMemoryValidCredentialTree(10);

      assert.strictEqual(await tree.size(), 0);
      assert.strictEqual(await tree.contains('12345'), false);
      assert.strictEqual(await tree.getWitness('12345'), null);

      // Remove from empty tree should be a no-op
      await tree.remove('12345');
      assert.strictEqual(await tree.size(), 0);
    });

    it('rejects invalid commitment format', async () => {
      const tree = new InMemoryValidCredentialTree(10);

      await assert.rejects(
        () => tree.add('not-a-number'),
        /Invalid commitment format/
      );
    });

    it('rejects invalid depth', () => {
      assert.throws(
        () => new InMemoryValidCredentialTree(0),
        /Invalid Merkle depth/
      );
      assert.throws(
        () => new InMemoryValidCredentialTree(21),
        /Invalid Merkle depth/
      );
    });

    it('add is idempotent', async () => {
      const tree = new InMemoryValidCredentialTree(10);
      const cred = await createCredential(1990, 840);

      await tree.add(cred.commitment);
      const root1 = await tree.getRoot();

      await tree.add(cred.commitment);
      const root2 = await tree.getRoot();

      assert.strictEqual(await tree.size(), 1);
      assert.strictEqual(root1, root2);
    });

    it('remove is idempotent', async () => {
      const tree = new InMemoryValidCredentialTree(10);
      const cred = await createCredential(1990, 840);

      await tree.add(cred.commitment);
      await tree.remove(cred.commitment);

      const root1 = await tree.getRoot();

      await tree.remove(cred.commitment);
      const root2 = await tree.getRoot();

      assert.strictEqual(root1, root2);
    });

    it('getRootInfo increments version on mutations', async () => {
      const tree = new InMemoryValidCredentialTree(10);
      const cred = await createCredential(1990, 840);

      const info0 = await tree.getRootInfo();
      assert.strictEqual(info0.version, 0);

      await tree.add(cred.commitment);
      const info1 = await tree.getRootInfo();
      assert.strictEqual(info1.version, 1);

      await tree.remove(cred.commitment);
      const info2 = await tree.getRootInfo();
      assert.strictEqual(info2.version, 2);
    });

    it('witness is correct (round-trip verification)', async () => {
      const tree = new InMemoryValidCredentialTree(3); // depth 3 = 8 leaves
      const cred = await createCredential(1990, 840);

      await tree.add(cred.commitment);
      const witness = await tree.getWitness(cred.commitment);

      assert.ok(witness);
      assert.strictEqual(witness!.pathIndices.length, 3);
      assert.strictEqual(witness!.siblings.length, 3);

      // Recompute root from witness
      let current = BigInt(cred.commitment);
      for (let i = 0; i < witness!.pathIndices.length; i++) {
        const sibling = BigInt(witness!.siblings[i]);
        if (witness!.pathIndices[i] === 0) {
          current = await poseidonHash([current, sibling]);
        } else {
          current = await poseidonHash([sibling, current]);
        }
      }

      assert.strictEqual(current.toString(), witness!.root);
      assert.strictEqual(current.toString(), await tree.getRoot());
    });
  });

  describe('InMemoryIssuedCredentialIndex - boundary conditions', () => {
    it('wasIssued returns false for unrecorded commitment', async () => {
      const index = new InMemoryIssuedCredentialIndex();
      assert.strictEqual(await index.wasIssued('12345'), false);
    });

    it('record is idempotent', async () => {
      const index = new InMemoryIssuedCredentialIndex();
      await index.record('12345');
      await index.record('12345');
      assert.strictEqual(await index.issuedCount(), 1);
    });

    it('handles many records', async () => {
      const index = new InMemoryIssuedCredentialIndex();
      for (let i = 0; i < 1000; i++) {
        await index.record(`commitment-${i}`);
      }
      assert.strictEqual(await index.issuedCount(), 1000);
      assert.strictEqual(await index.wasIssued('commitment-500'), true);
      assert.strictEqual(await index.wasIssued('commitment-1001'), false);
    });
  });

  describe('Concurrent operations', () => {
    it('handles concurrent adds to tree', async () => {
      const tree = new InMemoryValidCredentialTree(10);
      const creds = await Promise.all(
        Array.from({ length: 20 }, (_, i) =>
          createCredential(1970 + i, 1 + (i % 200))
        )
      );

      // Add all concurrently
      await Promise.all(creds.map((c) => tree.add(c.commitment)));

      assert.strictEqual(await tree.size(), 20);
      for (const c of creds) {
        assert.strictEqual(await tree.contains(c.commitment), true);
      }
    });

    it('handles concurrent add + remove on different credentials', async () => {
      const tree = new InMemoryValidCredentialTree(10);
      const creds = await Promise.all(
        Array.from({ length: 10 }, (_, i) =>
          createCredential(1970 + i, 1 + (i % 200))
        )
      );

      // Add first 5
      for (let i = 0; i < 5; i++) {
        await tree.add(creds[i].commitment);
      }

      // Concurrently add 5 more and remove the first 5
      await Promise.all([
        ...creds.slice(5).map((c) => tree.add(c.commitment)),
        ...creds.slice(0, 5).map((c) => tree.remove(c.commitment)),
      ]);

      assert.strictEqual(await tree.size(), 5);
      for (let i = 0; i < 5; i++) {
        assert.strictEqual(await tree.contains(creds[i].commitment), false);
      }
      for (let i = 5; i < 10; i++) {
        assert.strictEqual(await tree.contains(creds[i].commitment), true);
      }
    });

    it('handles concurrent revocations through UnifiedRevocationManager', async () => {
      const tree = new InMemoryValidCredentialTree(10);
      const issuedIndex = new InMemoryIssuedCredentialIndex();
      const manager = new UnifiedRevocationManager({ validTree: tree, issuedIndex });

      const creds = await Promise.all(
        Array.from({ length: 10 }, (_, i) =>
          createCredential(1970 + i, 1 + (i % 200))
        )
      );

      // Add all
      for (const c of creds) {
        await manager.addCredential(c.commitment);
      }

      // Revoke all concurrently
      await Promise.all(creds.map((c) => manager.revokeCredential(c.commitment)));

      assert.strictEqual(await manager.validCount(), 0);
      assert.strictEqual(await manager.issuedCount(), 10);

      for (const c of creds) {
        assert.strictEqual(await manager.getStatus(c.commitment), 'revoked');
      }
    });

    it('handles concurrent status checks', async () => {
      const tree = new InMemoryValidCredentialTree(10);
      const issuedIndex = new InMemoryIssuedCredentialIndex();
      const manager = new UnifiedRevocationManager({ validTree: tree, issuedIndex });

      const creds = await Promise.all(
        Array.from({ length: 10 }, (_, i) =>
          createCredential(1970 + i, 1 + (i % 200))
        )
      );

      for (const c of creds) {
        await manager.addCredential(c.commitment);
      }

      // Revoke half
      for (let i = 0; i < 5; i++) {
        await manager.revokeCredential(creds[i].commitment);
      }

      // Check all concurrently
      const results = await Promise.all(
        creds.map((c) => manager.getStatus(c.commitment))
      );

      for (let i = 0; i < 5; i++) {
        assert.strictEqual(results[i], 'revoked', `cred ${i} should be revoked`);
      }
      for (let i = 5; i < 10; i++) {
        assert.strictEqual(results[i], 'valid', `cred ${i} should be valid`);
      }
    });

    it('handles concurrent getWitness calls', async () => {
      const tree = new InMemoryValidCredentialTree(10);
      const creds = await Promise.all(
        Array.from({ length: 5 }, (_, i) =>
          createCredential(1970 + i, 1 + (i % 200))
        )
      );

      for (const c of creds) {
        await tree.add(c.commitment);
      }

      // Get all witnesses concurrently
      const witnesses = await Promise.all(
        creds.map((c) => tree.getWitness(c.commitment))
      );

      const root = await tree.getRoot();
      for (const w of witnesses) {
        assert.ok(w);
        assert.strictEqual(w!.root, root);
      }
    });
  });

  describe('Poseidon hash boundary conditions', () => {
    it('handles zero inputs', async () => {
      const hash = await poseidonHash([0n]);
      assert.ok(hash > 0n);
    });

    it('handles large inputs within field order', async () => {
      const largeVal = (1n << 253n) - 1n; // Large but within BN128 field
      const hash = await poseidonHash([largeVal]);
      assert.ok(hash >= 0n);
    });

    it('produces different hashes for different input counts', async () => {
      const h1 = await poseidonHash([1n, 2n]);
      const h2 = await poseidonHash([1n, 2n, 3n]);
      assert.notStrictEqual(h1, h2);
    });

    it('is deterministic', async () => {
      const h1 = await poseidonHash([42n, 100n]);
      const h2 = await poseidonHash([42n, 100n]);
      assert.strictEqual(h1, h2);
    });
  });

  describe('Credential creation boundary conditions', () => {
    it('handles minimum valid birth year', async () => {
      const cred = await createCredential(1900, 1);
      assert.strictEqual(cred.birthYear, 1900);
      assert.strictEqual(cred.nationality, 1);
    });

    it('handles maximum valid nationality', async () => {
      const cred = await createCredential(2000, 999);
      assert.strictEqual(cred.nationality, 999);
    });

    it('handles current year as birth year', async () => {
      const currentYear = new Date().getFullYear();
      const cred = await createCredential(currentYear, 840);
      assert.strictEqual(cred.birthYear, currentYear);
    });
  });
});
