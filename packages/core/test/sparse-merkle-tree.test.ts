import { strict as assert } from 'assert';
import { SparseMerkleTree } from '../src/sparse-merkle-tree';
import { UnifiedRevocationManager, InMemoryIssuedCredentialIndex } from '../src/unified-revocation';
import { createCredential } from '../src/credential';
import { poseidonHash } from '../src/poseidon';

describe('SparseMerkleTree', () => {
  describe('basic operations', () => {
    it('starts empty with zero root', async () => {
      const tree = new SparseMerkleTree(3);
      assert.strictEqual(await tree.size(), 0);
      assert.strictEqual(await tree.contains('12345'), false);
      assert.strictEqual(await tree.getWitness('12345'), null);
    });

    it('adds and contains a credential', async () => {
      const tree = new SparseMerkleTree(10);
      const cred = await createCredential(1990, 840);

      await tree.add(cred.commitment);
      assert.strictEqual(await tree.size(), 1);
      assert.strictEqual(await tree.contains(cred.commitment), true);
    });

    it('removes a credential', async () => {
      const tree = new SparseMerkleTree(10);
      const cred = await createCredential(1990, 840);

      await tree.add(cred.commitment);
      await tree.remove(cred.commitment);

      assert.strictEqual(await tree.size(), 0);
      assert.strictEqual(await tree.contains(cred.commitment), false);
    });

    it('add is idempotent', async () => {
      const tree = new SparseMerkleTree(10);
      const cred = await createCredential(1990, 840);

      await tree.add(cred.commitment);
      const root1 = await tree.getRoot();

      await tree.add(cred.commitment);
      const root2 = await tree.getRoot();

      assert.strictEqual(await tree.size(), 1);
      assert.strictEqual(root1, root2);
    });

    it('remove is idempotent', async () => {
      const tree = new SparseMerkleTree(10);
      const cred = await createCredential(1990, 840);

      await tree.add(cred.commitment);
      await tree.remove(cred.commitment);
      const root1 = await tree.getRoot();

      await tree.remove(cred.commitment);
      const root2 = await tree.getRoot();

      assert.strictEqual(root1, root2);
    });

    it('remove on empty tree is a no-op', async () => {
      const tree = new SparseMerkleTree(10);
      await tree.remove('12345');
      assert.strictEqual(await tree.size(), 0);
    });

    it('rejects invalid commitment format', async () => {
      const tree = new SparseMerkleTree(10);
      await assert.rejects(() => tree.add('not-a-number'), /Invalid commitment format/);
    });
  });

  describe('constructor validation', () => {
    it('rejects depth 0', () => {
      assert.throws(() => new SparseMerkleTree(0), /Invalid SMT depth/);
    });

    it('rejects depth > 254', () => {
      assert.throws(() => new SparseMerkleTree(255), /Invalid SMT depth/);
    });

    it('accepts depth 1', async () => {
      const tree = new SparseMerkleTree(1);
      assert.strictEqual(tree.getDepth(), 1);
      assert.strictEqual(await tree.size(), 0);
    });
  });

  describe('Merkle root', () => {
    it('root changes when credentials are added', async () => {
      const tree = new SparseMerkleTree(10);
      const emptyRoot = await tree.getRoot();

      const cred = await createCredential(1990, 840);
      await tree.add(cred.commitment);
      const rootAfterAdd = await tree.getRoot();

      assert.notStrictEqual(emptyRoot, rootAfterAdd);
    });

    it('root returns to empty state after removing all credentials', async () => {
      const tree = new SparseMerkleTree(10);
      const emptyRoot = await tree.getRoot();

      const cred = await createCredential(1990, 840);
      await tree.add(cred.commitment);
      await tree.remove(cred.commitment);
      const rootAfterRemove = await tree.getRoot();

      assert.strictEqual(emptyRoot, rootAfterRemove);
    });

    it('different credentials produce different roots', async () => {
      const tree1 = new SparseMerkleTree(10);
      const tree2 = new SparseMerkleTree(10);

      const cred1 = await createCredential(1990, 840);
      const cred2 = await createCredential(1991, 826);

      await tree1.add(cred1.commitment);
      await tree2.add(cred2.commitment);

      assert.notStrictEqual(await tree1.getRoot(), await tree2.getRoot());
    });
  });

  describe('getRootInfo', () => {
    it('returns version 0 for empty tree', async () => {
      const tree = new SparseMerkleTree(10);
      const info = await tree.getRootInfo();
      assert.strictEqual(info.version, 0);
    });

    it('increments version on mutations', async () => {
      const tree = new SparseMerkleTree(10);
      const cred = await createCredential(1990, 840);

      await tree.add(cred.commitment);
      const info1 = await tree.getRootInfo();
      assert.strictEqual(info1.version, 1);

      await tree.remove(cred.commitment);
      const info2 = await tree.getRootInfo();
      assert.strictEqual(info2.version, 2);
    });

    it('does not increment version on idempotent add', async () => {
      const tree = new SparseMerkleTree(10);
      const cred = await createCredential(1990, 840);

      await tree.add(cred.commitment);
      await tree.add(cred.commitment); // no-op
      const info = await tree.getRootInfo();
      assert.strictEqual(info.version, 1);
    });
  });

  describe('membership witness', () => {
    it('generates a valid membership witness', async () => {
      const tree = new SparseMerkleTree(10);
      const cred = await createCredential(1990, 840);

      await tree.add(cred.commitment);
      const witness = await tree.getWitness(cred.commitment);

      assert.ok(witness);
      assert.strictEqual(witness!.pathIndices.length, 10);
      assert.strictEqual(witness!.siblings.length, 10);
    });

    it('witness root matches tree root', async () => {
      const tree = new SparseMerkleTree(10);
      const cred = await createCredential(1990, 840);

      await tree.add(cred.commitment);
      const witness = await tree.getWitness(cred.commitment);
      const root = await tree.getRoot();

      assert.strictEqual(witness!.root, root);
    });

    it('witness verifies via Poseidon recomputation', async () => {
      const tree = new SparseMerkleTree(5);
      const cred = await createCredential(1990, 840);

      await tree.add(cred.commitment);
      const witness = await tree.getWitness(cred.commitment);
      assert.ok(witness);

      // Recompute root from leaf + witness
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

    it('witness remains valid after adding other credentials', async () => {
      const tree = new SparseMerkleTree(10);
      const cred1 = await createCredential(1990, 840);
      const cred2 = await createCredential(1991, 826);

      await tree.add(cred1.commitment);
      await tree.add(cred2.commitment);

      // Witness for cred1 should still verify against the current root
      const witness = await tree.getWitness(cred1.commitment);
      assert.ok(witness);

      let current = BigInt(cred1.commitment);
      for (let i = 0; i < witness!.pathIndices.length; i++) {
        const sibling = BigInt(witness!.siblings[i]);
        if (witness!.pathIndices[i] === 0) {
          current = await poseidonHash([current, sibling]);
        } else {
          current = await poseidonHash([sibling, current]);
        }
      }

      assert.strictEqual(current.toString(), await tree.getRoot());
    });

    it('returns null for absent credential', async () => {
      const tree = new SparseMerkleTree(10);
      const cred = await createCredential(1990, 840);
      assert.strictEqual(await tree.getWitness(cred.commitment), null);
    });
  });

  describe('non-membership witness', () => {
    it('generates a non-membership witness for absent credential', async () => {
      const tree = new SparseMerkleTree(5);
      const cred1 = await createCredential(1990, 840);
      const absent = await createCredential(1991, 826);

      await tree.add(cred1.commitment);
      const witness = await tree.getNonMembershipWitness(absent.commitment);

      assert.ok(witness, 'should return a witness');
      assert.strictEqual(witness!.pathIndices.length, 5);
      assert.strictEqual(witness!.siblings.length, 5);
    });

    it('non-membership witness root matches tree root', async () => {
      const tree = new SparseMerkleTree(5);
      const cred = await createCredential(1990, 840);
      const absent = await createCredential(1991, 826);

      await tree.add(cred.commitment);
      const witness = await tree.getNonMembershipWitness(absent.commitment);

      assert.strictEqual(witness!.root, await tree.getRoot());
    });

    it('non-membership witness verifies with zero leaf', async () => {
      const tree = new SparseMerkleTree(5);
      const cred = await createCredential(1990, 840);
      const absent = await createCredential(1991, 826);

      await tree.add(cred.commitment);
      const witness = await tree.getNonMembershipWitness(absent.commitment);
      assert.ok(witness);

      // Recompute root starting from 0 (empty leaf)
      let current = 0n;
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

    it('returns null for credential that IS in tree', async () => {
      const tree = new SparseMerkleTree(5);
      const cred = await createCredential(1990, 840);

      await tree.add(cred.commitment);
      const witness = await tree.getNonMembershipWitness(cred.commitment);

      assert.strictEqual(witness, null);
    });

    it('works on empty tree', async () => {
      const tree = new SparseMerkleTree(5);
      const cred = await createCredential(1990, 840);

      const witness = await tree.getNonMembershipWitness(cred.commitment);
      assert.ok(witness);

      // All siblings should be zero hashes since tree is empty
      let current = 0n;
      for (let i = 0; i < witness!.pathIndices.length; i++) {
        const sibling = BigInt(witness!.siblings[i]);
        if (witness!.pathIndices[i] === 0) {
          current = await poseidonHash([current, sibling]);
        } else {
          current = await poseidonHash([sibling, current]);
        }
      }
      assert.strictEqual(current.toString(), await tree.getRoot());
    });

    it('returns null when leaf is occupied by another commitment', async () => {
      const depth = 2;
      const tree = new SparseMerkleTree(depth);
      const mask = (1n << BigInt(depth)) - 1n;

      const seen = new Map<bigint, bigint>();
      let first: bigint | null = null;
      let second: bigint | null = null;

      for (let i = 1n; i < 500n; i++) {
        const hash = await poseidonHash([i]);
        const index = hash & mask;
        const existing = seen.get(index);
        if (existing !== undefined && existing !== i) {
          first = existing;
          second = i;
          break;
        }
        seen.set(index, i);
      }

      assert.ok(first !== null && second !== null, 'should find a collision');

      await tree.add(first!.toString());
      const witness = await tree.getNonMembershipWitness(second!.toString());
      assert.strictEqual(witness, null);
    });
  });

  describe('sparse storage efficiency', () => {
    it('nodeCount grows proportionally to entries, not tree size', async () => {
      const tree = new SparseMerkleTree(20); // 2^20 = 1M possible leaves
      assert.strictEqual(tree.nodeCount(), 0);

      const cred = await createCredential(1990, 840);
      await tree.add(cred.commitment);

      // Should have at most depth + 1 nodes (leaf + one parent per level)
      assert.ok(tree.nodeCount() <= 21);
    });

    it('nodeCount decreases when credentials are removed', async () => {
      const tree = new SparseMerkleTree(10);
      const cred = await createCredential(1990, 840);

      await tree.add(cred.commitment);
      const countAfterAdd = tree.nodeCount();

      await tree.remove(cred.commitment);
      const countAfterRemove = tree.nodeCount();

      assert.ok(countAfterRemove < countAfterAdd);
      assert.strictEqual(countAfterRemove, 0); // back to empty
    });
  });

  describe('multiple credentials', () => {
    it('handles 50 credentials', async () => {
      const tree = new SparseMerkleTree(20);
      const creds = await Promise.all(
        Array.from({ length: 50 }, (_, i) => createCredential(1970 + i, 1 + (i % 200))),
      );

      for (const c of creds) {
        await tree.add(c.commitment);
      }

      assert.strictEqual(await tree.size(), 50);
      for (const c of creds) {
        assert.strictEqual(await tree.contains(c.commitment), true);
        const w = await tree.getWitness(c.commitment);
        assert.ok(w);
        assert.strictEqual(w!.root, await tree.getRoot());
      }
    });

    it('handles interleaved add/remove', async () => {
      const tree = new SparseMerkleTree(10);
      const creds = await Promise.all(
        Array.from({ length: 10 }, (_, i) => createCredential(1980 + i, 840)),
      );

      // Add all
      for (const c of creds) {
        await tree.add(c.commitment);
      }

      // Remove odd-indexed
      for (let i = 1; i < creds.length; i += 2) {
        await tree.remove(creds[i].commitment);
      }

      assert.strictEqual(await tree.size(), 5);
      for (let i = 0; i < creds.length; i++) {
        if (i % 2 === 0) {
          assert.strictEqual(await tree.contains(creds[i].commitment), true);
        } else {
          assert.strictEqual(await tree.contains(creds[i].commitment), false);
        }
      }
    });
  });

  describe('integration with UnifiedRevocationManager', () => {
    it('works as ValidCredentialTree drop-in', async () => {
      const tree = new SparseMerkleTree(10);
      const issuedIndex = new InMemoryIssuedCredentialIndex();
      const manager = new UnifiedRevocationManager({
        validTree: tree,
        issuedIndex,
      });

      const cred = await createCredential(1990, 840);
      await manager.addCredential(cred.commitment);

      assert.strictEqual(await manager.getStatus(cred.commitment), 'valid');
      assert.strictEqual(await manager.validCount(), 1);
      assert.strictEqual(await manager.issuedCount(), 1);

      await manager.revokeCredential(cred.commitment);
      assert.strictEqual(await manager.getStatus(cred.commitment), 'revoked');
      assert.strictEqual(await manager.validCount(), 0);
      assert.strictEqual(await manager.issuedCount(), 1);
    });

    it('reactivation works through manager', async () => {
      const tree = new SparseMerkleTree(10);
      const issuedIndex = new InMemoryIssuedCredentialIndex();
      const manager = new UnifiedRevocationManager({
        validTree: tree,
        issuedIndex,
      });

      const cred = await createCredential(1990, 840);
      await manager.addCredential(cred.commitment);
      await manager.revokeCredential(cred.commitment);
      await manager.reactivateCredential(cred.commitment);

      assert.strictEqual(await manager.getStatus(cred.commitment), 'valid');
    });

    it('non-membership witness available for revoked credentials', async () => {
      const tree = new SparseMerkleTree(10);
      const issuedIndex = new InMemoryIssuedCredentialIndex();
      const manager = new UnifiedRevocationManager({
        validTree: tree,
        issuedIndex,
      });

      const cred = await createCredential(1990, 840);
      await manager.addCredential(cred.commitment);
      await manager.revokeCredential(cred.commitment);

      // After revocation, the sparse tree can prove non-membership
      const nmWitness = await tree.getNonMembershipWitness(cred.commitment);
      assert.ok(nmWitness, 'should get non-membership witness for revoked credential');

      // Verify: recompute root from zero leaf
      let current = 0n;
      for (let i = 0; i < nmWitness!.pathIndices.length; i++) {
        const sibling = BigInt(nmWitness!.siblings[i]);
        if (nmWitness!.pathIndices[i] === 0) {
          current = await poseidonHash([current, sibling]);
        } else {
          current = await poseidonHash([sibling, current]);
        }
      }
      assert.strictEqual(current.toString(), await tree.getRoot());
    });
  });

  describe('concurrent operations', () => {
    it('handles concurrent adds', async () => {
      const tree = new SparseMerkleTree(20);
      const creds = await Promise.all(
        Array.from({ length: 20 }, (_, i) => createCredential(1970 + i, 1 + (i % 200))),
      );

      await Promise.all(creds.map((c) => tree.add(c.commitment)));
      assert.strictEqual(await tree.size(), 20);
    });

    it('handles concurrent getWitness calls', async () => {
      const tree = new SparseMerkleTree(10);
      const creds = await Promise.all(
        Array.from({ length: 5 }, (_, i) => createCredential(1970 + i, 1 + (i % 200))),
      );

      for (const c of creds) {
        await tree.add(c.commitment);
      }

      const witnesses = await Promise.all(creds.map((c) => tree.getWitness(c.commitment)));

      const root = await tree.getRoot();
      for (const w of witnesses) {
        assert.ok(w);
        assert.strictEqual(w!.root, root);
      }
    });
  });
});
