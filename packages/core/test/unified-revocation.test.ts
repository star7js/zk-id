import { strict as assert } from 'assert';
import { UnifiedRevocationManager, UnifiedRevocationConfig } from '../src/unified-revocation';
import { InMemoryValidCredentialTree } from '../src/valid-credential-tree';
import { InMemoryRevocationStore } from '../src/revocation';
import { createCredential } from '../src/credential';

describe('UnifiedRevocationManager', () => {
  let tree: InMemoryValidCredentialTree;
  let store: InMemoryRevocationStore;
  let manager: UnifiedRevocationManager;

  beforeEach(async () => {
    tree = new InMemoryValidCredentialTree(10);
    store = new InMemoryRevocationStore();
    manager = new UnifiedRevocationManager({ validTree: tree, revocationStore: store });
  });

  describe('addCredential', () => {
    it('adds a credential to the valid tree', async () => {
      const cred = await createCredential(1990, 840);
      await manager.addCredential(cred.commitment);

      assert.strictEqual(await manager.isValid(cred.commitment), true);
      assert.strictEqual(await manager.validCount(), 1);
    });

    it('does not duplicate if added twice', async () => {
      const cred = await createCredential(1990, 840);
      await manager.addCredential(cred.commitment);
      await manager.addCredential(cred.commitment);

      assert.strictEqual(await manager.validCount(), 1);
    });
  });

  describe('revokeCredential', () => {
    it('removes from valid tree and adds to blacklist', async () => {
      const cred = await createCredential(1990, 840);
      await manager.addCredential(cred.commitment);
      await manager.revokeCredential(cred.commitment);

      assert.strictEqual(await manager.isValid(cred.commitment), false);
      assert.strictEqual(await manager.isRevoked(cred.commitment), true);
      assert.strictEqual(await manager.validCount(), 0);
      assert.strictEqual(await manager.revokedCount(), 1);
    });

    it('records in blacklist even if not in tree', async () => {
      const cred = await createCredential(1990, 840);
      await manager.revokeCredential(cred.commitment);

      assert.strictEqual(await manager.isRevoked(cred.commitment), true);
      assert.strictEqual(await manager.revokedCount(), 1);
    });
  });

  describe('isRevoked', () => {
    it('returns false for active credentials', async () => {
      const cred = await createCredential(1990, 840);
      await manager.addCredential(cred.commitment);

      assert.strictEqual(await manager.isRevoked(cred.commitment), false);
    });

    it('returns true for revoked credentials', async () => {
      const cred = await createCredential(1990, 840);
      await manager.addCredential(cred.commitment);
      await manager.revokeCredential(cred.commitment);

      assert.strictEqual(await manager.isRevoked(cred.commitment), true);
    });

    it('returns true for unknown credentials without blacklist', async () => {
      const treeOnly = new UnifiedRevocationManager({ validTree: tree });
      const cred = await createCredential(1990, 840);

      // Not in tree, no blacklist → treated as revoked
      assert.strictEqual(await treeOnly.isRevoked(cred.commitment), true);
    });

    it('checks blacklist for unknown credentials', async () => {
      const cred = await createCredential(1990, 840);

      // Not in tree, not in blacklist → not revoked (never issued)
      assert.strictEqual(await manager.isRevoked(cred.commitment), false);
    });
  });

  describe('reactivateCredential', () => {
    it('re-adds to tree after revocation', async () => {
      const cred = await createCredential(1990, 840);
      await manager.addCredential(cred.commitment);
      await manager.revokeCredential(cred.commitment);

      assert.strictEqual(await manager.isValid(cred.commitment), false);

      await manager.reactivateCredential(cred.commitment);

      assert.strictEqual(await manager.isValid(cred.commitment), true);
      assert.strictEqual(await manager.isRevoked(cred.commitment), false);
    });

    it('preserves revocation audit trail', async () => {
      const cred = await createCredential(1990, 840);
      await manager.addCredential(cred.commitment);
      await manager.revokeCredential(cred.commitment);
      await manager.reactivateCredential(cred.commitment);

      // Blacklist still has the record (audit trail)
      assert.strictEqual(await manager.revokedCount(), 1);
      // But credential is valid again
      assert.strictEqual(await manager.isValid(cred.commitment), true);
    });
  });

  describe('tree accessors', () => {
    it('getRoot returns a valid root', async () => {
      const root = await manager.getRoot();
      assert.ok(root);
      assert.strictEqual(typeof root, 'string');
    });

    it('getRootInfo returns metadata', async () => {
      const info = await manager.getRootInfo();
      assert.ok(info);
      assert.ok(info!.root);
      assert.strictEqual(typeof info!.version, 'number');
    });

    it('getWitness returns null for missing credential', async () => {
      const cred = await createCredential(1990, 840);
      const witness = await manager.getWitness(cred.commitment);
      assert.strictEqual(witness, null);
    });

    it('getWitness returns valid witness for existing credential', async () => {
      const cred = await createCredential(1990, 840);
      await manager.addCredential(cred.commitment);
      const witness = await manager.getWitness(cred.commitment);

      assert.ok(witness);
      assert.ok(witness!.root);
      assert.ok(witness!.pathIndices);
      assert.ok(witness!.siblings);
      assert.strictEqual(witness!.pathIndices.length, 10); // depth=10
    });
  });

  describe('without revocation store', () => {
    it('works with tree only', async () => {
      const treeOnly = new UnifiedRevocationManager({ validTree: tree });
      const cred = await createCredential(1990, 840);

      await treeOnly.addCredential(cred.commitment);
      assert.strictEqual(await treeOnly.isValid(cred.commitment), true);
      assert.strictEqual(await treeOnly.revokedCount(), 0);

      await treeOnly.revokeCredential(cred.commitment);
      assert.strictEqual(await treeOnly.isValid(cred.commitment), false);
    });
  });

  describe('consistency between stores', () => {
    it('stays in sync across add-revoke-reactivate cycle', async () => {
      const cred = await createCredential(1990, 840);

      // Add
      await manager.addCredential(cred.commitment);
      assert.strictEqual(await manager.isValid(cred.commitment), true);
      assert.strictEqual(await manager.isRevoked(cred.commitment), false);

      // Revoke
      await manager.revokeCredential(cred.commitment);
      assert.strictEqual(await manager.isValid(cred.commitment), false);
      assert.strictEqual(await manager.isRevoked(cred.commitment), true);

      // Reactivate
      await manager.reactivateCredential(cred.commitment);
      assert.strictEqual(await manager.isValid(cred.commitment), true);
      assert.strictEqual(await manager.isRevoked(cred.commitment), false);
    });

    it('root changes on mutations', async () => {
      const root0 = await manager.getRoot();
      const cred = await createCredential(1990, 840);

      await manager.addCredential(cred.commitment);
      const root1 = await manager.getRoot();
      assert.notStrictEqual(root0, root1);

      await manager.revokeCredential(cred.commitment);
      const root2 = await manager.getRoot();
      assert.notStrictEqual(root1, root2);
    });

    it('handles multiple credentials', async () => {
      const creds = await Promise.all([
        createCredential(1990, 840),
        createCredential(1995, 826),
        createCredential(2000, 276),
      ]);

      for (const c of creds) {
        await manager.addCredential(c.commitment);
      }
      assert.strictEqual(await manager.validCount(), 3);

      await manager.revokeCredential(creds[1].commitment);
      assert.strictEqual(await manager.validCount(), 2);
      assert.strictEqual(await manager.revokedCount(), 1);

      assert.strictEqual(await manager.isValid(creds[0].commitment), true);
      assert.strictEqual(await manager.isValid(creds[1].commitment), false);
      assert.strictEqual(await manager.isValid(creds[2].commitment), true);
    });
  });
});
