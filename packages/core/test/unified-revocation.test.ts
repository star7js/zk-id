import { strict as assert } from 'assert';
import {
  UnifiedRevocationManager,
  InMemoryIssuedCredentialIndex,
} from '../src/unified-revocation';
import { InMemoryValidCredentialTree } from '../src/valid-credential-tree';
import { createCredential } from '../src/credential';

describe('UnifiedRevocationManager', () => {
  let tree: InMemoryValidCredentialTree;
  let issuedIndex: InMemoryIssuedCredentialIndex;
  let manager: UnifiedRevocationManager;

  beforeEach(async () => {
    tree = new InMemoryValidCredentialTree(10);
    issuedIndex = new InMemoryIssuedCredentialIndex();
    manager = new UnifiedRevocationManager({ validTree: tree, issuedIndex });
  });

  describe('addCredential', () => {
    it('adds to the valid tree and issued index', async () => {
      const cred = await createCredential(1990, 840);
      await manager.addCredential(cred.commitment);

      assert.strictEqual(await manager.isValid(cred.commitment), true);
      assert.strictEqual(await manager.validCount(), 1);
      assert.strictEqual(await manager.issuedCount(), 1);
    });

    it('does not duplicate if added twice', async () => {
      const cred = await createCredential(1990, 840);
      await manager.addCredential(cred.commitment);
      await manager.addCredential(cred.commitment);

      assert.strictEqual(await manager.validCount(), 1);
      // Issued index is a Set, so also 1
      assert.strictEqual(await manager.issuedCount(), 1);
    });
  });

  describe('revokeCredential', () => {
    it('removes from tree but commitment remains in issued index', async () => {
      const cred = await createCredential(1990, 840);
      await manager.addCredential(cred.commitment);
      await manager.revokeCredential(cred.commitment);

      assert.strictEqual(await manager.isValid(cred.commitment), false);
      assert.strictEqual(await manager.isRevoked(cred.commitment), true);
      assert.strictEqual(await manager.validCount(), 0);
      // Still in issued index (append-only)
      assert.strictEqual(await manager.issuedCount(), 1);
    });

    it('removing a never-issued commitment results in unknown status', async () => {
      const cred = await createCredential(1990, 840);
      // Revoke without ever adding — tree remove is a no-op
      await manager.revokeCredential(cred.commitment);

      // Not in tree, not in issued index → unknown
      assert.strictEqual(await manager.isRevoked(cred.commitment), false);
      assert.strictEqual(await manager.getStatus(cred.commitment), 'unknown');
    });
  });

  describe('getStatus', () => {
    it('returns valid for active credentials', async () => {
      const cred = await createCredential(1990, 840);
      await manager.addCredential(cred.commitment);

      assert.strictEqual(await manager.getStatus(cred.commitment), 'valid');
    });

    it('returns revoked for issued-then-removed credentials', async () => {
      const cred = await createCredential(1990, 840);
      await manager.addCredential(cred.commitment);
      await manager.revokeCredential(cred.commitment);

      assert.strictEqual(await manager.getStatus(cred.commitment), 'revoked');
    });

    it('returns unknown for never-issued credentials', async () => {
      const cred = await createCredential(1990, 840);

      assert.strictEqual(await manager.getStatus(cred.commitment), 'unknown');
    });

    it('returns unknown when no issued index is configured', async () => {
      const treeOnly = new UnifiedRevocationManager({ validTree: tree });
      const cred = await createCredential(1990, 840);

      // Not in tree, no issued index → unknown
      assert.strictEqual(await treeOnly.getStatus(cred.commitment), 'unknown');
      assert.strictEqual(await treeOnly.isRevoked(cred.commitment), false);
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

    it('returns false for unknown credentials (never issued)', async () => {
      const cred = await createCredential(1990, 840);

      // Key difference from old design: unknown != revoked
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
      assert.strictEqual(await manager.getStatus(cred.commitment), 'valid');
    });

    it('issued index remains unchanged through reactivation', async () => {
      const cred = await createCredential(1990, 840);
      await manager.addCredential(cred.commitment);
      await manager.revokeCredential(cred.commitment);
      await manager.reactivateCredential(cred.commitment);

      // Issued index is append-only — still 1
      assert.strictEqual(await manager.issuedCount(), 1);
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

  describe('without issued index', () => {
    it('works with tree only', async () => {
      const treeOnly = new UnifiedRevocationManager({ validTree: tree });
      const cred = await createCredential(1990, 840);

      await treeOnly.addCredential(cred.commitment);
      assert.strictEqual(await treeOnly.isValid(cred.commitment), true);
      assert.strictEqual(await treeOnly.issuedCount(), 0); // no index

      await treeOnly.revokeCredential(cred.commitment);
      assert.strictEqual(await treeOnly.isValid(cred.commitment), false);
      // Without index, can't distinguish revoked from never-issued
      assert.strictEqual(await treeOnly.getStatus(cred.commitment), 'unknown');
    });
  });

  describe('InMemoryIssuedCredentialIndex', () => {
    it('record is idempotent', async () => {
      const idx = new InMemoryIssuedCredentialIndex();
      await idx.record('abc');
      await idx.record('abc');
      assert.strictEqual(await idx.issuedCount(), 1);
    });

    it('tracks multiple commitments', async () => {
      const idx = new InMemoryIssuedCredentialIndex();
      await idx.record('a');
      await idx.record('b');
      await idx.record('c');
      assert.strictEqual(await idx.issuedCount(), 3);
      assert.strictEqual(await idx.wasIssued('b'), true);
      assert.strictEqual(await idx.wasIssued('d'), false);
    });
  });

  describe('consistency — three-store separation', () => {
    it('stays in sync across add-revoke-reactivate cycle', async () => {
      const cred = await createCredential(1990, 840);

      // Add
      await manager.addCredential(cred.commitment);
      assert.strictEqual(await manager.getStatus(cred.commitment), 'valid');

      // Revoke
      await manager.revokeCredential(cred.commitment);
      assert.strictEqual(await manager.getStatus(cred.commitment), 'revoked');

      // Reactivate
      await manager.reactivateCredential(cred.commitment);
      assert.strictEqual(await manager.getStatus(cred.commitment), 'valid');
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

    it('handles multiple credentials with mixed statuses', async () => {
      const creds = await Promise.all([
        createCredential(1990, 840),
        createCredential(1995, 826),
        createCredential(2000, 276),
      ]);

      for (const c of creds) {
        await manager.addCredential(c.commitment);
      }
      assert.strictEqual(await manager.validCount(), 3);
      assert.strictEqual(await manager.issuedCount(), 3);

      await manager.revokeCredential(creds[1].commitment);
      assert.strictEqual(await manager.validCount(), 2);
      assert.strictEqual(await manager.issuedCount(), 3); // append-only

      assert.strictEqual(await manager.getStatus(creds[0].commitment), 'valid');
      assert.strictEqual(await manager.getStatus(creds[1].commitment), 'revoked');
      assert.strictEqual(await manager.getStatus(creds[2].commitment), 'valid');
    });
  });
});
