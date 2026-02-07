import { expect } from 'chai';
import { InMemoryRevocationStore } from '../src/revocation';

describe('Revocation Tests', () => {
  let store: InMemoryRevocationStore;

  beforeEach(() => {
    store = new InMemoryRevocationStore();
  });

  describe('InMemoryRevocationStore', () => {
    it('should not have credentials revoked by default', async () => {
      const isRevoked = await store.isRevoked('credential-123');
      expect(isRevoked).to.be.false;
    });

    it('should revoke a credential', async () => {
      const credentialId = 'credential-123';

      await store.revoke(credentialId);
      const isRevoked = await store.isRevoked(credentialId);

      expect(isRevoked).to.be.true;
    });

    it('should handle revoking the same credential twice (idempotent)', async () => {
      const credentialId = 'credential-123';

      await store.revoke(credentialId);
      await store.revoke(credentialId);

      const isRevoked = await store.isRevoked(credentialId);
      const count = await store.getRevokedCount();

      expect(isRevoked).to.be.true;
      expect(count).to.equal(1); // Should only count once
    });

    it('should track revoked count correctly', async () => {
      expect(await store.getRevokedCount()).to.equal(0);

      await store.revoke('cred-1');
      expect(await store.getRevokedCount()).to.equal(1);

      await store.revoke('cred-2');
      expect(await store.getRevokedCount()).to.equal(2);

      await store.revoke('cred-3');
      expect(await store.getRevokedCount()).to.equal(3);
    });

    it('should handle multiple different credentials', async () => {
      await store.revoke('cred-1');
      await store.revoke('cred-2');
      await store.revoke('cred-3');

      expect(await store.isRevoked('cred-1')).to.be.true;
      expect(await store.isRevoked('cred-2')).to.be.true;
      expect(await store.isRevoked('cred-3')).to.be.true;
      expect(await store.isRevoked('cred-4')).to.be.false;
    });

    it('should not affect unrevoked credentials when revoking others', async () => {
      await store.revoke('cred-1');

      expect(await store.isRevoked('cred-1')).to.be.true;
      expect(await store.isRevoked('cred-2')).to.be.false;
      expect(await store.isRevoked('cred-3')).to.be.false;
    });
  });
});
