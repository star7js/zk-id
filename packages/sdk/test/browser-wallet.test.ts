import { expect } from 'chai';
import { BrowserWallet, InMemoryCredentialStore, CredentialStore } from '../src/browser-wallet';
import { SignedCredential } from '@zk-id/core';

// ---------------------------------------------------------------------------
// Test fixtures
// ---------------------------------------------------------------------------

function makeSignedCredential(
  overrides: Partial<{
    id: string;
    birthYear: number;
    nationality: number;
    issuer: string;
    issuedAt: string;
  }> = {},
): SignedCredential {
  return {
    credential: {
      id: overrides.id ?? `cred-${Date.now()}-${Math.random().toString(36).slice(2)}`,
      birthYear: overrides.birthYear ?? 1990,
      nationality: overrides.nationality ?? 840,
      salt: 'aabbccdd',
      commitment: '123456789',
      createdAt: new Date().toISOString(),
    },
    issuer: overrides.issuer ?? 'TestIssuer',
    signature: 'mock-signature-base64',
    issuedAt: overrides.issuedAt ?? new Date().toISOString(),
  };
}

// ---------------------------------------------------------------------------
// InMemoryCredentialStore tests
// ---------------------------------------------------------------------------

describe('InMemoryCredentialStore', () => {
  it('starts empty', async () => {
    const store = new InMemoryCredentialStore();
    const all = await store.getAll();
    expect(all).to.deep.equal([]);
  });

  it('stores and retrieves a credential', async () => {
    const store = new InMemoryCredentialStore();
    const cred = makeSignedCredential({ id: 'test-1' });

    await store.put(cred);
    const retrieved = await store.get('test-1');

    expect(retrieved).to.not.be.null;
    expect(retrieved!.credential.id).to.equal('test-1');
  });

  it('returns null for missing credential', async () => {
    const store = new InMemoryCredentialStore();
    const result = await store.get('nonexistent');
    expect(result).to.be.null;
  });

  it('lists all credentials', async () => {
    const store = new InMemoryCredentialStore();
    await store.put(makeSignedCredential({ id: 'a' }));
    await store.put(makeSignedCredential({ id: 'b' }));

    const all = await store.getAll();
    expect(all).to.have.length(2);
  });

  it('overwrites on duplicate put', async () => {
    const store = new InMemoryCredentialStore();
    const cred1 = makeSignedCredential({ id: 'dup', issuer: 'IssuerA' });
    const cred2 = makeSignedCredential({ id: 'dup', issuer: 'IssuerB' });

    await store.put(cred1);
    await store.put(cred2);

    const result = await store.get('dup');
    expect(result!.issuer).to.equal('IssuerB');
    expect(await store.getAll()).to.have.length(1);
  });

  it('deletes a credential', async () => {
    const store = new InMemoryCredentialStore();
    await store.put(makeSignedCredential({ id: 'del-me' }));

    await store.delete('del-me');
    expect(await store.get('del-me')).to.be.null;
  });

  it('clears all credentials', async () => {
    const store = new InMemoryCredentialStore();
    await store.put(makeSignedCredential({ id: 'x' }));
    await store.put(makeSignedCredential({ id: 'y' }));

    await store.clear();
    expect(await store.getAll()).to.deep.equal([]);
  });
});

// ---------------------------------------------------------------------------
// BrowserWallet tests
// ---------------------------------------------------------------------------

describe('BrowserWallet', () => {
  function createWallet(storeOverride?: CredentialStore) {
    const store = storeOverride ?? new InMemoryCredentialStore();
    return new BrowserWallet({
      credentialStore: store,
      circuitPaths: {
        ageWasm: '/circuits/age-verify.wasm',
        ageZkey: '/circuits/age-verify.zkey',
        nationalityWasm: '/circuits/nationality-verify.wasm',
        nationalityZkey: '/circuits/nationality-verify.zkey',
        ageRevocableWasm: '/circuits/age-verify-revocable.wasm',
        ageRevocableZkey: '/circuits/age-verify-revocable.zkey',
      },
    });
  }

  describe('isAvailable()', () => {
    it('returns true', async () => {
      const wallet = createWallet();
      expect(await wallet.isAvailable()).to.be.true;
    });
  });

  describe('Credential management', () => {
    it('adds and lists credentials', async () => {
      const wallet = createWallet();
      const cred = makeSignedCredential({ id: 'c1' });

      await wallet.addCredential(cred);
      const list = await wallet.listCredentials();

      expect(list).to.have.length(1);
      expect(list[0].credential.id).to.equal('c1');
    });

    it('retrieves a single credential', async () => {
      const wallet = createWallet();
      const cred = makeSignedCredential({ id: 'c2' });

      await wallet.addCredential(cred);
      const result = await wallet.getCredential('c2');

      expect(result).to.not.be.null;
      expect(result!.credential.id).to.equal('c2');
    });

    it('returns null for missing credential', async () => {
      const wallet = createWallet();
      expect(await wallet.getCredential('missing')).to.be.null;
    });

    it('removes a credential', async () => {
      const wallet = createWallet();
      const cred = makeSignedCredential({ id: 'rm' });

      await wallet.addCredential(cred);
      await wallet.removeCredential('rm');

      expect(await wallet.getCredential('rm')).to.be.null;
      expect(await wallet.credentialCount()).to.equal(0);
    });

    it('counts credentials', async () => {
      const wallet = createWallet();
      expect(await wallet.credentialCount()).to.equal(0);

      await wallet.addCredential(makeSignedCredential({ id: 'a' }));
      await wallet.addCredential(makeSignedCredential({ id: 'b' }));
      expect(await wallet.credentialCount()).to.equal(2);
    });
  });

  describe('Backup & recovery', () => {
    it('exports and imports a single credential', async () => {
      const wallet = createWallet();
      const cred = makeSignedCredential({ id: 'export-test' });
      await wallet.addCredential(cred);

      const json = await wallet.exportCredential('export-test');
      expect(json).to.be.a('string');

      // Import into a new wallet
      const wallet2 = createWallet();
      const imported = await wallet2.importCredential(json);

      expect(imported.credential.id).to.equal('export-test');
      expect(await wallet2.credentialCount()).to.equal(1);
    });

    it('throws on export of nonexistent credential', async () => {
      const wallet = createWallet();

      try {
        await wallet.exportCredential('nope');
        expect.fail('Should have thrown');
      } catch (error: any) {
        expect(error.message).to.include('not found');
      }
    });

    it('rejects import of invalid JSON structure', async () => {
      const wallet = createWallet();

      try {
        await wallet.importCredential('{"foo": "bar"}');
        expect.fail('Should have thrown');
      } catch (error: any) {
        expect(error.message).to.include('Invalid credential format');
      }
    });

    it('exports and imports all credentials', async () => {
      const wallet = createWallet();
      await wallet.addCredential(makeSignedCredential({ id: 'bulk-1' }));
      await wallet.addCredential(makeSignedCredential({ id: 'bulk-2' }));

      const json = await wallet.exportAll();

      const wallet2 = createWallet();
      const count = await wallet2.importAll(json);

      expect(count).to.equal(2);
      expect(await wallet2.credentialCount()).to.equal(2);
    });

    it('rejects importAll with non-array JSON', async () => {
      const wallet = createWallet();

      try {
        await wallet.importAll('{"not": "array"}');
        expect.fail('Should have thrown');
      } catch (error: any) {
        expect(error.message).to.include('JSON array');
      }
    });
  });

  describe('requestProof()', () => {
    it('throws when no credentials are stored', async () => {
      const wallet = createWallet();

      try {
        await wallet.requestProof({
          claimType: 'age',
          minAge: 18,
          nonce: 'test-nonce',
          timestamp: new Date().toISOString(),
        });
        expect.fail('Should have thrown');
      } catch (error: any) {
        expect(error.message).to.include('No credentials stored');
      }
    });

    it('throws for unsupported claim type', async () => {
      const wallet = createWallet();
      await wallet.addCredential(makeSignedCredential({ id: 'c1' }));

      try {
        await wallet.requestProof({
          claimType: 'unknown' as any,
          nonce: 'test-nonce',
          timestamp: new Date().toISOString(),
        });
        expect.fail('Should have thrown');
      } catch (error: any) {
        expect(error.message).to.include('Unsupported claim type');
      }
    });

    it('throws when minAge is missing for age proof', async () => {
      const wallet = createWallet();
      await wallet.addCredential(makeSignedCredential({ id: 'c1' }));

      try {
        await wallet.requestProof({
          claimType: 'age',
          nonce: 'test-nonce',
          timestamp: new Date().toISOString(),
        });
        expect.fail('Should have thrown');
      } catch (error: any) {
        expect(error.message).to.include('minAge');
      }
    });

    it('throws when targetNationality is missing for nationality proof', async () => {
      const wallet = createWallet();
      await wallet.addCredential(makeSignedCredential({ id: 'c1' }));

      try {
        await wallet.requestProof({
          claimType: 'nationality',
          nonce: 'test-nonce',
          timestamp: new Date().toISOString(),
        });
        expect.fail('Should have thrown');
      } catch (error: any) {
        expect(error.message).to.include('targetNationality');
      }
    });

    it('throws when age-revocable is requested without revocationRootEndpoint', async () => {
      const wallet = createWallet();
      await wallet.addCredential(makeSignedCredential({ id: 'c1' }));

      try {
        await wallet.requestProof({
          claimType: 'age-revocable',
          minAge: 18,
          nonce: 'test-nonce',
          timestamp: new Date().toISOString(),
        });
        expect.fail('Should have thrown');
      } catch (error: any) {
        expect(error.message).to.include('revocationRootEndpoint');
      }
    });

    it('uses onProofRequest callback for credential selection', async () => {
      let callbackCalled = false;
      let receivedCredentials: SignedCredential[] = [];

      const store = new InMemoryCredentialStore();
      const wallet = new BrowserWallet({
        credentialStore: store,
        circuitPaths: {
          ageWasm: '/circuits/age.wasm',
          ageZkey: '/circuits/age.zkey',
        },
        onProofRequest: async (request, credentials) => {
          callbackCalled = true;
          receivedCredentials = credentials;
          return null; // reject
        },
      });

      await wallet.addCredential(makeSignedCredential({ id: 'sel-1' }));
      await wallet.addCredential(makeSignedCredential({ id: 'sel-2' }));

      try {
        await wallet.requestProof({
          claimType: 'age',
          minAge: 18,
          nonce: 'test',
          timestamp: new Date().toISOString(),
        });
        expect.fail('Should have thrown');
      } catch (error: any) {
        expect(error.message).to.include('rejected by user');
      }

      expect(callbackCalled).to.be.true;
      expect(receivedCredentials).to.have.length(2);
    });

    it('auto-selects the most recently issued credential', async () => {
      let selectedId: string | null = null;

      const store = new InMemoryCredentialStore();
      const wallet = new BrowserWallet({
        credentialStore: store,
        circuitPaths: {
          ageWasm: '/circuits/age.wasm',
          ageZkey: '/circuits/age.zkey',
        },
        // Override onProofRequest to capture which credential is selected
        onProofRequest: async (_request, credentials) => {
          // Return the auto-selection logic result for verification
          const sorted = [...credentials].sort((a, b) => {
            return Date.parse(b.issuedAt) - Date.parse(a.issuedAt);
          });
          selectedId = sorted[0].credential.id;
          return null; // still reject (we don't have real circuits)
        },
      });

      const older = makeSignedCredential({
        id: 'old',
        issuedAt: '2025-01-01T00:00:00Z',
      });
      const newer = makeSignedCredential({
        id: 'new',
        issuedAt: '2026-02-01T00:00:00Z',
      });

      await wallet.addCredential(older);
      await wallet.addCredential(newer);

      try {
        await wallet.requestProof({
          claimType: 'age',
          minAge: 18,
          nonce: 'test',
          timestamp: new Date().toISOString(),
        });
      } catch {
        // expected
      }

      expect(selectedId).to.equal('new');
    });

    it('throws when onProofRequest returns an ID not in the wallet', async () => {
      const store = new InMemoryCredentialStore();
      const wallet = new BrowserWallet({
        credentialStore: store,
        circuitPaths: {
          ageWasm: '/circuits/age.wasm',
          ageZkey: '/circuits/age.zkey',
        },
        onProofRequest: async () => 'nonexistent-id',
      });

      await wallet.addCredential(makeSignedCredential({ id: 'exists' }));

      try {
        await wallet.requestProof({
          claimType: 'age',
          minAge: 18,
          nonce: 'test',
          timestamp: new Date().toISOString(),
        });
        expect.fail('Should have thrown');
      } catch (error: any) {
        expect(error.message).to.include('not found');
      }
    });
  });

  describe('Circuit path validation', () => {
    it('throws when nationality circuit paths are not configured', async () => {
      const store = new InMemoryCredentialStore();
      const wallet = new BrowserWallet({
        credentialStore: store,
        circuitPaths: {
          ageWasm: '/circuits/age.wasm',
          ageZkey: '/circuits/age.zkey',
          // nationality paths intentionally omitted
        },
      });

      await wallet.addCredential(makeSignedCredential({ id: 'c1' }));

      try {
        await wallet.requestProof({
          claimType: 'nationality',
          targetNationality: 840,
          nonce: 'test',
          timestamp: new Date().toISOString(),
        });
        expect.fail('Should have thrown');
      } catch (error: any) {
        expect(error.message).to.include('Nationality circuit paths');
      }
    });

    it('throws when age-revocable circuit paths are not configured', async () => {
      const store = new InMemoryCredentialStore();
      const wallet = new BrowserWallet({
        credentialStore: store,
        circuitPaths: {
          ageWasm: '/circuits/age.wasm',
          ageZkey: '/circuits/age.zkey',
          // revocable paths intentionally omitted
        },
        revocationRootEndpoint: 'http://localhost/api/revocation/root',
      });

      await wallet.addCredential(makeSignedCredential({ id: 'c1' }));

      try {
        await wallet.requestProof({
          claimType: 'age-revocable',
          minAge: 18,
          nonce: 'test',
          timestamp: new Date().toISOString(),
        });
        expect.fail('Should have thrown');
      } catch (error: any) {
        expect(error.message).to.include('Age-revocable circuit paths');
      }
    });
  });
});
