/**
 * Tests for JSON.parse guards in browser-wallet (S-6 security fix)
 */

import { expect } from 'chai';
import { BrowserWallet } from '../src/browser-wallet';
import { ZkIdCredentialError } from '@zk-id/core';

describe('JSON.parse error handling - BrowserWallet (S-6 fix)', () => {
  let wallet: BrowserWallet;

  beforeEach(() => {
    wallet = new BrowserWallet({
      circuitPaths: {
        ageWasm: '/path/to/age.wasm',
        ageZkey: '/path/to/age.zkey',
      },
    });
  });

  describe('importCredential', () => {
    it('throws ZkIdCredentialError for invalid JSON', async () => {
      const invalidJson = 'not valid json {{{';

      try {
        await wallet.importCredential(invalidJson);
        expect.fail('Should have thrown ZkIdCredentialError');
      } catch (error: any) {
        expect(error).to.be.instanceOf(ZkIdCredentialError);
        expect(error.message).to.include('Failed to parse credential JSON');
        expect(error.code).to.equal('INVALID_CREDENTIAL_FORMAT');
      }
    });

    it('throws ZkIdCredentialError for structurally invalid credential', async () => {
      const incompleteJson = JSON.stringify({ credential: { id: 'test' } });

      try {
        await wallet.importCredential(incompleteJson);
        expect.fail('Should have thrown ZkIdCredentialError');
      } catch (error: any) {
        expect(error).to.be.instanceOf(ZkIdCredentialError);
        expect(error.message).to.include('Invalid credential format');
      }
    });
  });

  describe('importAll', () => {
    it('throws ZkIdCredentialError for invalid JSON', async () => {
      const invalidJson = '[ invalid ]';

      try {
        await wallet.importAll(invalidJson);
        expect.fail('Should have thrown ZkIdCredentialError');
      } catch (error: any) {
        expect(error).to.be.instanceOf(ZkIdCredentialError);
        expect(error.message).to.include('Failed to parse credentials JSON');
        expect(error.code).to.equal('INVALID_CREDENTIAL_FORMAT');
      }
    });

    it('throws ZkIdCredentialError for non-array JSON', async () => {
      const nonArrayJson = JSON.stringify({ credentials: [] });

      try {
        await wallet.importAll(nonArrayJson);
        expect.fail('Should have thrown ZkIdCredentialError');
      } catch (error: any) {
        expect(error).to.be.instanceOf(ZkIdCredentialError);
        expect(error.message).to.include('Expected a JSON array');
      }
    });
  });
});
