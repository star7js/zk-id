/**
 * Tests for JSON.parse guards (S-6 security fix)
 */

import { expect } from 'chai';
import { loadVerificationKey } from '../src/verifier';
import { ZkIdConfigError } from '../src/errors';

describe('JSON.parse error handling (S-6 fix)', () => {
  describe('loadVerificationKey', () => {
    it('throws ZkIdConfigError for invalid JSON', async () => {
      // Create a temp file with invalid JSON
      const fs = require('fs').promises;
      const path = require('path');
      const os = require('os');

      const tmpDir = os.tmpdir();
      const tmpFile = path.join(tmpDir, `test-invalid-${Date.now()}.json`);

      await fs.writeFile(tmpFile, 'invalid json {{{');

      try {
        await loadVerificationKey(tmpFile);
        expect.fail('Should have thrown ZkIdConfigError');
      } catch (error: any) {
        expect(error).to.be.instanceOf(ZkIdConfigError);
        expect(error.message).to.include('Failed to parse verification key');
      } finally {
        await fs.unlink(tmpFile).catch(() => {});
      }
    });

    it('successfully parses valid JSON', async () => {
      const fs = require('fs').promises;
      const path = require('path');
      const os = require('os');

      const tmpDir = os.tmpdir();
      const tmpFile = path.join(tmpDir, `test-valid-${Date.now()}.json`);

      const validVKey = { protocol: 'groth16', curve: 'bn128', nPublic: 5, vk_alpha_1: [] };
      await fs.writeFile(tmpFile, JSON.stringify(validVKey));

      try {
        const result = await loadVerificationKey(tmpFile);
        expect(result.protocol).to.equal('groth16');
      } finally {
        await fs.unlink(tmpFile).catch(() => {});
      }
    });
  });
});
