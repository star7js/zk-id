/**
 * Tests for JSON.parse guards (S-6 security fix)
 */

import { describe, test, expect } from 'vitest';
import { loadVerificationKey } from '../src/verifier';
import { ZkIdConfigError } from '../src/errors';

describe('JSON.parse error handling (S-6 fix)', () => {
  describe('loadVerificationKey', () => {
    test('throws ZkIdConfigError for invalid JSON', async () => {
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
        expect(error).toBeInstanceOf(ZkIdConfigError);
        expect(error.message).toContain('Failed to parse verification key');
      } finally {
        await fs.unlink(tmpFile).catch(() => {});
      }
    });

    test('successfully parses valid JSON', async () => {
      const fs = require('fs').promises;
      const path = require('path');
      const os = require('os');

      const tmpDir = os.tmpdir();
      const tmpFile = path.join(tmpDir, `test-valid-${Date.now()}.json`);

      const validVKey = { protocol: 'groth16', curve: 'bn128', nPublic: 5, vk_alpha_1: [] };
      await fs.writeFile(tmpFile, JSON.stringify(validVKey));

      try {
        const result = await loadVerificationKey(tmpFile);
        expect(result.protocol).toBe('groth16');
      } finally {
        await fs.unlink(tmpFile).catch(() => {});
      }
    });
  });
});
