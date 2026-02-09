import { strict as assert } from 'assert';
import {
  PROTOCOL_VERSION,
  parseProtocolVersion,
  isProtocolCompatible,
  DEPRECATION_SCHEDULE,
  DEPRECATION_POLICY,
  getVersionStatus,
  isVersionDeprecated,
  isVersionSunset,
  buildDeprecationHeaders,
  ProtocolDeprecationEntry,
} from '../src/version';

describe('Protocol Version', () => {
  describe('PROTOCOL_VERSION constant', () => {
    it('should follow correct format', () => {
      assert.match(PROTOCOL_VERSION, /^zk-id\/\d+\.\d+(?:-.+)?$/);
    });

    it('should be parseable', () => {
      assert.doesNotThrow(() => parseProtocolVersion(PROTOCOL_VERSION));
    });
  });

  describe('parseProtocolVersion', () => {
    it('should parse valid version with suffix', () => {
      const result = parseProtocolVersion('zk-id/1.0-draft');
      assert.deepStrictEqual(result, {
        major: 1,
        minor: 0,
        suffix: 'draft',
      });
    });

    it('should parse valid version without suffix', () => {
      const result = parseProtocolVersion('zk-id/2.5');
      assert.deepStrictEqual(result, {
        major: 2,
        minor: 5,
        suffix: undefined,
      });
    });

    it('should parse version with complex suffix', () => {
      const result = parseProtocolVersion('zk-id/1.2-rc1');
      assert.deepStrictEqual(result, {
        major: 1,
        minor: 2,
        suffix: 'rc1',
      });
    });

    it('should parse multi-digit versions', () => {
      const result = parseProtocolVersion('zk-id/10.25-alpha');
      assert.deepStrictEqual(result, {
        major: 10,
        minor: 25,
        suffix: 'alpha',
      });
    });

    it('should throw on missing prefix', () => {
      assert.throws(
        () => parseProtocolVersion('1.0-draft'),
        /Invalid protocol version format: 1.0-draft/
      );
    });

    it('should throw on wrong prefix', () => {
      assert.throws(
        () => parseProtocolVersion('zkid/1.0'),
        /Invalid protocol version format: zkid\/1.0/
      );
    });

    it('should throw on missing minor version', () => {
      assert.throws(
        () => parseProtocolVersion('zk-id/1'),
        /Invalid protocol version format: zk-id\/1/
      );
    });

    it('should throw on non-numeric versions', () => {
      assert.throws(
        () => parseProtocolVersion('zk-id/v1.0'),
        /Invalid protocol version format: zk-id\/v1.0/
      );
    });

    it('should throw on empty string', () => {
      assert.throws(
        () => parseProtocolVersion(''),
        /Invalid protocol version format: /
      );
    });
  });

  describe('isProtocolCompatible', () => {
    it('should return true for identical versions', () => {
      assert.strictEqual(
        isProtocolCompatible('zk-id/1.0-draft', 'zk-id/1.0-draft'),
        true
      );
    });

    it('should return true for same major, different minor', () => {
      assert.strictEqual(isProtocolCompatible('zk-id/1.0', 'zk-id/1.5'), true);
    });

    it('should return true for same major, different suffix', () => {
      assert.strictEqual(isProtocolCompatible('zk-id/1.0-draft', 'zk-id/1.0'), true);
      assert.strictEqual(isProtocolCompatible('zk-id/1.0-rc1', 'zk-id/1.0-rc2'), true);
    });

    it('should return true for same major, different minor and suffix', () => {
      assert.strictEqual(isProtocolCompatible('zk-id/1.0-draft', 'zk-id/1.5'), true);
    });

    it('should return false for different major versions', () => {
      assert.strictEqual(isProtocolCompatible('zk-id/1.0', 'zk-id/2.0'), false);
      assert.strictEqual(isProtocolCompatible('zk-id/1.5-draft', 'zk-id/2.0-draft'), false);
    });

    it('should return false for invalid first version', () => {
      assert.strictEqual(isProtocolCompatible('invalid', 'zk-id/1.0'), false);
    });

    it('should return false for invalid second version', () => {
      assert.strictEqual(isProtocolCompatible('zk-id/1.0', 'invalid'), false);
    });

    it('should return false for both invalid versions', () => {
      assert.strictEqual(isProtocolCompatible('invalid1', 'invalid2'), false);
    });
  });

  describe('Deprecation Policy', () => {
    describe('DEPRECATION_SCHEDULE', () => {
      it('should contain the current protocol version', () => {
        const entry = DEPRECATION_SCHEDULE.find((e) => e.version === PROTOCOL_VERSION);
        assert.ok(entry, 'Current protocol version should be in the schedule');
        assert.strictEqual(entry.status, 'active');
      });

      it('should have valid entries with parseable versions', () => {
        for (const entry of DEPRECATION_SCHEDULE) {
          assert.doesNotThrow(
            () => parseProtocolVersion(entry.version),
            `Schedule entry version ${entry.version} should be parseable`
          );
          assert.ok(
            ['active', 'deprecated', 'sunset'].includes(entry.status),
            `Invalid status: ${entry.status}`
          );
        }
      });
    });

    describe('DEPRECATION_POLICY', () => {
      it('should define minimum deprecation window', () => {
        assert.ok(DEPRECATION_POLICY.minDeprecationWindowDays >= 90);
      });

      it('should define HTTP header names', () => {
        assert.strictEqual(DEPRECATION_POLICY.sunsetHeader, 'Sunset');
        assert.strictEqual(DEPRECATION_POLICY.deprecationHeader, 'Deprecation');
      });
    });

    describe('getVersionStatus', () => {
      it('should return entry for known version', () => {
        const entry = getVersionStatus('zk-id/1.0-draft');
        assert.ok(entry);
        assert.strictEqual(entry.version, 'zk-id/1.0-draft');
        assert.strictEqual(entry.status, 'active');
      });

      it('should return null for unknown version', () => {
        const entry = getVersionStatus('zk-id/99.99');
        assert.strictEqual(entry, null);
      });

      it('should accept a custom schedule', () => {
        const custom: ProtocolDeprecationEntry[] = [
          {
            version: 'zk-id/0.9',
            status: 'sunset',
            deprecatedAt: '2025-01-01T00:00:00Z',
            sunsetAt: '2025-06-01T00:00:00Z',
            successor: 'zk-id/1.0-draft',
            migrationNote: 'Upgrade to v1.0',
          },
        ];

        const entry = getVersionStatus('zk-id/0.9', custom);
        assert.ok(entry);
        assert.strictEqual(entry.status, 'sunset');
        assert.strictEqual(entry.successor, 'zk-id/1.0-draft');
      });
    });

    describe('isVersionDeprecated', () => {
      const schedule: ProtocolDeprecationEntry[] = [
        { version: 'zk-id/1.0', status: 'active' },
        {
          version: 'zk-id/0.9',
          status: 'deprecated',
          deprecatedAt: '2025-06-01T00:00:00Z',
          sunsetAt: '2025-12-01T00:00:00Z',
          successor: 'zk-id/1.0',
        },
        {
          version: 'zk-id/0.8',
          status: 'sunset',
          deprecatedAt: '2025-01-01T00:00:00Z',
          sunsetAt: '2025-06-01T00:00:00Z',
          successor: 'zk-id/0.9',
        },
      ];

      it('should return false for active version', () => {
        assert.strictEqual(isVersionDeprecated('zk-id/1.0', schedule), false);
      });

      it('should return true for deprecated version', () => {
        assert.strictEqual(isVersionDeprecated('zk-id/0.9', schedule), true);
      });

      it('should return true for sunset version', () => {
        assert.strictEqual(isVersionDeprecated('zk-id/0.8', schedule), true);
      });

      it('should return false for unknown version', () => {
        assert.strictEqual(isVersionDeprecated('zk-id/99.0', schedule), false);
      });
    });

    describe('isVersionSunset', () => {
      const schedule: ProtocolDeprecationEntry[] = [
        { version: 'zk-id/1.0', status: 'active' },
        { version: 'zk-id/0.9', status: 'deprecated' },
        { version: 'zk-id/0.8', status: 'sunset' },
      ];

      it('should return false for active version', () => {
        assert.strictEqual(isVersionSunset('zk-id/1.0', schedule), false);
      });

      it('should return false for deprecated-but-not-sunset version', () => {
        assert.strictEqual(isVersionSunset('zk-id/0.9', schedule), false);
      });

      it('should return true for sunset version', () => {
        assert.strictEqual(isVersionSunset('zk-id/0.8', schedule), true);
      });

      it('should return false for unknown version', () => {
        assert.strictEqual(isVersionSunset('zk-id/99.0', schedule), false);
      });
    });

    describe('buildDeprecationHeaders', () => {
      it('should return empty headers for active version', () => {
        const entry: ProtocolDeprecationEntry = {
          version: 'zk-id/1.0',
          status: 'active',
        };

        const headers = buildDeprecationHeaders(entry);
        assert.deepStrictEqual(headers, {});
      });

      it('should include Deprecation header for deprecated version', () => {
        const entry: ProtocolDeprecationEntry = {
          version: 'zk-id/0.9',
          status: 'deprecated',
          deprecatedAt: '2025-06-01T00:00:00Z',
          sunsetAt: '2025-12-01T00:00:00Z',
        };

        const headers = buildDeprecationHeaders(entry);
        assert.strictEqual(headers['Deprecation'], '2025-06-01T00:00:00Z');
        assert.strictEqual(headers['Sunset'], '2025-12-01T00:00:00Z');
      });

      it('should include Link header when migration URL provided', () => {
        const entry: ProtocolDeprecationEntry = {
          version: 'zk-id/0.9',
          status: 'deprecated',
          deprecatedAt: '2025-06-01T00:00:00Z',
        };

        const headers = buildDeprecationHeaders(
          entry,
          'https://docs.example.com/migration'
        );
        assert.ok(headers['Link']);
        assert.ok(headers['Link'].includes('https://docs.example.com/migration'));
        assert.ok(headers['Link'].includes('rel="sunset"'));
      });

      it('should include Sunset header for sunset version', () => {
        const entry: ProtocolDeprecationEntry = {
          version: 'zk-id/0.8',
          status: 'sunset',
          deprecatedAt: '2025-01-01T00:00:00Z',
          sunsetAt: '2025-06-01T00:00:00Z',
        };

        const headers = buildDeprecationHeaders(entry);
        assert.strictEqual(headers['Sunset'], '2025-06-01T00:00:00Z');
        assert.strictEqual(headers['Deprecation'], '2025-01-01T00:00:00Z');
      });
    });
  });
});
