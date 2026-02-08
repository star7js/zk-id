import { strict as assert } from 'assert';
import {
  PROTOCOL_VERSION,
  parseProtocolVersion,
  isProtocolCompatible,
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
});
