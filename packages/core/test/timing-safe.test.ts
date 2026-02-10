/**
 * Timing-safe comparison tests
 *
 * Dedicated test suite for timing-safe comparison functions to prevent
 * timing attacks on sensitive comparisons like tokens and signatures.
 */

import { describe, test, expect } from 'vitest';
import { constantTimeEqual, constantTimeArrayEqual } from '../src/timing-safe';

describe('constantTimeEqual', () => {
  describe('basic equality', () => {
    test('returns true for identical strings', () => {
      expect(constantTimeEqual('secret-token', 'secret-token')).toBe(true);
    });

    test('returns false for different strings of same length', () => {
      expect(constantTimeEqual('secret-token', 'secret-tokeo')).toBe(false);
    });

    test('returns false for completely different strings', () => {
      expect(constantTimeEqual('abc', 'xyz')).toBe(false);
    });
  });

  describe('length handling', () => {
    test('returns false when first string is shorter', () => {
      expect(constantTimeEqual('short', 'longer-string')).toBe(false);
    });

    test('returns false when second string is shorter', () => {
      expect(constantTimeEqual('longer-string', 'short')).toBe(false);
    });

    test('returns true for empty strings', () => {
      expect(constantTimeEqual('', '')).toBe(true);
    });

    test('returns false when comparing empty to non-empty', () => {
      expect(constantTimeEqual('', 'non-empty')).toBe(false);
      expect(constantTimeEqual('non-empty', '')).toBe(false);
    });
  });

  describe('unicode and special characters', () => {
    test('handles unicode emoji correctly', () => {
      expect(constantTimeEqual('🔐🔑', '🔐🔑')).toBe(true);
      expect(constantTimeEqual('🔐🔑', '🔐🔓')).toBe(false);
    });

    test('handles unicode characters', () => {
      expect(constantTimeEqual('café', 'café')).toBe(true);
      expect(constantTimeEqual('café', 'cafe')).toBe(false);
    });

    test('handles null bytes', () => {
      expect(constantTimeEqual('test\x00test', 'test\x00test')).toBe(true);
      expect(constantTimeEqual('test\x00test', 'test\x01test')).toBe(false);
    });
  });

  describe('performance edge cases', () => {
    test('handles very long equal strings', () => {
      const long = 'a'.repeat(10000);
      expect(constantTimeEqual(long, long)).toBe(true);
    });

    test('handles very long unequal strings', () => {
      const longA = 'a'.repeat(10000);
      const longB = 'a'.repeat(9999) + 'b';
      expect(constantTimeEqual(longA, longB)).toBe(false);
    });

    test('handles strings differing only at the end', () => {
      const base = 'a'.repeat(1000);
      expect(constantTimeEqual(base + 'x', base + 'y')).toBe(false);
    });
  });
});

describe('constantTimeArrayEqual', () => {
  describe('basic equality', () => {
    test('returns true for identical arrays', () => {
      expect(constantTimeArrayEqual(['a', 'b', 'c'], ['a', 'b', 'c'])).toBe(true);
    });

    test('returns false for different arrays of same length', () => {
      expect(constantTimeArrayEqual(['a', 'b', 'c'], ['a', 'b', 'd'])).toBe(false);
    });

    test('returns false for completely different arrays', () => {
      expect(constantTimeArrayEqual(['x', 'y'], ['a', 'b'])).toBe(false);
    });
  });

  describe('length handling', () => {
    test('returns false when first array is shorter', () => {
      expect(constantTimeArrayEqual(['a', 'b'], ['a', 'b', 'c'])).toBe(false);
    });

    test('returns false when second array is shorter', () => {
      expect(constantTimeArrayEqual(['a', 'b', 'c'], ['a', 'b'])).toBe(false);
    });

    test('returns true for empty arrays', () => {
      expect(constantTimeArrayEqual([], [])).toBe(true);
    });

    test('returns false when comparing empty to non-empty', () => {
      expect(constantTimeArrayEqual([], ['a'])).toBe(false);
      expect(constantTimeArrayEqual(['a'], [])).toBe(false);
    });
  });

  describe('element content', () => {
    test('handles empty string elements', () => {
      expect(constantTimeArrayEqual(['', '', ''], ['', '', ''])).toBe(true);
      expect(constantTimeArrayEqual(['', 'a', ''], ['', 'b', ''])).toBe(false);
    });

    test('handles single element arrays', () => {
      expect(constantTimeArrayEqual(['single'], ['single'])).toBe(true);
      expect(constantTimeArrayEqual(['single'], ['different'])).toBe(false);
    });

    test('detects differences at start', () => {
      expect(constantTimeArrayEqual(['x', 'b', 'c'], ['a', 'b', 'c'])).toBe(false);
    });

    test('detects differences in middle', () => {
      expect(constantTimeArrayEqual(['a', 'x', 'c'], ['a', 'b', 'c'])).toBe(false);
    });

    test('detects differences at end', () => {
      expect(constantTimeArrayEqual(['a', 'b', 'x'], ['a', 'b', 'c'])).toBe(false);
    });
  });

  describe('uses constantTimeEqual internally', () => {
    test('handles unicode in array elements', () => {
      expect(constantTimeArrayEqual(['🔐', '🔑'], ['🔐', '🔑'])).toBe(true);
      expect(constantTimeArrayEqual(['🔐', '🔑'], ['🔐', '🔓'])).toBe(false);
    });

    test('handles different length strings in array', () => {
      expect(constantTimeArrayEqual(['short', 'long'], ['short', 'long'])).toBe(true);
      expect(constantTimeArrayEqual(['short', 'long'], ['short', 'longer'])).toBe(false);
    });
  });
});
