/**
 * Security test suite - boundary fuzzing and edge cases
 *
 * Tests validators against extreme inputs, invalid types, and edge cases
 * to ensure robust input validation and prevent security vulnerabilities.
 */

import { describe, test, expect } from 'vitest';
import {
  validateBirthYear,
  validateNationality,
  validateMinAge,
  validateNonce,
  validateRequestTimestamp,
  validateBigIntString,
  validateFieldElement,
  validateHexString,
  validateScopeId,
  validatePositiveInt,
  validateClaimType,
  BN128_FIELD_ORDER,
  MIN_NONCE_LENGTH,
  MAX_NONCE_LENGTH,
  MAX_AGE,
  MIN_BIRTH_YEAR,
  MIN_NATIONALITY,
  MAX_NATIONALITY,
} from '../src/validation';
import { constantTimeEqual, constantTimeArrayEqual } from '../src/timing-safe';

describe('Security: Boundary Fuzzing', () => {
  describe('validateBirthYear - boundary fuzzing', () => {
    test('rejects MAX_SAFE_INTEGER', () => {
      expect(() => validateBirthYear(Number.MAX_SAFE_INTEGER)).toThrow('birthYear must be between');
    });

    test('rejects negative year', () => {
      expect(() => validateBirthYear(-100)).toThrow('birthYear must be between');
    });

    test('rejects NaN', () => {
      expect(() => validateBirthYear(NaN)).toThrow('birthYear must be an integer');
    });

    test('rejects Infinity', () => {
      expect(() => validateBirthYear(Infinity)).toThrow('birthYear must be an integer');
    });

    test('rejects below MIN_BIRTH_YEAR', () => {
      expect(() => validateBirthYear(MIN_BIRTH_YEAR - 1)).toThrow('birthYear must be between');
    });

    test('accepts MIN_BIRTH_YEAR', () => {
      expect(() => validateBirthYear(MIN_BIRTH_YEAR)).not.toThrow();
    });

    test('accepts current year', () => {
      expect(() => validateBirthYear(new Date().getFullYear())).not.toThrow();
    });
  });

  describe('validateNationality - boundary fuzzing', () => {
    test('rejects 0', () => {
      expect(() => validateNationality(0)).toThrow('nationality must be between');
    });

    test('accepts MIN_NATIONALITY', () => {
      expect(() => validateNationality(MIN_NATIONALITY)).not.toThrow();
    });

    test('accepts MAX_NATIONALITY', () => {
      expect(() => validateNationality(MAX_NATIONALITY)).not.toThrow();
    });

    test('rejects MAX_NATIONALITY + 1', () => {
      expect(() => validateNationality(MAX_NATIONALITY + 1)).toThrow(
        'nationality must be between',
      );
    });

    test('rejects negative', () => {
      expect(() => validateNationality(-1)).toThrow('nationality must be between');
    });

    test('rejects NaN', () => {
      expect(() => validateNationality(NaN)).toThrow('nationality must be an integer');
    });
  });

  describe('validateMinAge - boundary fuzzing', () => {
    test('accepts 0', () => {
      expect(() => validateMinAge(0)).not.toThrow();
    });

    test('accepts MAX_AGE', () => {
      expect(() => validateMinAge(MAX_AGE)).not.toThrow();
    });

    test('rejects MAX_AGE + 1', () => {
      expect(() => validateMinAge(MAX_AGE + 1)).toThrow('minAge must be between');
    });

    test('rejects negative', () => {
      expect(() => validateMinAge(-1)).toThrow('minAge must be between');
    });

    test('rejects NaN', () => {
      expect(() => validateMinAge(NaN)).toThrow('minAge must be an integer');
    });

    test('rejects Infinity', () => {
      expect(() => validateMinAge(Infinity)).toThrow('minAge must be an integer');
    });
  });

  describe('validateBigIntString - boundary fuzzing', () => {
    test('rejects empty string', () => {
      expect(() => validateBigIntString('', 'test')).toThrow('must be a non-empty string');
    });

    test('accepts 0', () => {
      expect(() => validateBigIntString('0', 'test')).not.toThrow();
    });

    test('accepts very large number', () => {
      expect(() =>
        validateBigIntString('99999999999999999999999999999999999999999999', 'test'),
      ).not.toThrow();
    });

    test('rejects invalid string', () => {
      expect(() => validateBigIntString('not-a-number', 'test')).toThrow('not a valid numeric');
    });

    test('accepts hex string with 0x prefix', () => {
      expect(() => validateBigIntString('0x1234', 'test')).not.toThrow();
    });
  });

  describe('validateHexString - boundary fuzzing', () => {
    test('rejects empty string', () => {
      expect(() => validateHexString('', 'test')).toThrow('must be a non-empty string');
    });

    test('accepts valid hex', () => {
      expect(() => validateHexString('deadbeef', 'test')).not.toThrow();
    });

    test('accepts uppercase hex', () => {
      expect(() => validateHexString('DEADBEEF', 'test')).not.toThrow();
    });

    test('rejects hex with 0x prefix', () => {
      expect(() => validateHexString('0xdeadbeef', 'test')).toThrow('must be a hex string');
    });

    test('rejects non-hex characters', () => {
      expect(() => validateHexString('deadbeefg', 'test')).toThrow('must be a hex string');
    });
  });
});

describe('Security: Timing-Safe Comparisons', () => {
  describe('constantTimeEqual', () => {
    test('returns true for equal strings', () => {
      expect(constantTimeEqual('hello', 'hello')).toBe(true);
    });

    test('returns false for unequal strings of same length', () => {
      expect(constantTimeEqual('hello', 'world')).toBe(false);
    });

    test('returns false for different length strings', () => {
      expect(constantTimeEqual('short', 'verylongstring')).toBe(false);
    });

    test('returns true for empty strings', () => {
      expect(constantTimeEqual('', '')).toBe(true);
    });

    test('handles unicode correctly', () => {
      expect(constantTimeEqual('🔐', '🔐')).toBe(true);
      expect(constantTimeEqual('🔐', '🔓')).toBe(false);
    });

    test('handles very long strings', () => {
      const long = 'a'.repeat(10000);
      expect(constantTimeEqual(long, long)).toBe(true);
      expect(constantTimeEqual(long, long + 'b')).toBe(false);
    });

    test('handles null bytes', () => {
      expect(constantTimeEqual('\x00\x00', '\x00\x00')).toBe(true);
      expect(constantTimeEqual('\x00\x00', '\x00\x01')).toBe(false);
    });

    test('different lengths always return false', () => {
      expect(constantTimeEqual('a', 'aa')).toBe(false);
      expect(constantTimeEqual('aa', 'a')).toBe(false);
    });
  });

  describe('constantTimeArrayEqual', () => {
    test('returns true for equal arrays', () => {
      expect(constantTimeArrayEqual(['a', 'b', 'c'], ['a', 'b', 'c'])).toBe(true);
    });

    test('returns false for unequal arrays', () => {
      expect(constantTimeArrayEqual(['a', 'b', 'c'], ['a', 'b', 'd'])).toBe(false);
    });

    test('returns false for different length arrays', () => {
      expect(constantTimeArrayEqual(['a', 'b'], ['a', 'b', 'c'])).toBe(false);
    });

    test('returns true for empty arrays', () => {
      expect(constantTimeArrayEqual([], [])).toBe(true);
    });

    test('handles arrays with empty string elements', () => {
      expect(constantTimeArrayEqual(['', ''], ['', ''])).toBe(true);
      expect(constantTimeArrayEqual(['', 'a'], ['', 'b'])).toBe(false);
    });

    test('handles single element arrays', () => {
      expect(constantTimeArrayEqual(['test'], ['test'])).toBe(true);
      expect(constantTimeArrayEqual(['test'], ['fail'])).toBe(false);
    });
  });
});

describe('Security: Field Element Boundaries', () => {
  test('accepts 0', () => {
    expect(() => validateFieldElement(0n, 'test')).not.toThrow();
  });

  test('accepts BN128_FIELD_ORDER - 1', () => {
    expect(() => validateFieldElement(BN128_FIELD_ORDER - 1n, 'test')).not.toThrow();
  });

  test('rejects BN128_FIELD_ORDER', () => {
    expect(() => validateFieldElement(BN128_FIELD_ORDER, 'test')).toThrow(
      'not a valid BN128 field element',
    );
  });

  test('rejects negative', () => {
    expect(() => validateFieldElement(-1n, 'test')).toThrow('not a valid BN128 field element');
  });

  test('rejects way over field order', () => {
    expect(() => validateFieldElement(BN128_FIELD_ORDER * 2n, 'test')).toThrow(
      'not a valid BN128 field element',
    );
  });
});

describe('Security: Nonce Edge Cases', () => {
  test('rejects below MIN_NONCE_LENGTH', () => {
    const short = 'a'.repeat(MIN_NONCE_LENGTH - 1);
    expect(() => validateNonce(short)).toThrow('nonce must be at least');
  });

  test('accepts MIN_NONCE_LENGTH', () => {
    const exact = 'a'.repeat(MIN_NONCE_LENGTH);
    expect(() => validateNonce(exact)).not.toThrow();
  });

  test('accepts MAX_NONCE_LENGTH', () => {
    const max = 'a'.repeat(MAX_NONCE_LENGTH);
    expect(() => validateNonce(max)).not.toThrow();
  });

  test('rejects above MAX_NONCE_LENGTH', () => {
    const tooLong = 'a'.repeat(MAX_NONCE_LENGTH + 1);
    expect(() => validateNonce(tooLong)).toThrow('nonce must be at most');
  });

  test('rejects empty string', () => {
    expect(() => validateNonce('')).toThrow('nonce must be at least');
  });
});

describe('Security: validateClaimType', () => {
  test('accepts age', () => {
    expect(() => validateClaimType('age')).not.toThrow();
  });

  test('accepts nationality', () => {
    expect(() => validateClaimType('nationality')).not.toThrow();
  });

  test('accepts age-revocable', () => {
    expect(() => validateClaimType('age-revocable')).not.toThrow();
  });

  test('rejects unknown claim type', () => {
    expect(() => validateClaimType('unknown')).toThrow('Invalid claim type: unknown');
  });

  test('rejects empty string', () => {
    expect(() => validateClaimType('')).toThrow('Invalid claim type');
  });

  test('rejects similar but incorrect types', () => {
    expect(() => validateClaimType('Age')).toThrow('Invalid claim type: Age');
    expect(() => validateClaimType('age-revoke')).toThrow('Invalid claim type: age-revoke');
    expect(() => validateClaimType('nationality-revocable')).toThrow(
      'Invalid claim type: nationality-revocable',
    );
  });
});

describe('Security: Timestamp Validation', () => {
  test('rejects timestamps in the far future', () => {
    const farFuture = Date.now() + 1000 * 60 * 60; // 1 hour ahead
    expect(() => validateRequestTimestamp(farFuture)).toThrow('requestTimestamp is in the future');
  });

  test('rejects very old timestamps', () => {
    const veryOld = Date.now() - 1000 * 60 * 10; // 10 minutes ago
    expect(() => validateRequestTimestamp(veryOld)).toThrow('requestTimestamp is too old');
  });

  test('accepts recent timestamp', () => {
    const recent = Date.now() - 1000; // 1 second ago
    expect(() => validateRequestTimestamp(recent)).not.toThrow();
  });

  test('rejects 0', () => {
    expect(() => validateRequestTimestamp(0)).toThrow('requestTimestamp is too old');
  });

  test('rejects negative', () => {
    expect(() => validateRequestTimestamp(-1)).toThrow(
      'requestTimestamp must be a positive integer',
    );
  });

  test('rejects NaN', () => {
    expect(() => validateRequestTimestamp(NaN)).toThrow(
      'requestTimestamp must be a positive integer',
    );
  });
});

describe('Security: Scope ID Validation', () => {
  test('rejects empty string', () => {
    expect(() => validateScopeId('')).toThrow('Scope ID must be a non-empty string');
  });

  test('accepts normal scope ID', () => {
    expect(() => validateScopeId('my-app-scope')).not.toThrow();
  });

  test('rejects extremely long scope ID', () => {
    const tooLong = 'a'.repeat(257);
    expect(() => validateScopeId(tooLong)).toThrow('Scope ID must be at most');
  });
});

describe('Security: Positive Integer Validation', () => {
  test('accepts 1', () => {
    expect(() => validatePositiveInt(1, 'test')).not.toThrow();
  });

  test('rejects 0', () => {
    expect(() => validatePositiveInt(0, 'test')).toThrow('test must be a positive integer');
  });

  test('rejects negative', () => {
    expect(() => validatePositiveInt(-1, 'test')).toThrow('test must be a positive integer');
  });

  test('rejects float', () => {
    expect(() => validatePositiveInt(1.5, 'test')).toThrow('test must be a positive integer');
  });

  test('accepts MAX_SAFE_INTEGER', () => {
    expect(() => validatePositiveInt(Number.MAX_SAFE_INTEGER, 'test')).not.toThrow();
  });
});
