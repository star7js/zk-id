import { expect } from 'chai';
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
  BN128_FIELD_ORDER,
  MIN_NONCE_LENGTH,
  MAX_NONCE_LENGTH,
  MAX_SCOPE_ID_LENGTH,
} from '../src/validation';

describe('Input Validation', () => {
  describe('validateBirthYear', () => {
    it('should accept valid birth years', () => {
      expect(() => validateBirthYear(1990)).to.not.throw();
      expect(() => validateBirthYear(1900)).to.not.throw();
      expect(() => validateBirthYear(2020)).to.not.throw();
    });

    it('should reject non-integer birth years', () => {
      expect(() => validateBirthYear(1990.5)).to.throw(/integer/);
      expect(() => validateBirthYear(NaN)).to.throw(/integer/);
    });

    it('should reject out-of-range birth years', () => {
      expect(() => validateBirthYear(1899)).to.throw(/birthYear/);
      expect(() => validateBirthYear(3000)).to.throw(/birthYear/);
    });
  });

  describe('validateNationality', () => {
    it('should accept valid nationality codes', () => {
      expect(() => validateNationality(1)).to.not.throw();
      expect(() => validateNationality(840)).to.not.throw();
      expect(() => validateNationality(999)).to.not.throw();
    });

    it('should reject invalid nationality codes', () => {
      expect(() => validateNationality(0)).to.throw(/nationality/);
      expect(() => validateNationality(1000)).to.throw(/nationality/);
      expect(() => validateNationality(-1)).to.throw(/nationality/);
      expect(() => validateNationality(1.5)).to.throw(/integer/);
    });
  });

  describe('validateMinAge', () => {
    it('should accept valid age values', () => {
      expect(() => validateMinAge(0)).to.not.throw();
      expect(() => validateMinAge(18)).to.not.throw();
      expect(() => validateMinAge(150)).to.not.throw();
    });

    it('should reject invalid age values', () => {
      expect(() => validateMinAge(-1)).to.throw(/minAge/);
      expect(() => validateMinAge(151)).to.throw(/minAge/);
      expect(() => validateMinAge(18.5)).to.throw(/integer/);
    });
  });

  describe('validateNonce', () => {
    it('should accept valid nonces', () => {
      const validNonce = 'a'.repeat(MIN_NONCE_LENGTH);
      expect(() => validateNonce(validNonce)).to.not.throw();
    });

    it('should reject short nonces', () => {
      expect(() => validateNonce('short')).to.throw(/at least/);
      expect(() => validateNonce('')).to.throw(/at least/);
    });

    it('should reject overly long nonces', () => {
      const longNonce = 'a'.repeat(MAX_NONCE_LENGTH + 1);
      expect(() => validateNonce(longNonce)).to.throw(/at most/);
    });

    it('should reject non-string nonces', () => {
      expect(() => validateNonce(123 as unknown as string)).to.throw(/string/);
    });
  });

  describe('validateRequestTimestamp', () => {
    it('should accept a recent timestamp', () => {
      expect(() => validateRequestTimestamp(Date.now())).to.not.throw();
      expect(() => validateRequestTimestamp(Date.now() - 1000)).to.not.throw();
    });

    it('should reject future timestamps', () => {
      expect(() => validateRequestTimestamp(Date.now() + 60_000)).to.throw(/future/);
    });

    it('should reject stale timestamps', () => {
      expect(() => validateRequestTimestamp(Date.now() - 10 * 60 * 1000)).to.throw(/too old/);
    });

    it('should reject non-positive timestamps', () => {
      expect(() => validateRequestTimestamp(0)).to.throw(/positive integer/);
      expect(() => validateRequestTimestamp(-1)).to.throw(/positive integer/);
    });
  });

  describe('validateBigIntString', () => {
    it('should accept valid BigInt strings', () => {
      expect(() => validateBigIntString('12345', 'test')).to.not.throw();
      expect(() => validateBigIntString('0', 'test')).to.not.throw();
      expect(() => validateBigIntString('0x1a2b3c', 'test')).to.not.throw();
    });

    it('should reject invalid BigInt strings', () => {
      expect(() => validateBigIntString('', 'test')).to.throw(/non-empty/);
      expect(() => validateBigIntString('not-a-number', 'test')).to.throw(/valid numeric/);
    });
  });

  describe('validateFieldElement', () => {
    it('should accept valid field elements', () => {
      expect(() => validateFieldElement(0n, 'test')).to.not.throw();
      expect(() => validateFieldElement(1n, 'test')).to.not.throw();
      expect(() => validateFieldElement(BN128_FIELD_ORDER - 1n, 'test')).to.not.throw();
    });

    it('should reject out-of-range values', () => {
      expect(() => validateFieldElement(-1n, 'test')).to.throw(/field element/);
      expect(() => validateFieldElement(BN128_FIELD_ORDER, 'test')).to.throw(/field element/);
    });
  });

  describe('validateHexString', () => {
    it('should accept valid hex strings', () => {
      expect(() => validateHexString('deadbeef', 'test')).to.not.throw();
      expect(() => validateHexString('0123456789abcdefABCDEF', 'test')).to.not.throw();
    });

    it('should reject invalid hex strings', () => {
      expect(() => validateHexString('', 'test')).to.throw(/non-empty/);
      expect(() => validateHexString('xyz', 'test')).to.throw(/hex/);
      expect(() => validateHexString('0x123', 'test')).to.throw(/hex/); // 0x prefix not valid hex
    });
  });

  describe('validateScopeId', () => {
    it('should accept valid scope IDs', () => {
      expect(() => validateScopeId('election-2026')).to.not.throw();
      expect(() => validateScopeId('a')).to.not.throw();
    });

    it('should reject empty scope IDs', () => {
      expect(() => validateScopeId('')).to.throw(/non-empty/);
    });

    it('should reject overly long scope IDs', () => {
      const longId = 'a'.repeat(MAX_SCOPE_ID_LENGTH + 1);
      expect(() => validateScopeId(longId)).to.throw(/at most/);
    });
  });

  describe('validatePositiveInt', () => {
    it('should accept positive integers', () => {
      expect(() => validatePositiveInt(1, 'test')).to.not.throw();
      expect(() => validatePositiveInt(1000, 'test')).to.not.throw();
    });

    it('should reject non-positive values', () => {
      expect(() => validatePositiveInt(0, 'test')).to.throw(/positive integer/);
      expect(() => validatePositiveInt(-1, 'test')).to.throw(/positive integer/);
      expect(() => validatePositiveInt(1.5, 'test')).to.throw(/positive integer/);
    });
  });
});
