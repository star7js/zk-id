import { expect } from 'chai';
import {
  validateBirthYear,
  validateNationality,
  validateMinAge,
  validateFieldElement,
  validateNonce,
  validateClaimType,
  BN128_FIELD_ORDER,
  MIN_NONCE_LENGTH,
  MAX_NONCE_LENGTH,
  MIN_BIRTH_YEAR,
  MAX_AGE,
  MIN_NATIONALITY,
  MAX_NATIONALITY,
} from '../src/validation';
import { constantTimeEqual, constantTimeArrayEqual } from '../src/timing-safe';

describe('Security - Boundary Fuzzing', () => {
  describe('Boundary Fuzzing - Birth Year', () => {
    it('should reject NaN', () => {
      expect(() => validateBirthYear(NaN)).to.throw(/integer/);
    });

    it('should reject Infinity', () => {
      expect(() => validateBirthYear(Infinity)).to.throw(/integer/);
    });

    it('should reject -Infinity', () => {
      expect(() => validateBirthYear(-Infinity)).to.throw(/integer/);
    });

    it('should reject 1899 (below minimum)', () => {
      expect(() => validateBirthYear(1899)).to.throw(/birthYear/);
    });

    it('should accept 1900 (minimum boundary)', () => {
      expect(() => validateBirthYear(1900)).to.not.throw();
    });

    it('should reject non-integer values', () => {
      expect(() => validateBirthYear(1990.5)).to.throw(/integer/);
    });

    it('should reject future years', () => {
      const futureYear = new Date().getFullYear() + 1;
      expect(() => validateBirthYear(futureYear)).to.throw(/birthYear/);
    });
  });

  describe('Boundary Fuzzing - Nationality', () => {
    it('should reject 0 (below minimum)', () => {
      expect(() => validateNationality(0)).to.throw(/nationality/);
    });

    it('should reject 1000 (above maximum)', () => {
      expect(() => validateNationality(1000)).to.throw(/nationality/);
    });

    it('should accept 1 (minimum boundary)', () => {
      expect(() => validateNationality(1)).to.not.throw();
    });

    it('should accept 999 (maximum boundary)', () => {
      expect(() => validateNationality(999)).to.not.throw();
    });

    it('should reject NaN', () => {
      expect(() => validateNationality(NaN)).to.throw(/integer/);
    });

    it('should reject non-integer values', () => {
      expect(() => validateNationality(1.5)).to.throw(/integer/);
    });
  });

  describe('Boundary Fuzzing - Min Age', () => {
    it('should reject -1 (below minimum)', () => {
      expect(() => validateMinAge(-1)).to.throw(/minAge/);
    });

    it('should accept 0 (minimum boundary)', () => {
      expect(() => validateMinAge(0)).to.not.throw();
    });

    it('should accept 150 (maximum boundary)', () => {
      expect(() => validateMinAge(150)).to.not.throw();
    });

    it('should reject 151 (above maximum)', () => {
      expect(() => validateMinAge(151)).to.throw(/minAge/);
    });

    it('should reject NaN', () => {
      expect(() => validateMinAge(NaN)).to.throw(/integer/);
    });
  });

  describe('Field Element Boundaries', () => {
    it('should accept 0 (minimum boundary)', () => {
      expect(() => validateFieldElement(0n, 'test')).to.not.throw();
    });

    it('should accept BN128_FIELD_ORDER - 1 (maximum boundary)', () => {
      expect(() => validateFieldElement(BN128_FIELD_ORDER - 1n, 'test')).to.not.throw();
    });

    it('should reject BN128_FIELD_ORDER (at boundary)', () => {
      expect(() => validateFieldElement(BN128_FIELD_ORDER, 'test')).to.throw(/field element/);
    });

    it('should reject negative values', () => {
      expect(() => validateFieldElement(-1n, 'test')).to.throw(/field element/);
    });

    it('should reject values above 2^256', () => {
      const huge = 2n ** 256n;
      expect(() => validateFieldElement(huge, 'test')).to.throw(/field element/);
    });
  });

  describe('Nonce Edge Cases', () => {
    it('should reject nonce with MIN_NONCE_LENGTH - 1 characters', () => {
      const shortNonce = 'a'.repeat(MIN_NONCE_LENGTH - 1);
      expect(() => validateNonce(shortNonce)).to.throw(/at least/);
    });

    it('should accept nonce with MIN_NONCE_LENGTH characters', () => {
      const minNonce = 'a'.repeat(MIN_NONCE_LENGTH);
      expect(() => validateNonce(minNonce)).to.not.throw();
    });

    it('should accept nonce with MAX_NONCE_LENGTH characters', () => {
      const maxNonce = 'a'.repeat(MAX_NONCE_LENGTH);
      expect(() => validateNonce(maxNonce)).to.not.throw();
    });

    it('should reject nonce with MAX_NONCE_LENGTH + 1 characters', () => {
      const longNonce = 'a'.repeat(MAX_NONCE_LENGTH + 1);
      expect(() => validateNonce(longNonce)).to.throw(/at most/);
    });
  });

  describe('validateClaimType', () => {
    it('should accept "age"', () => {
      expect(() => validateClaimType('age')).to.not.throw();
    });

    it('should accept "nationality"', () => {
      expect(() => validateClaimType('nationality')).to.not.throw();
    });

    it('should accept "age-revocable"', () => {
      expect(() => validateClaimType('age-revocable')).to.not.throw();
    });

    it('should reject unknown claim type', () => {
      expect(() => validateClaimType('unknown')).to.throw(/Invalid claim type/);
    });

    it('should reject empty string', () => {
      expect(() => validateClaimType('')).to.throw(/Invalid claim type/);
    });

    it('should reject uppercase "AGE"', () => {
      expect(() => validateClaimType('AGE')).to.throw(/Invalid claim type/);
    });
  });
});
