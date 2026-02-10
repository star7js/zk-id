/**
 * Input validation utilities.
 *
 * Provides reusable boundary checks for values that enter the system from
 * external callers (API requests, user input, credential fields, config).
 * Internal-only values that are produced and consumed within zk-id do not
 * need re-validation at every hop.
 */

import { ZkIdValidationError } from './errors';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** BN128 scalar field order (the max value a field element can take + 1). */
export const BN128_FIELD_ORDER =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;

/** Minimum acceptable nonce length in characters. */
export const MIN_NONCE_LENGTH = 16;

/** Maximum acceptable nonce length in characters. */
export const MAX_NONCE_LENGTH = 256;

/** Maximum reasonable request age in milliseconds (5 minutes). */
export const MAX_REQUEST_AGE_MS = 5 * 60 * 1000;

/** Minimum plausible birth year. */
export const MIN_BIRTH_YEAR = 1900;

/** Maximum plausible age in years. */
export const MAX_AGE = 150;

/** ISO 3166-1 numeric code range. */
export const MIN_NATIONALITY = 1;
export const MAX_NATIONALITY = 999;

/** Maximum scope ID length. */
export const MAX_SCOPE_ID_LENGTH = 256;

// ---------------------------------------------------------------------------
// Validation functions
// ---------------------------------------------------------------------------

/**
 * Validate that a birth year is within plausible bounds.
 * @throws Error if out of range
 */
export function validateBirthYear(birthYear: number): void {
  if (!Number.isInteger(birthYear)) {
    throw new ZkIdValidationError('birthYear must be an integer', 'birthYear');
  }
  if (birthYear < MIN_BIRTH_YEAR || birthYear > new Date().getFullYear()) {
    throw new ZkIdValidationError(`birthYear must be between ${MIN_BIRTH_YEAR} and ${new Date().getFullYear()}`, 'birthYear');
  }
}

/**
 * Validate an ISO 3166-1 numeric nationality code.
 * @throws Error if out of range
 */
export function validateNationality(nationality: number): void {
  if (!Number.isInteger(nationality)) {
    throw new ZkIdValidationError('nationality must be an integer', 'nationality');
  }
  if (nationality < MIN_NATIONALITY || nationality > MAX_NATIONALITY) {
    throw new ZkIdValidationError(`nationality must be between ${MIN_NATIONALITY} and ${MAX_NATIONALITY}`, 'nationality');
  }
}

/**
 * Validate a minimum-age parameter.
 * @throws Error if out of range
 */
export function validateMinAge(minAge: number): void {
  if (!Number.isInteger(minAge)) {
    throw new ZkIdValidationError('minAge must be an integer', 'minAge');
  }
  if (minAge < 0 || minAge > MAX_AGE) {
    throw new ZkIdValidationError(`minAge must be between 0 and ${MAX_AGE}`, 'minAge');
  }
}

/**
 * Validate a nonce string for sufficient entropy.
 *
 * Nonces must be:
 *   - Non-empty
 *   - At least MIN_NONCE_LENGTH characters (128 bits of hex = 32 chars)
 *   - At most MAX_NONCE_LENGTH characters
 *
 * @throws Error if nonce is invalid
 */
export function validateNonce(nonce: string): void {
  if (typeof nonce !== 'string') {
    throw new ZkIdValidationError('nonce must be a string', 'nonce');
  }
  if (nonce.length < MIN_NONCE_LENGTH) {
    throw new ZkIdValidationError(`nonce must be at least ${MIN_NONCE_LENGTH} characters (got ${nonce.length})`, 'nonce');
  }
  if (nonce.length > MAX_NONCE_LENGTH) {
    throw new ZkIdValidationError(`nonce must be at most ${MAX_NONCE_LENGTH} characters (got ${nonce.length})`, 'nonce');
  }
}

/**
 * Validate a request timestamp in milliseconds.
 *
 * Must be:
 *   - A positive integer
 *   - Not in the future (with 30s tolerance for clock skew)
 *   - Not older than MAX_REQUEST_AGE_MS
 *
 * @throws Error if timestamp is invalid
 */
export function validateRequestTimestamp(timestampMs: number): void {
  if (!Number.isInteger(timestampMs) || timestampMs <= 0) {
    throw new ZkIdValidationError('requestTimestamp must be a positive integer (milliseconds)', 'requestTimestamp');
  }
  const now = Date.now();
  const clockSkewMs = 30_000; // 30 seconds
  if (timestampMs > now + clockSkewMs) {
    throw new ZkIdValidationError('requestTimestamp is in the future', 'requestTimestamp');
  }
  if (now - timestampMs > MAX_REQUEST_AGE_MS) {
    throw new ZkIdValidationError(`requestTimestamp is too old (max age: ${MAX_REQUEST_AGE_MS / 1000}s)`, 'requestTimestamp');
  }
}

/**
 * Validate that a string represents a valid BigInt (numeric string or hex).
 * @throws Error if not a valid BigInt string
 */
export function validateBigIntString(value: string, label: string): void {
  if (typeof value !== 'string' || value.length === 0) {
    throw new ZkIdValidationError(`${label} must be a non-empty string`, label);
  }
  try {
    BigInt(value);
  } catch {
    throw new ZkIdValidationError(`${label} is not a valid numeric string`, label);
  }
}

/**
 * Validate that a value is a valid BN128 field element (0 <= value < field order).
 * @throws Error if out of field range
 */
export function validateFieldElement(value: bigint, label: string): void {
  if (value < 0n || value >= BN128_FIELD_ORDER) {
    throw new ZkIdValidationError(`${label} is not a valid BN128 field element`, label);
  }
}

/**
 * Validate a hex string (e.g., a salt).
 * @throws Error if not valid hex
 */
export function validateHexString(value: string, label: string): void {
  if (typeof value !== 'string' || value.length === 0) {
    throw new ZkIdValidationError(`${label} must be a non-empty string`, label);
  }
  if (!/^[0-9a-fA-F]+$/.test(value)) {
    throw new ZkIdValidationError(`${label} must be a hex string`, label);
  }
}

/**
 * Validate a scope ID for nullifier computation.
 * @throws Error if invalid
 */
export function validateScopeId(scopeId: string): void {
  if (typeof scopeId !== 'string' || scopeId.length === 0) {
    throw new ZkIdValidationError('Scope ID must be a non-empty string', 'scopeId');
  }
  if (scopeId.length > MAX_SCOPE_ID_LENGTH) {
    throw new ZkIdValidationError(
      `Scope ID must be at most ${MAX_SCOPE_ID_LENGTH} characters (got ${scopeId.length})`,
      'scopeId',
    );
  }
}

/**
 * Validate a positive integer configuration value.
 * @throws Error if not a positive integer
 */
export function validatePositiveInt(value: number, label: string): void {
  if (!Number.isInteger(value) || value <= 0) {
    throw new ZkIdValidationError(`${label} must be a positive integer`, label);
  }
}
