/**
 * Custom error hierarchy for zk-id
 *
 * Provides typed error classes for better error handling and programmatic error checking.
 * All errors extend ZkIdError which has a code property for categorization.
 */

/**
 * Base error class for all zk-id errors
 */
export class ZkIdError extends Error {
  readonly code: string;

  constructor(code: string, message: string) {
    super(message);
    this.name = 'ZkIdError';
    this.code = code;
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

/**
 * Validation error for invalid input or constraints
 */
export class ZkIdValidationError extends ZkIdError {
  readonly field?: string;

  constructor(message: string, field?: string) {
    super('VALIDATION_ERROR', message);
    this.name = 'ZkIdValidationError';
    this.field = field;
  }
}

/**
 * Configuration error for invalid setup or options
 */
export class ZkIdConfigError extends ZkIdError {
  constructor(message: string) {
    super('CONFIG_ERROR', message);
    this.name = 'ZkIdConfigError';
  }
}

/**
 * Credential error for credential-related issues
 */
export class ZkIdCredentialError extends ZkIdError {
  constructor(message: string, code = 'CREDENTIAL_ERROR') {
    super(code, message);
    this.name = 'ZkIdCredentialError';
  }
}

/**
 * Proof error for proof generation/verification issues
 */
export class ZkIdProofError extends ZkIdError {
  constructor(message: string, code = 'PROOF_ERROR') {
    super(code, message);
    this.name = 'ZkIdProofError';
  }
}

/**
 * Cryptographic error for crypto operations
 */
export class ZkIdCryptoError extends ZkIdError {
  constructor(message: string, code = 'CRYPTO_ERROR') {
    super(code, message);
    this.name = 'ZkIdCryptoError';
  }
}

/**
 * Error codes for programmatic error checking
 */
export const ZkIdErrorCode = {
  VALIDATION_ERROR: 'VALIDATION_ERROR',
  CONFIG_ERROR: 'CONFIG_ERROR',
  CREDENTIAL_ERROR: 'CREDENTIAL_ERROR',
  CREDENTIAL_NOT_FOUND: 'CREDENTIAL_NOT_FOUND',
  INVALID_CREDENTIAL_FORMAT: 'INVALID_CREDENTIAL_FORMAT',
  PROOF_ERROR: 'PROOF_ERROR',
  UNKNOWN_PROOF_TYPE: 'UNKNOWN_PROOF_TYPE',
  UNKNOWN_CLAIM_TYPE: 'UNKNOWN_CLAIM_TYPE',
  CRYPTO_ERROR: 'CRYPTO_ERROR',
  INVALID_KEY: 'INVALID_KEY',
} as const;

export type ZkIdErrorCodeType = (typeof ZkIdErrorCode)[keyof typeof ZkIdErrorCode];
