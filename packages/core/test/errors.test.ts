import { expect } from 'chai';
import {
  ZkIdError,
  ZkIdValidationError,
  ZkIdConfigError,
  ZkIdCredentialError,
  ZkIdProofError,
  ZkIdCryptoError,
  ZkIdErrorCode,
} from '../src/errors';

describe('Error Classes', () => {
  describe('ZkIdError', () => {
    it('should create base error with code and message', () => {
      const error = new ZkIdError('TEST_CODE', 'Test message');
      expect(error).to.be.instanceOf(Error);
      expect(error).to.be.instanceOf(ZkIdError);
      expect(error.name).to.equal('ZkIdError');
      expect(error.code).to.equal('TEST_CODE');
      expect(error.message).to.equal('Test message');
    });

    it('should have proper prototype chain', () => {
      const error = new ZkIdError('TEST', 'Message');
      expect(error instanceof Error).to.be.true;
      expect(error instanceof ZkIdError).to.be.true;
    });

    it('should have stack trace', () => {
      const error = new ZkIdError('TEST', 'Message');
      expect(error.stack).to.be.a('string');
      expect(error.stack).to.include('ZkIdError');
    });
  });

  describe('ZkIdValidationError', () => {
    it('should create validation error with message', () => {
      const error = new ZkIdValidationError('Invalid input');
      expect(error).to.be.instanceOf(Error);
      expect(error).to.be.instanceOf(ZkIdError);
      expect(error).to.be.instanceOf(ZkIdValidationError);
      expect(error.name).to.equal('ZkIdValidationError');
      expect(error.code).to.equal('VALIDATION_ERROR');
      expect(error.message).to.equal('Invalid input');
      expect(error.field).to.be.undefined;
    });

    it('should create validation error with field', () => {
      const error = new ZkIdValidationError('Invalid age', 'birthYear');
      expect(error.field).to.equal('birthYear');
      expect(error.message).to.equal('Invalid age');
      expect(error.code).to.equal('VALIDATION_ERROR');
    });

    it('should inherit from ZkIdError', () => {
      const error = new ZkIdValidationError('Test');
      expect(error instanceof ZkIdError).to.be.true;
    });
  });

  describe('ZkIdConfigError', () => {
    it('should create config error', () => {
      const error = new ZkIdConfigError('Missing config option');
      expect(error).to.be.instanceOf(Error);
      expect(error).to.be.instanceOf(ZkIdError);
      expect(error).to.be.instanceOf(ZkIdConfigError);
      expect(error.name).to.equal('ZkIdConfigError');
      expect(error.code).to.equal('CONFIG_ERROR');
      expect(error.message).to.equal('Missing config option');
    });
  });

  describe('ZkIdCredentialError', () => {
    it('should create credential error with default code', () => {
      const error = new ZkIdCredentialError('Credential not found');
      expect(error).to.be.instanceOf(Error);
      expect(error).to.be.instanceOf(ZkIdError);
      expect(error).to.be.instanceOf(ZkIdCredentialError);
      expect(error.name).to.equal('ZkIdCredentialError');
      expect(error.code).to.equal('CREDENTIAL_ERROR');
      expect(error.message).to.equal('Credential not found');
    });

    it('should create credential error with custom code', () => {
      const error = new ZkIdCredentialError('Not found', 'CREDENTIAL_NOT_FOUND');
      expect(error.code).to.equal('CREDENTIAL_NOT_FOUND');
      expect(error.message).to.equal('Not found');
    });
  });

  describe('ZkIdProofError', () => {
    it('should create proof error with default code', () => {
      const error = new ZkIdProofError('Proof generation failed');
      expect(error).to.be.instanceOf(Error);
      expect(error).to.be.instanceOf(ZkIdError);
      expect(error).to.be.instanceOf(ZkIdProofError);
      expect(error.name).to.equal('ZkIdProofError');
      expect(error.code).to.equal('PROOF_ERROR');
      expect(error.message).to.equal('Proof generation failed');
    });

    it('should create proof error with custom code', () => {
      const error = new ZkIdProofError('Unknown type', 'UNKNOWN_PROOF_TYPE');
      expect(error.code).to.equal('UNKNOWN_PROOF_TYPE');
      expect(error.message).to.equal('Unknown type');
    });
  });

  describe('ZkIdCryptoError', () => {
    it('should create crypto error with default code', () => {
      const error = new ZkIdCryptoError('Key generation failed');
      expect(error).to.be.instanceOf(Error);
      expect(error).to.be.instanceOf(ZkIdError);
      expect(error).to.be.instanceOf(ZkIdCryptoError);
      expect(error.name).to.equal('ZkIdCryptoError');
      expect(error.code).to.equal('CRYPTO_ERROR');
      expect(error.message).to.equal('Key generation failed');
    });

    it('should create crypto error with custom code', () => {
      const error = new ZkIdCryptoError('Invalid key format', 'INVALID_KEY');
      expect(error.code).to.equal('INVALID_KEY');
      expect(error.message).to.equal('Invalid key format');
    });
  });

  describe('ZkIdErrorCode constants', () => {
    it('should have all expected error codes', () => {
      expect(ZkIdErrorCode.VALIDATION_ERROR).to.equal('VALIDATION_ERROR');
      expect(ZkIdErrorCode.CONFIG_ERROR).to.equal('CONFIG_ERROR');
      expect(ZkIdErrorCode.CREDENTIAL_ERROR).to.equal('CREDENTIAL_ERROR');
      expect(ZkIdErrorCode.CREDENTIAL_NOT_FOUND).to.equal('CREDENTIAL_NOT_FOUND');
      expect(ZkIdErrorCode.INVALID_CREDENTIAL_FORMAT).to.equal('INVALID_CREDENTIAL_FORMAT');
      expect(ZkIdErrorCode.PROOF_ERROR).to.equal('PROOF_ERROR');
      expect(ZkIdErrorCode.UNKNOWN_PROOF_TYPE).to.equal('UNKNOWN_PROOF_TYPE');
      expect(ZkIdErrorCode.UNKNOWN_CLAIM_TYPE).to.equal('UNKNOWN_CLAIM_TYPE');
      expect(ZkIdErrorCode.CRYPTO_ERROR).to.equal('CRYPTO_ERROR');
      expect(ZkIdErrorCode.INVALID_KEY).to.equal('INVALID_KEY');
    });
  });

  describe('Error catching and instanceof checks', () => {
    it('should catch errors by type', () => {
      try {
        throw new ZkIdValidationError('Test validation');
      } catch (error) {
        expect(error).to.be.instanceOf(ZkIdValidationError);
        expect(error).to.be.instanceOf(ZkIdError);
        expect(error).to.be.instanceOf(Error);
        if (error instanceof ZkIdValidationError) {
          expect(error.code).to.equal('VALIDATION_ERROR');
          expect(error.field).to.be.undefined;
        }
      }
    });

    it('should catch errors with field information', () => {
      try {
        throw new ZkIdValidationError('Invalid value', 'testField');
      } catch (error) {
        if (error instanceof ZkIdValidationError) {
          expect(error.field).to.equal('testField');
          expect(error.message).to.equal('Invalid value');
        }
      }
    });

    it('should differentiate between error types', () => {
      const validationError = new ZkIdValidationError('Validation failed');
      const configError = new ZkIdConfigError('Config failed');

      expect(validationError).to.be.instanceOf(ZkIdValidationError);
      expect(validationError).to.not.be.instanceOf(ZkIdConfigError);

      expect(configError).to.be.instanceOf(ZkIdConfigError);
      expect(configError).to.not.be.instanceOf(ZkIdValidationError);

      // Both are ZkIdErrors
      expect(validationError).to.be.instanceOf(ZkIdError);
      expect(configError).to.be.instanceOf(ZkIdError);
    });
  });

  describe('Backwards compatibility', () => {
    it('should preserve Error.message for legacy code', () => {
      const error = new ZkIdValidationError('Legacy message');
      expect(error.message).to.equal('Legacy message');
      expect(String(error)).to.include('Legacy message');
    });

    it('should work with error.message checks', () => {
      try {
        throw new ZkIdCredentialError('Credential expired');
      } catch (error: any) {
        expect(error.message).to.include('expired');
        expect(error.message).to.equal('Credential expired');
      }
    });
  });
});
