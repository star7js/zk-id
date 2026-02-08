import { expect } from 'chai';
import Ajv from 'ajv';
import addFormats from 'ajv-formats';
import { readFileSync } from 'fs';
import path from 'path';

// Load JSON schemas from docs/schemas/
const schemasDir = path.resolve(__dirname, '../../../docs/schemas');

function loadSchema(name: string): object {
  return JSON.parse(readFileSync(path.join(schemasDir, name), 'utf-8'));
}

const defsSchema = loadSchema('defs.json');
const proofRequestSchema = loadSchema('proof-request.json');
const proofResponseSchema = loadSchema('proof-response.json');
const signedProofRequestSchema = loadSchema('signed-proof-request.json');
const verificationResultSchema = loadSchema('verification-result.json');

function createValidator() {
  const ajv = new Ajv({ allErrors: true, strict: false });
  addFormats(ajv);
  ajv.addSchema(defsSchema, 'defs.json');
  return ajv;
}

describe('JSON Schema interop', () => {
  describe('ProofRequest schema', () => {
    it('validates a well-formed age ProofRequest', () => {
      const ajv = createValidator();
      const validate = ajv.compile(proofRequestSchema);
      const valid = validate({
        claimType: 'age',
        minAge: 18,
        nonce: '123456789',
        timestamp: '2026-02-08T12:00:00Z',
      });
      expect(valid).to.equal(true);
    });

    it('validates a well-formed nationality ProofRequest', () => {
      const ajv = createValidator();
      const validate = ajv.compile(proofRequestSchema);
      const valid = validate({
        claimType: 'nationality',
        targetNationality: 840,
        nonce: '123456789',
        timestamp: '2026-02-08T12:00:00Z',
      });
      expect(valid).to.equal(true);
    });

    it('validates a well-formed age-revocable ProofRequest', () => {
      const ajv = createValidator();
      const validate = ajv.compile(proofRequestSchema);
      const valid = validate({
        claimType: 'age-revocable',
        minAge: 21,
        nonce: '987654321',
        timestamp: '2026-02-08T12:00:00Z',
      });
      expect(valid).to.equal(true);
    });

    it('rejects ProofRequest with invalid claimType', () => {
      const ajv = createValidator();
      const validate = ajv.compile(proofRequestSchema);
      const valid = validate({
        claimType: 'invalid',
        nonce: '123',
        timestamp: '2026-02-08T12:00:00Z',
      });
      expect(valid).to.equal(false);
    });

    it('rejects ProofRequest missing required fields', () => {
      const ajv = createValidator();
      const validate = ajv.compile(proofRequestSchema);
      const valid = validate({ claimType: 'age' });
      expect(valid).to.equal(false);
    });
  });

  describe('ProofResponse schema', () => {
    const sampleProofResponse = {
      credentialId: 'cred-001',
      claimType: 'age',
      proof: {
        proof: {
          pi_a: ['1', '2', '3'],
          pi_b: [['4', '5'], ['6', '7']],
          pi_c: ['8', '9', '10'],
          protocol: 'groth16',
          curve: 'bn128',
        },
        publicSignals: {
          currentYear: 2026,
          minAge: 18,
          credentialHash: '12345678901234567890',
          nonce: '99999',
          requestTimestamp: 1707350400000,
        },
      },
      signedCredential: {
        credential: {
          id: 'cred-001',
          birthYear: 2000,
          nationality: 840,
          salt: 'random-salt',
          commitment: '12345678901234567890',
          createdAt: '2026-01-01T00:00:00Z',
        },
        issuer: 'test-issuer',
        signature: 'base64signature==',
        issuedAt: '2026-01-01T00:00:00Z',
      },
      nonce: '99999',
      requestTimestamp: '2026-02-08T12:00:00Z',
    };

    it('validates a well-formed ProofResponse', () => {
      const ajv = createValidator();
      const validate = ajv.compile(proofResponseSchema);
      const valid = validate(sampleProofResponse);
      if (!valid) {
        console.log('ProofResponse errors:', validate.errors);
      }
      expect(valid).to.equal(true);
    });

    it('rejects ProofResponse missing claimType', () => {
      const ajv = createValidator();
      const validate = ajv.compile(proofResponseSchema);
      const { claimType, ...rest } = sampleProofResponse;
      const valid = validate(rest);
      expect(valid).to.equal(false);
    });

    it('rejects ProofResponse missing proof', () => {
      const ajv = createValidator();
      const validate = ajv.compile(proofResponseSchema);
      const { proof, ...rest } = sampleProofResponse;
      const valid = validate(rest);
      expect(valid).to.equal(false);
    });
  });

  describe('SignedProofRequest schema', () => {
    const sampleSignedProofRequest = {
      claimType: 'age',
      issuer: 'test-issuer',
      nonce: '123456',
      requestTimestamp: '2026-02-08T12:00:00Z',
      proof: {
        proof: {
          pi_a: ['1', '2'],
          pi_b: [['3', '4']],
          pi_c: ['5', '6'],
          protocol: 'groth16',
          curve: 'bn128',
        },
        publicSignals: {
          currentYear: 2026,
          minAge: 18,
          credentialHash: 'hash',
          nonce: '123456',
          requestTimestamp: 1707350400000,
          issuerPublicKey: ['pk1', 'pk2'],
        },
      },
    };

    it('validates a well-formed SignedProofRequest', () => {
      const ajv = createValidator();
      const validate = ajv.compile(signedProofRequestSchema);
      const valid = validate(sampleSignedProofRequest);
      if (!valid) {
        console.log('SignedProofRequest errors:', validate.errors);
      }
      expect(valid).to.equal(true);
    });

    it('rejects SignedProofRequest with invalid claimType', () => {
      const ajv = createValidator();
      const validate = ajv.compile(signedProofRequestSchema);
      const valid = validate({ ...sampleSignedProofRequest, claimType: 'age-revocable' });
      expect(valid).to.equal(false);
    });

    it('rejects SignedProofRequest missing issuer', () => {
      const ajv = createValidator();
      const validate = ajv.compile(signedProofRequestSchema);
      const { issuer, ...rest } = sampleSignedProofRequest;
      const valid = validate(rest);
      expect(valid).to.equal(false);
    });
  });

  describe('VerificationResult schema', () => {
    it('validates a successful VerificationResult', () => {
      const ajv = createValidator();
      const validate = ajv.compile(verificationResultSchema);
      const valid = validate({
        verified: true,
        claimType: 'age',
        minAge: 18,
        protocolVersion: 'zk-id/1.0-draft',
      });
      expect(valid).to.equal(true);
    });

    it('validates a failed VerificationResult', () => {
      const ajv = createValidator();
      const validate = ajv.compile(verificationResultSchema);
      const valid = validate({
        verified: false,
        error: 'Proof verification failed',
      });
      expect(valid).to.equal(true);
    });

    it('rejects VerificationResult missing verified field', () => {
      const ajv = createValidator();
      const validate = ajv.compile(verificationResultSchema);
      const valid = validate({ claimType: 'age' });
      expect(valid).to.equal(false);
    });
  });

  describe('Shared definitions (defs.json)', () => {
    it('is valid JSON schema', () => {
      const ajv = createValidator();
      // Should not throw when adding the schema
      expect(() => ajv.getSchema('defs.json')).to.not.throw();
    });

    it('validates a Credential against the definition', () => {
      const ajv = createValidator();
      const validate = ajv.compile({ $ref: 'defs.json#/definitions/Credential' });
      const valid = validate({
        id: 'cred-001',
        birthYear: 2000,
        nationality: 840,
        salt: 'abc123',
        commitment: 'hash123',
        createdAt: '2026-01-01T00:00:00Z',
      });
      expect(valid).to.equal(true);
    });

    it('validates a RevocationRootInfo against the definition', () => {
      const ajv = createValidator();
      const validate = ajv.compile({ $ref: 'defs.json#/definitions/RevocationRootInfo' });
      const valid = validate({
        root: '123456',
        version: 1,
        updatedAt: '2026-02-08T12:00:00Z',
        expiresAt: '2026-02-08T12:05:00Z',
        ttlSeconds: 300,
        source: 'test-issuer',
      });
      expect(valid).to.equal(true);
    });

    it('rejects invalid RevocationRootInfo missing required fields', () => {
      const ajv = createValidator();
      const validate = ajv.compile({ $ref: 'defs.json#/definitions/RevocationRootInfo' });
      const valid = validate({ root: '123' });
      expect(valid).to.equal(false);
    });
  });
});
