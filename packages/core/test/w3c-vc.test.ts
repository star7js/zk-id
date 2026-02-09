import { expect } from 'chai';
import {
  toW3CVerifiableCredential,
  fromW3CVerifiableCredential,
  ed25519PublicKeyToDIDKey,
  didKeyToEd25519PublicKey,
  W3CVerifiableCredential,
} from '../src/w3c-vc';
import { SignedCredential, Credential } from '../src/types';

describe('W3C Verifiable Credentials', () => {
  const mockCredential: Credential = {
    id: '123e4567-e89b-12d3-a456-426614174000',
    birthYear: 1990,
    nationality: 840, // USA
    salt: 'test-salt-value',
    commitment: '12345678901234567890',
    createdAt: '2026-02-09T00:00:00.000Z',
  };

  const mockSignedCredential: SignedCredential = {
    credential: mockCredential,
    issuer: 'test-issuer',
    signature: 'base64-encoded-signature',
    issuedAt: '2026-02-09T01:00:00.000Z',
  };

  describe('toW3CVerifiableCredential', () => {
    it('should convert SignedCredential to W3C VC format', () => {
      const vc = toW3CVerifiableCredential(mockSignedCredential);

      expect(vc['@context']).to.be.an('array');
      expect(vc['@context']).to.include('https://www.w3.org/ns/credentials/v2');
      expect(vc['@context']).to.include('https://w3id.org/zk-id/credentials/v1');

      expect(vc.type).to.be.an('array');
      expect(vc.type).to.include('VerifiableCredential');
      expect(vc.type).to.include('ZkIdCredential');

      expect(vc.id).to.equal('urn:uuid:123e4567-e89b-12d3-a456-426614174000');
      expect(vc.issuer).to.equal('test-issuer');
      expect(vc.issuanceDate).to.equal('2026-02-09T01:00:00.000Z');

      expect(vc.credentialSubject).to.deep.include({
        zkCredential: {
          commitment: '12345678901234567890',
          createdAt: '2026-02-09T00:00:00.000Z',
        },
      });

      expect(vc.proof).to.deep.include({
        type: 'Ed25519Signature2020',
        proofPurpose: 'assertionMethod',
        proofValue: 'base64-encoded-signature',
      });
    });

    it('should accept issuer DID', () => {
      const vc = toW3CVerifiableCredential(mockSignedCredential, {
        issuerDID: 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK',
      });

      expect(vc.issuer).to.equal(
        'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK'
      );
    });

    it('should accept subject DID', () => {
      const vc = toW3CVerifiableCredential(mockSignedCredential, {
        subjectDID: 'did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH',
      });

      expect(vc.credentialSubject.id).to.equal(
        'did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH'
      );
    });

    it('should accept expiration date', () => {
      const vc = toW3CVerifiableCredential(mockSignedCredential, {
        expirationDate: '2027-02-09T00:00:00.000Z',
      });

      expect(vc.expirationDate).to.equal('2027-02-09T00:00:00.000Z');
    });

    it('should accept additional contexts', () => {
      const vc = toW3CVerifiableCredential(mockSignedCredential, {
        additionalContexts: ['https://example.com/custom-context'],
      });

      expect(vc['@context']).to.include('https://example.com/custom-context');
    });

    it('should accept custom verification method', () => {
      const vc = toW3CVerifiableCredential(mockSignedCredential, {
        verificationMethod: 'did:key:z6Mk...#key-2',
      });

      expect(vc.proof?.verificationMethod).to.equal('did:key:z6Mk...#key-2');
    });
  });

  describe('fromW3CVerifiableCredential', () => {
    it('should convert W3C VC back to SignedCredential', () => {
      const vc = toW3CVerifiableCredential(mockSignedCredential);
      const signedCred = fromW3CVerifiableCredential(vc);

      expect(signedCred.credential.id).to.equal(mockCredential.id);
      expect(signedCred.credential.commitment).to.equal(mockCredential.commitment);
      expect(signedCred.credential.createdAt).to.equal(mockCredential.createdAt);
      expect(signedCred.issuer).to.equal('test-issuer');
      expect(signedCred.signature).to.equal('base64-encoded-signature');
      expect(signedCred.issuedAt).to.equal('2026-02-09T01:00:00.000Z');
    });

    it('should throw error for non-ZkIdCredential', () => {
      const nonZkVC: W3CVerifiableCredential = {
        '@context': ['https://www.w3.org/ns/credentials/v2'],
        type: ['VerifiableCredential'], // Missing ZkIdCredential type
        id: 'urn:uuid:test',
        issuer: 'test-issuer',
        issuanceDate: '2026-02-09T00:00:00.000Z',
        credentialSubject: {
          zkCredential: {
            commitment: 'test',
            createdAt: '2026-02-09T00:00:00.000Z',
          },
        },
        proof: {
          type: 'Ed25519Signature2020',
          created: '2026-02-09T00:00:00.000Z',
          verificationMethod: 'test#key-1',
          proofPurpose: 'assertionMethod',
          proofValue: 'test-sig',
        },
      };

      expect(() => fromW3CVerifiableCredential(nonZkVC)).to.throw('Not a ZkIdCredential');
    });

    it('should throw error for missing zkCredential', () => {
      const invalidVC = {
        '@context': ['https://www.w3.org/ns/credentials/v2'],
        type: ['VerifiableCredential', 'ZkIdCredential'],
        id: 'urn:uuid:test',
        issuer: 'test-issuer',
        issuanceDate: '2026-02-09T00:00:00.000Z',
        credentialSubject: {}, // Missing zkCredential
      } as unknown as W3CVerifiableCredential;

      expect(() => fromW3CVerifiableCredential(invalidVC)).to.throw(
        'Missing zkCredential in credentialSubject'
      );
    });

    it('should throw error for missing proof', () => {
      const invalidVC = {
        '@context': ['https://www.w3.org/ns/credentials/v2'],
        type: ['VerifiableCredential', 'ZkIdCredential'],
        id: 'urn:uuid:test',
        issuer: 'test-issuer',
        issuanceDate: '2026-02-09T00:00:00.000Z',
        credentialSubject: {
          zkCredential: {
            commitment: 'test',
            createdAt: '2026-02-09T00:00:00.000Z',
          },
        },
        // Missing proof
      } as unknown as W3CVerifiableCredential;

      expect(() => fromW3CVerifiableCredential(invalidVC)).to.throw(
        'Missing proof or proofValue'
      );
    });
  });

  describe('DID key helpers', () => {
    it('should convert Ed25519 public key to did:key', () => {
      // Mock 32-byte Ed25519 public key
      const publicKey = new Uint8Array(32);
      for (let i = 0; i < 32; i++) {
        publicKey[i] = i;
      }

      const didKey = ed25519PublicKeyToDIDKey(publicKey);

      expect(didKey).to.be.a('string');
      expect(didKey).to.match(/^did:key:z[1-9A-HJ-NP-Za-km-z]+$/);
    });

    it('should round-trip Ed25519 public key through did:key', () => {
      const originalKey = new Uint8Array(32);
      for (let i = 0; i < 32; i++) {
        originalKey[i] = i * 2;
      }

      const didKey = ed25519PublicKeyToDIDKey(originalKey);
      const recoveredKey = didKeyToEd25519PublicKey(didKey);

      expect(recoveredKey).to.deep.equal(originalKey);
    });

    it('should throw error for invalid public key length', () => {
      const invalidKey = new Uint8Array(16); // Wrong length

      expect(() => ed25519PublicKeyToDIDKey(invalidKey)).to.throw(
        'Ed25519 public key must be 32 bytes'
      );
    });

    it('should throw error for invalid did:key format', () => {
      expect(() => didKeyToEd25519PublicKey('not-a-did')).to.throw(
        'Invalid did:key format'
      );
      expect(() => didKeyToEd25519PublicKey('did:web:example.com')).to.throw(
        'Invalid did:key format'
      );
    });
  });

  describe('W3C VC interoperability', () => {
    it('should produce credential that passes basic W3C VC validation', () => {
      const vc = toW3CVerifiableCredential(mockSignedCredential, {
        issuerDID: 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK',
        subjectDID: 'did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH',
      });

      // Required W3C VC fields
      expect(vc).to.have.property('@context');
      expect(vc).to.have.property('type');
      expect(vc).to.have.property('id');
      expect(vc).to.have.property('issuer');
      expect(vc).to.have.property('issuanceDate');
      expect(vc).to.have.property('credentialSubject');

      // W3C VC v2.0 requirements
      expect(vc['@context']).to.be.an('array');
      expect(vc['@context'][0]).to.equal('https://www.w3.org/ns/credentials/v2');
      expect(vc.type).to.be.an('array');
      expect(vc.type[0]).to.equal('VerifiableCredential');

      // Proof requirements
      expect(vc.proof).to.be.an('object');
      expect(vc.proof).to.have.property('type');
      expect(vc.proof).to.have.property('created');
      expect(vc.proof).to.have.property('verificationMethod');
      expect(vc.proof).to.have.property('proofPurpose');
    });
  });
});
