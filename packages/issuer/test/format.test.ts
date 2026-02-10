import { expect } from 'chai';
import { CredentialIssuer } from '../src/issuer';
import { toExternalCredentialFormat, fromExternalCredentialFormat } from '../src/format';

describe('External Credential Format Tests', () => {
  let issuer: CredentialIssuer;

  beforeEach(() => {
    issuer = CredentialIssuer.createTestIssuer('Test Government ID Authority');
  });

  describe('toExternalCredentialFormat', () => {
    it('should convert SignedCredential to external format', async () => {
      const signed = await issuer.issueCredential(1990, 840);
      const vc = toExternalCredentialFormat(signed);

      expect(vc).to.have.property('@context');
      expect(vc['@context']).to.be.an('array');
      expect(vc['@context']).to.include('https://zk-id.example.org/credentials/v1');

      expect(vc).to.have.property('type');
      expect(vc.type).to.include('ExternalCredential');
      expect(vc.type).to.include('ZkIdentityCredential');

      expect(vc).to.have.property('issuer', signed.issuer);
      expect(vc).to.have.property('issuanceDate', signed.issuedAt);

      expect(vc.credentialSubject).to.have.property('commitment', signed.credential.commitment);
    });

    it('should include birthYear and nationality when present', async () => {
      const signed = await issuer.issueCredential(1990, 840);
      const vc = toExternalCredentialFormat(signed);

      expect(vc.credentialSubject.birthYear).to.equal(1990);
      expect(vc.credentialSubject.nationality).to.equal(840);
    });

    it('should include optional subject ID', async () => {
      const signed = await issuer.issueCredential(1990, 840);
      const subjectId = 'did:example:123456789abcdefgh';
      const vc = toExternalCredentialFormat(signed, subjectId);

      expect(vc.credentialSubject.id).to.equal(subjectId);
    });

    it('should include proof section with Ed25519 signature', async () => {
      const signed = await issuer.issueCredential(1990, 840);
      const vc = toExternalCredentialFormat(signed);

      expect(vc.proof).to.exist;
      expect(vc.proof!.type).to.equal('Ed25519Signature');
      expect(vc.proof!.signature).to.equal(signed.signature);
      expect(vc.proof!.created).to.equal(signed.issuedAt);
      expect(vc.proof!.proofPurpose).to.equal('assertion');
    });
  });

  describe('fromExternalCredentialFormat', () => {
    it('should convert external format back to SignedCredential', async () => {
      const signed = await issuer.issueCredential(1990, 840);
      const vc = toExternalCredentialFormat(signed);

      const converted = fromExternalCredentialFormat(
        vc,
        signed.credential.id,
        signed.credential.salt,
        signed.credential.createdAt,
      );

      expect(converted.credential.id).to.equal(signed.credential.id);
      expect(converted.credential.commitment).to.equal(signed.credential.commitment);
      expect(converted.credential.birthYear).to.equal(signed.credential.birthYear);
      expect(converted.credential.nationality).to.equal(signed.credential.nationality);
      expect(converted.issuer).to.equal(signed.issuer);
      expect(converted.signature).to.equal(signed.signature);
    });

    it('should throw error if external format missing proof section', async () => {
      const signed = await issuer.issueCredential(1990, 840);
      const vc = toExternalCredentialFormat(signed);
      delete vc.proof;

      try {
        fromExternalCredentialFormat(
          vc,
          signed.credential.id,
          signed.credential.salt,
          signed.credential.createdAt,
        );
        expect.fail('Should have thrown an error');
      } catch (error) {
        expect(error).to.be.instanceOf(Error);
        expect((error as Error).message).to.include('missing proof');
      }
    });
  });

  describe('Round-trip conversion', () => {
    it('should preserve signature through round-trip conversion', async () => {
      const signed = await issuer.issueCredential(1990, 840);
      const publicKey = (issuer as any).config.publicKey;

      // Convert to external format and back
      const vc = toExternalCredentialFormat(signed);
      const converted = fromExternalCredentialFormat(
        vc,
        signed.credential.id,
        signed.credential.salt,
        signed.credential.createdAt,
      );

      // Verify signature still works
      const isValid = CredentialIssuer.verifySignature(converted, publicKey);
      expect(isValid).to.be.true;
    });

    it('should handle credentials without subject ID', async () => {
      const signed = await issuer.issueCredential(1990, 840);
      const vc = toExternalCredentialFormat(signed); // No subject ID

      const converted = fromExternalCredentialFormat(
        vc,
        signed.credential.id,
        signed.credential.salt,
        signed.credential.createdAt,
      );

      expect(converted.credential.commitment).to.equal(signed.credential.commitment);
    });

    it('should preserve all credential fields', async () => {
      const birthYear = 1985;
      const nationality = 826;
      const signed = await issuer.issueCredential(birthYear, nationality);

      const vc = toExternalCredentialFormat(signed, 'did:example:alice');
      const converted = fromExternalCredentialFormat(
        vc,
        signed.credential.id,
        signed.credential.salt,
        signed.credential.createdAt,
      );

      expect(converted.credential.birthYear).to.equal(birthYear);
      expect(converted.credential.nationality).to.equal(nationality);
      expect(converted.credential.salt).to.equal(signed.credential.salt);
      expect(converted.credential.id).to.equal(signed.credential.id);
    });
  });
});
