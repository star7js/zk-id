import { expect } from 'chai';
import { CredentialIssuer } from '../src/issuer';
import {
  MDL_NAMESPACE,
  MDL_ELEMENTS,
  ISO_3166_NUMERIC_TO_ALPHA2,
  ISO_3166_ALPHA2_TO_NUMERIC,
  toMdlElements,
  createAgeOverAttestation,
  STANDARDS_MAPPINGS,
} from '../src/standards';

describe('ISO 18013-5/7 Standards Mapping', () => {
  let issuer: CredentialIssuer;

  beforeEach(() => {
    issuer = CredentialIssuer.createTestIssuer('Test Authority');
  });

  describe('MDL_NAMESPACE', () => {
    it('should follow ISO 18013-5 namespace format', () => {
      expect(MDL_NAMESPACE).to.equal('org.iso.18013.5.1');
    });
  });

  describe('MDL_ELEMENTS', () => {
    it('should define birth_date element', () => {
      expect(MDL_ELEMENTS.BIRTH_DATE).to.equal('org.iso.18013.5.1.birth_date');
    });

    it('should define nationality element', () => {
      expect(MDL_ELEMENTS.NATIONALITY).to.equal('org.iso.18013.5.1.nationality');
    });

    it('should define age_over prefix', () => {
      expect(MDL_ELEMENTS.AGE_OVER_PREFIX).to.equal('org.iso.18013.5.1.age_over_');
    });

    it('should define issuing_authority element', () => {
      expect(MDL_ELEMENTS.ISSUING_AUTHORITY).to.include('issuing_authority');
    });
  });

  describe('ISO 3166 country code mappings', () => {
    it('should map common numeric codes to alpha-2', () => {
      expect(ISO_3166_NUMERIC_TO_ALPHA2[840]).to.equal('US');
      expect(ISO_3166_NUMERIC_TO_ALPHA2[826]).to.equal('GB');
      expect(ISO_3166_NUMERIC_TO_ALPHA2[276]).to.equal('DE');
      expect(ISO_3166_NUMERIC_TO_ALPHA2[392]).to.equal('JP');
      expect(ISO_3166_NUMERIC_TO_ALPHA2[124]).to.equal('CA');
    });

    it('should provide reverse mapping from alpha-2 to numeric', () => {
      expect(ISO_3166_ALPHA2_TO_NUMERIC['US']).to.equal(840);
      expect(ISO_3166_ALPHA2_TO_NUMERIC['GB']).to.equal(826);
      expect(ISO_3166_ALPHA2_TO_NUMERIC['DE']).to.equal(276);
    });

    it('should have consistent bidirectional mappings', () => {
      for (const [num, alpha] of Object.entries(ISO_3166_NUMERIC_TO_ALPHA2)) {
        expect(ISO_3166_ALPHA2_TO_NUMERIC[alpha]).to.equal(Number(num));
      }
    });
  });

  describe('toMdlElements', () => {
    it('should map credential to mDL data elements', async () => {
      const signed = await issuer.issueCredential(1990, 840);
      const elements = toMdlElements(signed, 'US');

      expect(elements.length).to.be.greaterThanOrEqual(5);

      const birthDate = elements.find((e) => e.identifier === MDL_ELEMENTS.BIRTH_DATE);
      expect(birthDate).to.exist;
      expect(birthDate!.value).to.equal('1990-01-01');

      const nationality = elements.find((e) => e.identifier === MDL_ELEMENTS.NATIONALITY);
      expect(nationality).to.exist;
      expect(nationality!.value).to.equal('US');

      const authority = elements.find((e) => e.identifier === MDL_ELEMENTS.ISSUING_AUTHORITY);
      expect(authority).to.exist;
      expect(authority!.value).to.equal('Test Authority');
    });

    it('should include issuing country when provided', async () => {
      const signed = await issuer.issueCredential(1990, 826);
      const elements = toMdlElements(signed, 'GB');

      const country = elements.find((e) => e.identifier === MDL_ELEMENTS.ISSUING_COUNTRY);
      expect(country).to.exist;
      expect(country!.value).to.equal('GB');
    });

    it('should omit issuing country when not provided', async () => {
      const signed = await issuer.issueCredential(1990, 840);
      const elements = toMdlElements(signed);

      const country = elements.find((e) => e.identifier === MDL_ELEMENTS.ISSUING_COUNTRY);
      expect(country).to.not.exist;
    });

    it('should include document number from credential ID', async () => {
      const signed = await issuer.issueCredential(1985, 276);
      const elements = toMdlElements(signed);

      const docNum = elements.find((e) => e.identifier === MDL_ELEMENTS.DOCUMENT_NUMBER);
      expect(docNum).to.exist;
      expect(docNum!.value).to.equal(signed.credential.id);
    });
  });

  describe('createAgeOverAttestation', () => {
    it('should create age_over_18 attestation', () => {
      const attestation = createAgeOverAttestation(18);

      expect(attestation.ageThreshold).to.equal(18);
      expect(attestation.elementId).to.equal('org.iso.18013.5.1.age_over_18');
      expect(attestation.value).to.be.true;
    });

    it('should create age_over_21 attestation', () => {
      const attestation = createAgeOverAttestation(21);

      expect(attestation.ageThreshold).to.equal(21);
      expect(attestation.elementId).to.equal('org.iso.18013.5.1.age_over_21');
      expect(attestation.value).to.be.true;
    });

    it('should support arbitrary age thresholds', () => {
      const attestation = createAgeOverAttestation(65);

      expect(attestation.elementId).to.include('age_over_65');
    });
  });

  describe('STANDARDS_MAPPINGS', () => {
    it('should document all key zk-id concepts', () => {
      const concepts = STANDARDS_MAPPINGS.map((m) => m.zkIdConcept);

      expect(concepts).to.include('Age proof (minAge)');
      expect(concepts).to.include('Nationality proof');
      expect(concepts).to.include('Credential commitment');
      expect(concepts).to.include('Issuer registry');
    });

    it('should reference ISO 18013-5 or 18013-7', () => {
      for (const mapping of STANDARDS_MAPPINGS) {
        expect(mapping.standard).to.match(/ISO 18013-[57]/);
      }
    });

    it('should have valid fidelity values', () => {
      for (const mapping of STANDARDS_MAPPINGS) {
        expect(['exact', 'partial', 'conceptual']).to.include(mapping.fidelity);
      }
    });

    it('should have non-empty notes for each mapping', () => {
      for (const mapping of STANDARDS_MAPPINGS) {
        expect(mapping.notes).to.be.a('string').with.length.greaterThan(0);
      }
    });
  });
});
