/**
 * ISO 18013-5 / 18013-7 standards mapping for zk-id credentials.
 *
 * ISO 18013-5 defines the mDL (mobile Driving License) data model.
 * ISO 18013-7 extends it for online presentation and age verification.
 *
 * This module provides:
 * - Namespace and element identifiers aligned with ISO 18013-5
 * - Mapping helpers between zk-id attributes and mDL data elements
 * - Age-over attestation helpers per ISO 18013-7 online flow
 */

import { SignedCredential } from '@zk-id/core';

// ---------------------------------------------------------------------------
// ISO 18013-5 Namespace & Element Constants
// ---------------------------------------------------------------------------

/**
 * ISO 18013-5 namespace for the core mDL data model.
 */
export const MDL_NAMESPACE = 'org.iso.18013.5.1';

/**
 * ISO 18013-5 data element identifiers relevant to zk-id.
 *
 * Full spec defines ~30 elements; we map the ones relevant to
 * age and nationality verification.
 */
export const MDL_ELEMENTS = {
  /** Date of birth (full date in the spec; we use birth year only) */
  BIRTH_DATE: `${MDL_NAMESPACE}.birth_date`,
  /** Nationality (ISO 3166-1 alpha-2 in the spec; we use numeric) */
  NATIONALITY: `${MDL_NAMESPACE}.nationality`,
  /** Age attestation — subject is at least N years old */
  AGE_OVER_PREFIX: `${MDL_NAMESPACE}.age_over_`,
  /** Issuing authority */
  ISSUING_AUTHORITY: `${MDL_NAMESPACE}.issuing_authority`,
  /** Document number (mapped to credential ID) */
  DOCUMENT_NUMBER: `${MDL_NAMESPACE}.document_number`,
  /** Issuance date */
  ISSUE_DATE: `${MDL_NAMESPACE}.issue_date`,
  /** Issuing country (ISO 3166-1 alpha-2) */
  ISSUING_COUNTRY: `${MDL_NAMESPACE}.issuing_country`,
} as const;

/**
 * Common ISO 3166-1 numeric-to-alpha-2 country code mappings.
 *
 * ISO 18013-5 uses alpha-2 codes; zk-id uses numeric codes.
 * This table covers the most common codes. Extend as needed.
 */
export const ISO_3166_NUMERIC_TO_ALPHA2: Record<number, string> = {
  4: 'AF',
  8: 'AL',
  12: 'DZ',
  20: 'AD',
  24: 'AO',
  32: 'AR',
  36: 'AU',
  40: 'AT',
  48: 'BH',
  50: 'BD',
  56: 'BE',
  76: 'BR',
  100: 'BG',
  124: 'CA',
  156: 'CN',
  170: 'CO',
  203: 'CZ',
  208: 'DK',
  218: 'EC',
  818: 'EG',
  233: 'EE',
  246: 'FI',
  250: 'FR',
  276: 'DE',
  300: 'GR',
  344: 'HK',
  348: 'HU',
  352: 'IS',
  356: 'IN',
  360: 'ID',
  364: 'IR',
  368: 'IQ',
  372: 'IE',
  376: 'IL',
  380: 'IT',
  392: 'JP',
  400: 'JO',
  410: 'KR',
  414: 'KW',
  428: 'LV',
  440: 'LT',
  442: 'LU',
  458: 'MY',
  484: 'MX',
  528: 'NL',
  554: 'NZ',
  578: 'NO',
  586: 'PK',
  604: 'PE',
  608: 'PH',
  616: 'PL',
  620: 'PT',
  634: 'QA',
  642: 'RO',
  643: 'RU',
  682: 'SA',
  702: 'SG',
  703: 'SK',
  705: 'SI',
  710: 'ZA',
  724: 'ES',
  752: 'SE',
  756: 'CH',
  764: 'TH',
  792: 'TR',
  784: 'AE',
  826: 'GB',
  840: 'US',
  804: 'UA',
  704: 'VN',
};

/**
 * Reverse mapping: alpha-2 to numeric.
 */
export const ISO_3166_ALPHA2_TO_NUMERIC: Record<string, number> = {};
for (const [num, alpha] of Object.entries(ISO_3166_NUMERIC_TO_ALPHA2)) {
  ISO_3166_ALPHA2_TO_NUMERIC[alpha] = Number(num);
}

// ---------------------------------------------------------------------------
// mDL Data Element Mapping
// ---------------------------------------------------------------------------

/**
 * An mDL data element as defined by ISO 18013-5.
 */
export interface MdlDataElement {
  /** Element identifier (e.g., "org.iso.18013.5.1.birth_date") */
  identifier: string;
  /** Value of the element */
  value: string | number | boolean;
}

/**
 * An mDL-aligned age attestation claim.
 *
 * ISO 18013-7 defines age_over_NN boolean claims that attest the
 * holder is at least NN years old, without revealing the birth date.
 * This maps directly to zk-id's age proof with minAge.
 */
export interface AgeOverAttestation {
  /** The age threshold (e.g., 18, 21) */
  ageThreshold: number;
  /** The mDL element identifier (e.g., "org.iso.18013.5.1.age_over_18") */
  elementId: string;
  /** Attestation result (always true if proof verifies) */
  value: boolean;
}

/**
 * Map a zk-id credential to mDL-aligned data elements.
 *
 * Note: zk-id credentials use Poseidon commitments and ZK proofs,
 * so not all mDL elements are directly populated. This mapping
 * provides the structural alignment for interop documentation.
 *
 * @param credential - Signed credential to map
 * @param issuerCountryAlpha2 - Issuer's country code (alpha-2)
 * @returns Array of mDL data elements
 */
export function toMdlElements(
  credential: SignedCredential,
  issuerCountryAlpha2?: string,
): MdlDataElement[] {
  const elements: MdlDataElement[] = [];

  // Birth date — we only have birth year, so represent as YYYY-01-01
  elements.push({
    identifier: MDL_ELEMENTS.BIRTH_DATE,
    value: `${credential.credential.birthYear}-01-01`,
  });

  // Nationality
  const alpha2 = ISO_3166_NUMERIC_TO_ALPHA2[credential.credential.nationality];
  if (alpha2) {
    elements.push({
      identifier: MDL_ELEMENTS.NATIONALITY,
      value: alpha2,
    });
  }

  // Issuing authority
  elements.push({
    identifier: MDL_ELEMENTS.ISSUING_AUTHORITY,
    value: credential.issuer,
  });

  // Document number → credential ID
  elements.push({
    identifier: MDL_ELEMENTS.DOCUMENT_NUMBER,
    value: credential.credential.id,
  });

  // Issue date
  elements.push({
    identifier: MDL_ELEMENTS.ISSUE_DATE,
    value: credential.issuedAt,
  });

  // Issuing country
  if (issuerCountryAlpha2) {
    elements.push({
      identifier: MDL_ELEMENTS.ISSUING_COUNTRY,
      value: issuerCountryAlpha2,
    });
  }

  return elements;
}

/**
 * Create an mDL-aligned age-over attestation from a verified age proof.
 *
 * This represents the output of a successful zk-id age verification
 * in ISO 18013-7 terms. The verifier can present this attestation
 * to downstream systems expecting mDL-format responses.
 *
 * @param minAge - The minimum age that was proven (e.g., 18)
 * @returns Age-over attestation
 */
export function createAgeOverAttestation(minAge: number): AgeOverAttestation {
  return {
    ageThreshold: minAge,
    elementId: `${MDL_ELEMENTS.AGE_OVER_PREFIX}${minAge}`,
    value: true,
  };
}

// ---------------------------------------------------------------------------
// Standards Compliance Info
// ---------------------------------------------------------------------------

/**
 * Describes the mapping between a zk-id concept and a standards concept.
 */
export interface StandardsMapping {
  /** zk-id concept name */
  zkIdConcept: string;
  /** ISO standard identifier */
  standard: string;
  /** Standard concept/element */
  standardConcept: string;
  /** Mapping fidelity */
  fidelity: 'exact' | 'partial' | 'conceptual';
  /** Notes on mapping differences */
  notes: string;
}

/**
 * Known mappings between zk-id and ISO 18013-5/7.
 *
 * This table documents the alignment for audit and interoperability review.
 */
export const STANDARDS_MAPPINGS: StandardsMapping[] = [
  {
    zkIdConcept: 'Age proof (minAge)',
    standard: 'ISO 18013-7',
    standardConcept: 'age_over_NN attestation',
    fidelity: 'exact',
    notes: 'Both prove age >= threshold without revealing birth date',
  },
  {
    zkIdConcept: 'Nationality proof',
    standard: 'ISO 18013-5',
    standardConcept: 'nationality data element',
    fidelity: 'partial',
    notes: 'zk-id uses ISO 3166-1 numeric; mDL uses alpha-2. Conversion provided.',
  },
  {
    zkIdConcept: 'Credential commitment',
    standard: 'ISO 18013-5',
    standardConcept: 'IssuerAuth (COSE_Sign1)',
    fidelity: 'conceptual',
    notes: 'zk-id uses Poseidon commitment + Ed25519; mDL uses MSO + COSE signing',
  },
  {
    zkIdConcept: 'Ed25519 credential signature',
    standard: 'ISO 18013-5',
    standardConcept: 'IssuerAuth signature',
    fidelity: 'partial',
    notes:
      'Both sign credential data; different signature algorithms (Ed25519 vs ECDSA/EdDSA over COSE)',
  },
  {
    zkIdConcept: 'Issuer registry',
    standard: 'ISO 18013-5',
    standardConcept: 'VICAL (Verified Issuer Certificate Authority List)',
    fidelity: 'conceptual',
    notes: 'zk-id uses a trust registry; mDL uses X.509 certificate chains via VICAL',
  },
  {
    zkIdConcept: 'Valid credential tree (Merkle)',
    standard: 'ISO 18013-5',
    standardConcept: 'Status list / revocation',
    fidelity: 'conceptual',
    notes: 'zk-id uses ZK-friendly Merkle inclusion; mDL defines status lists in future extensions',
  },
  {
    zkIdConcept: 'ZK proof (Groth16)',
    standard: 'ISO 18013-7',
    standardConcept: 'Online presentation',
    fidelity: 'conceptual',
    notes:
      'ISO 18013-7 defines online age verification flow; zk-id adds zero-knowledge privacy guarantees',
  },
  {
    zkIdConcept: 'Protocol version (zk-id/1.0-draft)',
    standard: 'ISO 18013-7',
    standardConcept: 'Protocol versioning',
    fidelity: 'conceptual',
    notes: 'Both version their protocols; different namespacing schemes',
  },
];
