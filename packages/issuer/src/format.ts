import { SignedCredential, ZkIdValidationError } from '@zk-id/core';

/**
 * External credential format representation
 */
export interface ExternalCredential {
  '@context': string[];
  type: string[];
  issuer: string;
  issuanceDate: string;
  credentialSubject: {
    id?: string;
    commitment: string;
    birthYear?: number;
    nationality?: number;
  };
  proof?: {
    type: string;
    created: string;
    proofPurpose: string;
    verificationMethod: string;
    signature: string;
  };
}

/**
 * Convert a SignedCredential to an external credential format
 *
 * @param signedCredential - The signed credential to convert
 * @param subjectId - Optional subject identifier
 * @returns External credential format
 */
export function toExternalCredentialFormat(
  signedCredential: SignedCredential,
  subjectId?: string,
): ExternalCredential {
  const external: ExternalCredential = {
    '@context': [
      'https://zk-id.example.org/credentials/v1',
      'https://zk-id.example.org/credentials/external/v1',
    ],
    type: ['ExternalCredential', 'ZkIdentityCredential'],
    issuer: signedCredential.issuer,
    issuanceDate: signedCredential.issuedAt,
    credentialSubject: {
      commitment: signedCredential.credential.commitment,
    },
  };

  // Add optional subject ID
  if (subjectId) {
    external.credentialSubject.id = subjectId;
  }

  // Optionally include birthYear and nationality (can be omitted for privacy)
  if (signedCredential.credential.birthYear != null) {
    external.credentialSubject.birthYear = signedCredential.credential.birthYear;
  }
  if (signedCredential.credential.nationality != null) {
    external.credentialSubject.nationality = signedCredential.credential.nationality;
  }

  // Add proof section
  external.proof = {
    type: 'Ed25519Signature',
    created: signedCredential.issuedAt,
    proofPurpose: 'assertion',
    verificationMethod: `${signedCredential.issuer}#signing-key`,
    signature: signedCredential.signature,
  };

  return external;
}

/**
 * Convert an external credential format back to SignedCredential
 *
 * Note: The salt is not stored in the external format, so it must be provided separately
 *
 * @param external - The external credential format
 * @param credentialId - The credential ID
 * @param salt - The salt used in the commitment (not stored in external format)
 * @param createdAt - The original credential creation timestamp
 * @returns SignedCredential
 */
export function fromExternalCredentialFormat(
  external: ExternalCredential,
  credentialId: string,
  salt: string,
  createdAt: string,
): SignedCredential {
  if (!external.proof) {
    throw new ZkIdValidationError('External credential missing proof section', 'proof');
  }

  return {
    credential: {
      id: credentialId,
      birthYear: external.credentialSubject.birthYear ?? 0,
      nationality: external.credentialSubject.nationality ?? 0,
      salt,
      commitment: external.credentialSubject.commitment,
      createdAt,
    },
    issuer: external.issuer,
    signature: external.proof.signature,
    issuedAt: external.issuanceDate,
  };
}
