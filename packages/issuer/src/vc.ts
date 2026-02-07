import { SignedCredential } from './issuer';

/**
 * W3C Verifiable Credential representation
 */
export interface VerifiableCredential {
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
 * Convert a SignedCredential to W3C Verifiable Credential format
 *
 * @param signedCredential - The signed credential to convert
 * @param subjectId - Optional DID or URI identifying the credential subject
 * @returns W3C Verifiable Credential
 */
export function toVerifiableCredential(
  signedCredential: SignedCredential,
  subjectId?: string
): VerifiableCredential {
  const vc: VerifiableCredential = {
    '@context': [
      'https://www.w3.org/2018/credentials/v1',
      'https://zk-id.example.org/credentials/v1',
    ],
    type: ['VerifiableCredential', 'ZkIdentityCredential'],
    issuer: signedCredential.issuer,
    issuanceDate: signedCredential.issuedAt,
    credentialSubject: {
      commitment: signedCredential.credential.commitment,
    },
  };

  // Add optional subject ID
  if (subjectId) {
    vc.credentialSubject.id = subjectId;
  }

  // Optionally include birthYear and nationality (can be omitted for privacy)
  if (signedCredential.credential.birthYear) {
    vc.credentialSubject.birthYear = signedCredential.credential.birthYear;
  }
  if (signedCredential.credential.nationality) {
    vc.credentialSubject.nationality = signedCredential.credential.nationality;
  }

  // Add proof section
  vc.proof = {
    type: 'Ed25519Signature2020',
    created: signedCredential.issuedAt,
    proofPurpose: 'assertionMethod',
    verificationMethod: `${signedCredential.issuer}#key-1`,
    signature: signedCredential.signature,
  };

  return vc;
}

/**
 * Convert a W3C Verifiable Credential back to SignedCredential format
 *
 * Note: The salt is not stored in the VC, so it must be provided separately
 *
 * @param vc - The W3C Verifiable Credential
 * @param credentialId - The credential ID
 * @param salt - The salt used in the commitment (not stored in VC)
 * @param createdAt - The original credential creation timestamp
 * @returns SignedCredential
 */
export function fromVerifiableCredential(
  vc: VerifiableCredential,
  credentialId: string,
  salt: string,
  createdAt: string
): SignedCredential {
  if (!vc.proof) {
    throw new Error('VC missing proof section');
  }

  return {
    credential: {
      id: credentialId,
      birthYear: vc.credentialSubject.birthYear || 0,
      nationality: vc.credentialSubject.nationality || 0,
      salt,
      commitment: vc.credentialSubject.commitment,
      createdAt,
    },
    issuer: vc.issuer,
    signature: vc.proof.signature,
    issuedAt: vc.issuanceDate,
  };
}
