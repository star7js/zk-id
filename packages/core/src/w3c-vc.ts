/**
 * W3C Verifiable Credentials Data Model v2.0 support for zk-id
 *
 * This module provides W3C VC-compliant credential formats while maintaining
 * backward compatibility with the existing zk-id credential format.
 *
 * References:
 * - W3C VC Data Model v2.0: https://www.w3.org/TR/vc-data-model-2.0/
 * - W3C DID Core: https://www.w3.org/TR/did-core/
 */

import { Credential, SignedCredential } from './types.js';

/**
 * W3C VC-compliant credential format
 *
 * This format wraps the zk-id credential in a W3C Verifiable Credential envelope,
 * enabling interoperability with W3C VC ecosystems while preserving the ZK properties.
 */
export interface W3CVerifiableCredential {
  /** W3C VC context (required) */
  '@context': string[];

  /** W3C VC type (required) */
  type: string[];

  /** Credential identifier (URI) */
  id: string;

  /** Issuer identifier (DID or URL) */
  issuer: string | { id: string; [key: string]: unknown };

  /** Issuance date (ISO 8601) */
  issuanceDate: string;

  /** Expiration date (optional, ISO 8601) */
  expirationDate?: string;

  /** Credential subject */
  credentialSubject: {
    /** Subject identifier (optional DID) */
    id?: string;

    /** zk-id credential commitment */
    zkCredential: {
      /** Poseidon hash commitment binding (birthYear, nationality, salt) */
      commitment: string;

      /** ISO 8601 timestamp of credential creation */
      createdAt: string;
    };
  };

  /** W3C proof (signature) */
  proof?: {
    /** Proof type */
    type: string;

    /** ISO 8601 timestamp */
    created: string;

    /** Verification method (DID URL or key ID) */
    verificationMethod: string;

    /** Purpose of the proof */
    proofPurpose: string;

    /** Signature value (base64 or multibase encoded) */
    proofValue?: string;

    /** JWS signature (for JWT VCs) */
    jws?: string;
  };

  /** Additional properties */
  [key: string]: unknown;
}

/**
 * Convert a zk-id SignedCredential to W3C VC format
 *
 * @param signedCredential - The zk-id signed credential
 * @param options - Conversion options
 * @returns W3C Verifiable Credential
 */
export function toW3CVerifiableCredential(
  signedCredential: SignedCredential,
  options?: {
    /** Issuer DID (defaults to did:key derived from public key if not provided) */
    issuerDID?: string;

    /** Subject DID (optional) */
    subjectDID?: string;

    /** Expiration date (optional) */
    expirationDate?: string;

    /** Additional context URLs */
    additionalContexts?: string[];

    /** Verification method (DID URL or key ID) */
    verificationMethod?: string;
  }
): W3CVerifiableCredential {
  const { credential, issuer, signature, issuedAt } = signedCredential;

  // Default to using the issuer name as a simple identifier
  // In production, this should be a DID (did:key, did:web, etc.)
  const issuerIdentifier = options?.issuerDID || issuer;

  return {
    '@context': [
      'https://www.w3.org/ns/credentials/v2',
      'https://w3id.org/zk-id/credentials/v1', // zk-id-specific context (placeholder)
      ...(options?.additionalContexts || []),
    ],
    type: ['VerifiableCredential', 'ZkIdCredential'],
    id: `urn:uuid:${credential.id}`,
    issuer: issuerIdentifier,
    issuanceDate: issuedAt,
    expirationDate: options?.expirationDate,
    credentialSubject: {
      id: options?.subjectDID,
      zkCredential: {
        commitment: credential.commitment,
        createdAt: credential.createdAt,
      },
    },
    proof: {
      type: 'Ed25519Signature2020', // Standard W3C proof type for Ed25519
      created: issuedAt,
      verificationMethod:
        options?.verificationMethod ||
        `${issuerIdentifier}#key-1`, // Default key reference
      proofPurpose: 'assertionMethod',
      proofValue: signature,
    },
  };
}

/**
 * Convert a W3C VC back to zk-id SignedCredential format
 *
 * @param vc - W3C Verifiable Credential
 * @returns zk-id SignedCredential
 * @throws Error if the VC is not a valid ZkIdCredential
 */
export function fromW3CVerifiableCredential(
  vc: W3CVerifiableCredential
): SignedCredential {
  // Validate that this is a ZkIdCredential
  if (!vc.type.includes('ZkIdCredential')) {
    throw new Error('Not a ZkIdCredential');
  }

  if (!vc.credentialSubject.zkCredential) {
    throw new Error('Missing zkCredential in credentialSubject');
  }

  if (!vc.proof || !vc.proof.proofValue) {
    throw new Error('Missing proof or proofValue');
  }

  // Extract credential ID from URN
  const credentialId = vc.id.startsWith('urn:uuid:')
    ? vc.id.substring(9)
    : vc.id;

  // Extract issuer identifier
  const issuer = typeof vc.issuer === 'string' ? vc.issuer : vc.issuer.id;

  // Note: We can't recover birthYear, nationality, or salt from the commitment
  // This function is primarily for signature verification, not credential reconstruction
  const credential: Credential = {
    id: credentialId,
    birthYear: 0, // Unknown from commitment alone
    nationality: 0, // Unknown from commitment alone
    salt: '', // Unknown from commitment alone
    commitment: vc.credentialSubject.zkCredential.commitment,
    createdAt: vc.credentialSubject.zkCredential.createdAt,
  };

  return {
    credential,
    issuer,
    signature: vc.proof.proofValue,
    issuedAt: vc.issuanceDate,
  };
}

/**
 * DID Helper: Generate a did:key identifier from an Ed25519 public key
 *
 * This is a minimal implementation of did:key for Ed25519 keys following
 * the W3C DID specification.
 *
 * @param publicKeyBytes - Ed25519 public key (32 bytes)
 * @returns did:key identifier
 */
export function ed25519PublicKeyToDIDKey(publicKeyBytes: Uint8Array): string {
  if (publicKeyBytes.length !== 32) {
    throw new Error('Ed25519 public key must be 32 bytes');
  }

  // Multicodec prefix for Ed25519 public key: 0xed 0x01
  const multicodecPrefix = new Uint8Array([0xed, 0x01]);

  // Concatenate prefix + public key
  const combined = new Uint8Array(multicodecPrefix.length + publicKeyBytes.length);
  combined.set(multicodecPrefix, 0);
  combined.set(publicKeyBytes, multicodecPrefix.length);

  // Base58 encode (multibase with 'z' prefix)
  const base58Encoded = base58Encode(combined);

  return `did:key:z${base58Encoded}`;
}

/**
 * DID Helper: Extract Ed25519 public key from a did:key identifier
 *
 * @param didKey - did:key identifier
 * @returns Ed25519 public key bytes
 */
export function didKeyToEd25519PublicKey(didKey: string): Uint8Array {
  if (!didKey.startsWith('did:key:z')) {
    throw new Error('Invalid did:key format');
  }

  // Remove 'did:key:z' prefix and decode base58
  const base58Part = didKey.substring(9);
  const decoded = base58Decode(base58Part);

  // Verify multicodec prefix (0xed 0x01 for Ed25519)
  if (decoded[0] !== 0xed || decoded[1] !== 0x01) {
    throw new Error('Not an Ed25519 did:key');
  }

  // Return the public key bytes (skip 2-byte prefix)
  return decoded.slice(2);
}

// ---------------------------------------------------------------------------
// Base58 encoding/decoding (Bitcoin alphabet)
// ---------------------------------------------------------------------------

const BASE58_ALPHABET =
  '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

function base58Encode(bytes: Uint8Array): string {
  let num = 0n;
  for (const byte of bytes) {
    num = num * 256n + BigInt(byte);
  }

  let encoded = '';
  while (num > 0n) {
    const remainder = Number(num % 58n);
    encoded = BASE58_ALPHABET[remainder] + encoded;
    num = num / 58n;
  }

  // Handle leading zeros
  for (const byte of bytes) {
    if (byte === 0) {
      encoded = '1' + encoded;
    } else {
      break;
    }
  }

  return encoded;
}

function base58Decode(str: string): Uint8Array {
  let num = 0n;
  for (const char of str) {
    const digit = BASE58_ALPHABET.indexOf(char);
    if (digit === -1) {
      throw new Error(`Invalid base58 character: ${char}`);
    }
    num = num * 58n + BigInt(digit);
  }

  const bytes: number[] = [];
  while (num > 0n) {
    bytes.unshift(Number(num % 256n));
    num = num / 256n;
  }

  // Handle leading '1's
  for (const char of str) {
    if (char === '1') {
      bytes.unshift(0);
    } else {
      break;
    }
  }

  return new Uint8Array(bytes);
}
