import * as snarkjs from 'snarkjs';
import {
  AgeProof,
  NationalityProof,
  AgeProofSigned,
  NationalityProofSigned,
  AgeProofRevocable,
  VerificationKey,
  BatchVerificationResult,
  ZkProof,
  NullifierProof,
  BBSProofResponse,
} from './types';
import { constantTimeEqual, constantTimeArrayEqual } from './timing-safe';
import { ZkIdProofError, ZkIdConfigError } from './errors';
import { deserializeBBSProof, verifyBBSDisclosureProof } from './bbs';
import { SCHEMA_REGISTRY } from './bbs-schema';

/** Default staleness window for request timestamps (5 minutes). */
const STALE_TIMESTAMP_MS = 5 * 60 * 1000;

/** Returns true if value is a non-empty string parseable as a BigInt. */
function isValidBigIntString(value: string): boolean {
  if (!value || value.length === 0) return false;
  try {
    BigInt(value);
    return true;
  } catch {
    return false;
  }
}

/**
 * Validates the common public-signal fields shared by all proof types:
 * credentialHash, nonce, requestTimestamp, and staleness.
 *
 * Pushes human-readable error strings into the provided `errors` array.
 */
function validateCommonSignals(
  signals: { credentialHash: string; nonce: string; requestTimestamp: number },
  errors: string[],
  windowMs: number = STALE_TIMESTAMP_MS,
): void {
  // Credential hash
  if (
    !signals.credentialHash ||
    signals.credentialHash === '0' ||
    !isValidBigIntString(signals.credentialHash)
  ) {
    errors.push('Missing or invalid credential hash');
  }
  // Nonce
  if (!signals.nonce || signals.nonce.length === 0) {
    errors.push('Missing nonce');
  }
  // Timestamp presence
  if (!signals.requestTimestamp || signals.requestTimestamp <= 0) {
    errors.push('Invalid request timestamp');
  }
  // Staleness
  if (signals.requestTimestamp > 0 && Date.now() - signals.requestTimestamp > windowMs) {
    errors.push('Request timestamp is stale (> 5 minutes old)');
  }
}

/**
 * Verifies an age proof using the verification key
 *
 * @param proof - The proof to verify
 * @param verificationKey - The circuit's verification key (public)
 * @returns true if the proof is valid, false otherwise
 */
export async function verifyAgeProof(
  proof: AgeProof,
  verificationKey: VerificationKey,
): Promise<boolean> {
  // Convert proof to snarkjs format
  const snarkProof = {
    pi_a: proof.proof.pi_a,
    pi_b: proof.proof.pi_b,
    pi_c: proof.proof.pi_c,
    protocol: proof.proof.protocol,
    curve: proof.proof.curve,
  };

  // Convert public signals to array
  const publicSignals = [
    proof.publicSignals.currentYear.toString(),
    proof.publicSignals.minAge.toString(),
    proof.publicSignals.credentialHash,
    proof.publicSignals.nonce,
    proof.publicSignals.requestTimestamp.toString(),
  ];

  // Verify the proof
  const isValid = await snarkjs.groth16.verify(verificationKey, publicSignals, snarkProof);

  return isValid;
}

/**
 * Additional validation checks beyond cryptographic verification
 *
 * @param proof - The age proof to validate
 * @returns Object containing validation result and any error messages
 */
export function validateProofConstraints(proof: AgeProof): {
  valid: boolean;
  errors: string[];
} {
  const errors: string[] = [];

  // Check that current year is reasonable
  const now = new Date().getFullYear();
  if (proof.publicSignals.currentYear < 2020 || proof.publicSignals.currentYear > now + 1) {
    errors.push('Invalid current year in proof');
  }

  // Check that minAge is reasonable
  if (proof.publicSignals.minAge < 0 || proof.publicSignals.minAge > 150) {
    errors.push('Invalid minimum age requirement');
  }

  // Common signal checks (credentialHash, nonce, timestamp, staleness)
  validateCommonSignals(proof.publicSignals, errors);

  return {
    valid: errors.length === 0,
    errors,
  };
}

/**
 * Verifies a nationality proof using the verification key
 *
 * @param proof - The proof to verify
 * @param verificationKey - The circuit's verification key (public)
 * @returns true if the proof is valid, false otherwise
 */
export async function verifyNationalityProof(
  proof: NationalityProof,
  verificationKey: VerificationKey,
): Promise<boolean> {
  // Convert proof to snarkjs format
  const snarkProof = {
    pi_a: proof.proof.pi_a,
    pi_b: proof.proof.pi_b,
    pi_c: proof.proof.pi_c,
    protocol: proof.proof.protocol,
    curve: proof.proof.curve,
  };

  // Convert public signals to array
  const publicSignals = [
    proof.publicSignals.targetNationality.toString(),
    proof.publicSignals.credentialHash,
    proof.publicSignals.nonce,
    proof.publicSignals.requestTimestamp.toString(),
  ];

  // Verify the proof
  const isValid = await snarkjs.groth16.verify(verificationKey, publicSignals, snarkProof);

  return isValid;
}

/**
 * Verifies a signed age proof (includes issuer public key bits in public signals)
 *
 * @param proof - The signed age proof to verify
 * @param verificationKey - The circuit's verification key (public)
 * @returns true if the proof is valid, false otherwise
 */
export async function verifyAgeProofSigned(
  proof: AgeProofSigned,
  verificationKey: VerificationKey,
): Promise<boolean> {
  const snarkProof = {
    pi_a: proof.proof.pi_a,
    pi_b: proof.proof.pi_b,
    pi_c: proof.proof.pi_c,
    protocol: proof.proof.protocol,
    curve: proof.proof.curve,
  };

  const publicSignals = [
    proof.publicSignals.currentYear.toString(),
    proof.publicSignals.minAge.toString(),
    proof.publicSignals.credentialHash,
    proof.publicSignals.nonce,
    proof.publicSignals.requestTimestamp.toString(),
    ...proof.publicSignals.issuerPublicKey,
  ];

  const isValid = await snarkjs.groth16.verify(verificationKey, publicSignals, snarkProof);

  return isValid;
}

/**
 * Verifies a signed age proof and checks the issuer public key matches the trusted key
 *
 * @param proof - The signed age proof to verify
 * @param verificationKey - The circuit's verification key (public)
 * @param issuerPublicKeyBits - Trusted issuer public key bits to verify against
 * @returns true if the proof is valid and issuer matches, false otherwise
 */
export async function verifyAgeProofSignedWithIssuer(
  proof: AgeProofSigned,
  verificationKey: VerificationKey,
  trustedIssuerPublicKeyBits: string[],
): Promise<boolean> {
  if (!constantTimeArrayEqual(trustedIssuerPublicKeyBits, proof.publicSignals.issuerPublicKey)) {
    return false;
  }
  return verifyAgeProofSigned(proof, verificationKey);
}

/**
 * Verifies a signed nationality proof (includes issuer public key bits in public signals)
 *
 * @param proof - The signed nationality proof to verify
 * @param verificationKey - The circuit's verification key (public)
 * @returns true if the proof is valid, false otherwise
 */
export async function verifyNationalityProofSigned(
  proof: NationalityProofSigned,
  verificationKey: VerificationKey,
): Promise<boolean> {
  const snarkProof = {
    pi_a: proof.proof.pi_a,
    pi_b: proof.proof.pi_b,
    pi_c: proof.proof.pi_c,
    protocol: proof.proof.protocol,
    curve: proof.proof.curve,
  };

  const publicSignals = [
    proof.publicSignals.targetNationality.toString(),
    proof.publicSignals.credentialHash,
    proof.publicSignals.nonce,
    proof.publicSignals.requestTimestamp.toString(),
    ...proof.publicSignals.issuerPublicKey,
  ];

  const isValid = await snarkjs.groth16.verify(verificationKey, publicSignals, snarkProof);

  return isValid;
}

/**
 * Verifies a signed nationality proof and checks the issuer public key matches the trusted key
 *
 * @param proof - The signed nationality proof to verify
 * @param verificationKey - The circuit's verification key (public)
 * @param issuerPublicKeyBits - Trusted issuer public key bits to verify against
 * @returns true if the proof is valid and issuer matches, false otherwise
 */
export async function verifyNationalityProofSignedWithIssuer(
  proof: NationalityProofSigned,
  verificationKey: VerificationKey,
  trustedIssuerPublicKeyBits: string[],
): Promise<boolean> {
  if (!constantTimeArrayEqual(trustedIssuerPublicKeyBits, proof.publicSignals.issuerPublicKey)) {
    return false;
  }
  return verifyNationalityProofSigned(proof, verificationKey);
}

/**
 * Additional validation checks for nationality proofs
 *
 * @param proof - The nationality proof to validate
 * @returns Object containing validation result and any error messages
 */
export function validateNationalityProofConstraints(proof: NationalityProof): {
  valid: boolean;
  errors: string[];
} {
  const errors: string[] = [];

  // Check that nationality code is valid (ISO 3166-1 numeric: 1-999)
  if (proof.publicSignals.targetNationality < 1 || proof.publicSignals.targetNationality > 999) {
    errors.push('Invalid nationality code in proof');
  }

  // Common signal checks (credentialHash, nonce, timestamp, staleness)
  validateCommonSignals(proof.publicSignals, errors);

  return {
    valid: errors.length === 0,
    errors,
  };
}

/**
 * Verifies a revocable age proof using the verification key
 *
 * @param proof - The proof to verify
 * @param verificationKey - The circuit's verification key (public)
 * @param expectedMerkleRoot - Optional expected Merkle root for freshness check
 * @returns true if the proof is valid, false otherwise
 */
export async function verifyAgeProofRevocable(
  proof: AgeProofRevocable,
  verificationKey: VerificationKey,
  expectedMerkleRoot?: string,
): Promise<boolean> {
  // Optional server-side freshness check
  if (
    expectedMerkleRoot != null &&
    !constantTimeEqual(proof.publicSignals.merkleRoot, expectedMerkleRoot)
  ) {
    return false;
  }

  // Convert proof to snarkjs format
  const snarkProof = {
    pi_a: proof.proof.pi_a,
    pi_b: proof.proof.pi_b,
    pi_c: proof.proof.pi_c,
    protocol: proof.proof.protocol,
    curve: proof.proof.curve,
  };

  // Convert public signals to array
  // Index mapping: [0]=currentYear, [1]=minAge, [2]=credentialHash, [3]=merkleRoot, [4]=nonce, [5]=requestTimestamp
  const publicSignals = [
    proof.publicSignals.currentYear.toString(),
    proof.publicSignals.minAge.toString(),
    proof.publicSignals.credentialHash,
    proof.publicSignals.merkleRoot,
    proof.publicSignals.nonce,
    proof.publicSignals.requestTimestamp.toString(),
  ];

  // Verify the proof
  const isValid = await snarkjs.groth16.verify(verificationKey, publicSignals, snarkProof);

  return isValid;
}

/**
 * Additional validation checks for revocable age proofs
 *
 * @param proof - The revocable age proof to validate
 * @returns Object containing validation result and any error messages
 */
export function validateAgeProofRevocableConstraints(proof: AgeProofRevocable): {
  valid: boolean;
  errors: string[];
} {
  const errors: string[] = [];

  // Check that current year is reasonable
  const now = new Date().getFullYear();
  if (proof.publicSignals.currentYear < 2020 || proof.publicSignals.currentYear > now + 1) {
    errors.push('Invalid current year in proof');
  }

  // Check that minAge is reasonable
  if (proof.publicSignals.minAge < 0 || proof.publicSignals.minAge > 150) {
    errors.push('Invalid minimum age requirement');
  }

  // Check that merkle root is a valid numeric string
  if (
    !proof.publicSignals.merkleRoot ||
    proof.publicSignals.merkleRoot === '0' ||
    !isValidBigIntString(proof.publicSignals.merkleRoot)
  ) {
    errors.push('Missing or invalid merkle root');
  }

  // Common signal checks (credentialHash, nonce, timestamp, staleness)
  validateCommonSignals(proof.publicSignals, errors);

  return {
    valid: errors.length === 0,
    errors,
  };
}

/**
 * Load verification key from JSON file
 *
 * @param path - Filesystem path to the verification key JSON file
 * @returns The parsed verification key object
 */
export async function loadVerificationKey(path: string): Promise<VerificationKey> {
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  const fs = require('fs').promises;
  const data = await fs.readFile(path, 'utf8');
  try {
    return JSON.parse(data);
  } catch (error) {
    throw new ZkIdConfigError(
      `Failed to parse verification key from ${path}: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
}

/**
 * Verifies multiple proofs in parallel.
 *
 * Each proof carries a `proofType` discriminator so the verifier can
 * dispatch to the correct verification function automatically.
 *
 * @param proofs - Array of proofs with their verification keys
 * @returns Batch verification result with individual and aggregate outcomes
 */
export async function verifyBatch(
  proofs: Array<{
    proof: ZkProof;
    verificationKey: VerificationKey;
  }>,
): Promise<BatchVerificationResult> {
  // Handle empty array
  if (proofs.length === 0) {
    return {
      results: [],
      allVerified: true,
      verifiedCount: 0,
      totalCount: 0,
    };
  }

  // Verify all proofs in parallel (errors caught per-promise)
  const verificationPromises = proofs.map(async ({ proof, verificationKey }, index) => {
    try {
      let verified: boolean;
      switch (proof.proofType) {
        case 'age':
          verified = await verifyAgeProof(proof, verificationKey);
          break;
        case 'nationality':
          verified = await verifyNationalityProof(proof, verificationKey);
          break;
        case 'age-revocable':
          verified = await verifyAgeProofRevocable(proof, verificationKey);
          break;
        case 'age-signed':
          verified = await verifyAgeProofSigned(proof, verificationKey);
          break;
        case 'nationality-signed':
          verified = await verifyNationalityProofSigned(proof, verificationKey);
          break;
        case 'nullifier':
          verified = await verifyNullifierProof(proof, verificationKey);
          break;
        case 'bbs-selective-disclosure': {
          const disclosureProof = deserializeBBSProof(proof.proof);
          verified = await verifyBBSDisclosureProof(disclosureProof);
          break;
        }
        case 'range':
          verified = await verifyRangeProof(proof, verificationKey);
          break;
        default:
          throw new ZkIdProofError(
            `Unknown proof type: ${(proof as ZkProof).proofType}`,
            'UNKNOWN_PROOF_TYPE',
          );
      }
      return { index, verified, error: undefined };
    } catch (error) {
      return {
        index,
        verified: false,
        error: error instanceof Error ? error.message : 'Unknown error',
      };
    }
  });

  const results = await Promise.all(verificationPromises);

  const verifiedCount = results.filter((r) => r.verified).length;
  const allVerified = verifiedCount === results.length;

  return {
    results,
    allVerified,
    verifiedCount,
    totalCount: results.length,
  };
}

/**
 * Verifies a nullifier proof using the verification key
 *
 * @param proof - The nullifier proof to verify
 * @param verificationKey - The circuit's verification key (public)
 * @returns true if the proof is valid, false otherwise
 */
export async function verifyNullifierProof(
  proof: NullifierProof,
  verificationKey: VerificationKey,
): Promise<boolean> {
  // Convert proof to snarkjs format
  const snarkProof = {
    pi_a: proof.proof.pi_a,
    pi_b: proof.proof.pi_b,
    pi_c: proof.proof.pi_c,
  };

  // Convert public signals to array
  // Order: [credentialHash, scopeHash, nullifier]
  const publicSignals = [
    proof.publicSignals.credentialHash,
    proof.publicSignals.scopeHash,
    proof.publicSignals.nullifier,
  ];

  // Verify the proof
  const isValid = await snarkjs.groth16.verify(verificationKey, publicSignals, snarkProof);

  return isValid;
}

/**
 * Verifies a BBS+ selective disclosure proof from a proof response
 *
 * @param response - The BBS proof response containing the proof and revealed fields
 * @param publicKey - The issuer's BBS+ public key (Uint8Array)
 * @returns true if the proof is valid, false otherwise
 */
export async function verifyBBSDisclosureProofFromResponse(
  response: BBSProofResponse,
  _publicKey: Uint8Array,
): Promise<boolean> {
  // Validate schema exists
  const schema = SCHEMA_REGISTRY.get(response.schemaId);
  if (!schema) {
    throw new ZkIdProofError(`Unknown schema: ${response.schemaId}`, 'UNKNOWN_SCHEMA');
  }

  // Deserialize the proof
  const disclosureProof = deserializeBBSProof(response.proof);

  // Verify the proof
  return verifyBBSDisclosureProof(disclosureProof);
}

/**
 * Verifies a range proof using the verification key
 *
 * @param proof - The range proof to verify
 * @param verificationKey - The circuit's verification key (public)
 * @returns true if the proof is valid, false otherwise
 */
export async function verifyRangeProof(
  proof: { proof: { pi_a: string[]; pi_b: string[][]; pi_c: string[] }; publicSignals: string[] },
  verificationKey: VerificationKey,
): Promise<boolean> {
  const snarkProof = {
    pi_a: proof.proof.pi_a,
    pi_b: proof.proof.pi_b,
    pi_c: proof.proof.pi_c,
  };

  return snarkjs.groth16.verify(verificationKey, proof.publicSignals, snarkProof);
}
