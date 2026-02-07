import * as snarkjs from 'snarkjs';
import {
  AgeProof,
  NationalityProof,
  AgeProofSigned,
  NationalityProofSigned,
  VerificationKey,
  BatchVerificationResult,
} from './types';

/**
 * Verifies an age proof using the verification key
 *
 * @param proof - The proof to verify
 * @param verificationKey - The circuit's verification key (public)
 * @returns true if the proof is valid, false otherwise
 */
export async function verifyAgeProof(
  proof: AgeProof,
  verificationKey: VerificationKey
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
  const isValid = await snarkjs.groth16.verify(
    verificationKey,
    publicSignals,
    snarkProof
  );

  return isValid;
}

/**
 * Additional validation checks beyond cryptographic verification
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

  // Check that credential hash is present
  if (!proof.publicSignals.credentialHash || proof.publicSignals.credentialHash === '0') {
    errors.push('Missing or invalid credential hash');
  }
  if (!proof.publicSignals.nonce || proof.publicSignals.nonce.length === 0) {
    errors.push('Missing nonce');
  }
  if (!proof.publicSignals.requestTimestamp || proof.publicSignals.requestTimestamp <= 0) {
    errors.push('Invalid request timestamp');
  }

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
  verificationKey: VerificationKey
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
  const isValid = await snarkjs.groth16.verify(
    verificationKey,
    publicSignals,
    snarkProof
  );

  return isValid;
}

/**
 * Verifies a signed age proof (includes issuer public key bits in public signals)
 */
export async function verifyAgeProofSigned(
  proof: AgeProofSigned,
  verificationKey: VerificationKey
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

  const isValid = await snarkjs.groth16.verify(
    verificationKey,
    publicSignals,
    snarkProof
  );

  return isValid;
}

/**
 * Verifies a signed nationality proof (includes issuer public key bits in public signals)
 */
export async function verifyNationalityProofSigned(
  proof: NationalityProofSigned,
  verificationKey: VerificationKey
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

  const isValid = await snarkjs.groth16.verify(
    verificationKey,
    publicSignals,
    snarkProof
  );

  return isValid;
}

/**
 * Additional validation checks for nationality proofs
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

  // Check that credential hash is present
  if (!proof.publicSignals.credentialHash || proof.publicSignals.credentialHash === '0') {
    errors.push('Missing or invalid credential hash');
  }
  if (!proof.publicSignals.nonce || proof.publicSignals.nonce.length === 0) {
    errors.push('Missing nonce');
  }
  if (!proof.publicSignals.requestTimestamp || proof.publicSignals.requestTimestamp <= 0) {
    errors.push('Invalid request timestamp');
  }

  return {
    valid: errors.length === 0,
    errors,
  };
}

/**
 * Load verification key from JSON file
 */
export async function loadVerificationKey(path: string): Promise<VerificationKey> {
  const fs = require('fs').promises;
  const data = await fs.readFile(path, 'utf8');
  return JSON.parse(data);
}

/**
 * Verifies multiple proofs in parallel
 *
 * @param proofs - Array of proofs with their verification keys and types
 * @returns Batch verification result with individual and aggregate outcomes
 */
export async function verifyBatch(
  proofs: Array<{
    proof: AgeProof | NationalityProof;
    verificationKey: VerificationKey;
    type: 'age' | 'nationality';
  }>
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

  // Verify all proofs in parallel using Promise.allSettled
  const verificationPromises = proofs.map(async ({ proof, verificationKey, type }, index) => {
    try {
      let verified: boolean;
      if (type === 'age') {
        verified = await verifyAgeProof(proof as AgeProof, verificationKey);
      } else {
        verified = await verifyNationalityProof(proof as NationalityProof, verificationKey);
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

  const verifiedCount = results.filter(r => r.verified).length;
  const allVerified = verifiedCount === results.length;

  return {
    results,
    allVerified,
    verifiedCount,
    totalCount: results.length,
  };
}
