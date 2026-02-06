import * as snarkjs from 'snarkjs';
import { AgeProof, VerificationKey } from './types';

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
