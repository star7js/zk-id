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
  // Check timestamp staleness (5 minutes)
  const nowMs = Date.now();
  if (proof.publicSignals.requestTimestamp > 0 &&
      nowMs - proof.publicSignals.requestTimestamp > 5 * 60 * 1000) {
    errors.push('Request timestamp is stale (> 5 minutes old)');
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
 * Verifies a signed age proof and checks the issuer public key matches the trusted key
 */
export async function verifyAgeProofSignedWithIssuer(
  proof: AgeProofSigned,
  verificationKey: VerificationKey,
  trustedIssuerPublicKeyBits: string[]
): Promise<boolean> {
  if (
    trustedIssuerPublicKeyBits.length !== proof.publicSignals.issuerPublicKey.length ||
    trustedIssuerPublicKeyBits.some((bit, i) => bit !== proof.publicSignals.issuerPublicKey[i])
  ) {
    return false;
  }
  return verifyAgeProofSigned(proof, verificationKey);
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
 * Verifies a signed nationality proof and checks the issuer public key matches the trusted key
 */
export async function verifyNationalityProofSignedWithIssuer(
  proof: NationalityProofSigned,
  verificationKey: VerificationKey,
  trustedIssuerPublicKeyBits: string[]
): Promise<boolean> {
  if (
    trustedIssuerPublicKeyBits.length !== proof.publicSignals.issuerPublicKey.length ||
    trustedIssuerPublicKeyBits.some((bit, i) => bit !== proof.publicSignals.issuerPublicKey[i])
  ) {
    return false;
  }
  return verifyNationalityProofSigned(proof, verificationKey);
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
  const nowMs2 = Date.now();
  if (proof.publicSignals.requestTimestamp > 0 &&
      nowMs2 - proof.publicSignals.requestTimestamp > 5 * 60 * 1000) {
    errors.push('Request timestamp is stale (> 5 minutes old)');
  }

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
  expectedMerkleRoot?: string
): Promise<boolean> {
  // Optional server-side freshness check
  if (expectedMerkleRoot != null && proof.publicSignals.merkleRoot !== expectedMerkleRoot) {
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
  const isValid = await snarkjs.groth16.verify(
    verificationKey,
    publicSignals,
    snarkProof
  );

  return isValid;
}

/**
 * Additional validation checks for revocable age proofs
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

  // Check that credential hash is present
  if (!proof.publicSignals.credentialHash || proof.publicSignals.credentialHash === '0') {
    errors.push('Missing or invalid credential hash');
  }

  // Check that merkle root is present
  if (!proof.publicSignals.merkleRoot || proof.publicSignals.merkleRoot === '0') {
    errors.push('Missing or invalid merkle root');
  }

  if (!proof.publicSignals.nonce || proof.publicSignals.nonce.length === 0) {
    errors.push('Missing nonce');
  }

  if (!proof.publicSignals.requestTimestamp || proof.publicSignals.requestTimestamp <= 0) {
    errors.push('Invalid request timestamp');
  }
  const nowMs3 = Date.now();
  if (proof.publicSignals.requestTimestamp > 0 &&
      nowMs3 - proof.publicSignals.requestTimestamp > 5 * 60 * 1000) {
    errors.push('Request timestamp is stale (> 5 minutes old)');
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
        default:
          throw new Error(`Unknown proof type: ${(proof as ZkProof).proofType}`);
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
