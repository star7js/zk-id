/**
 * Generic predicate proof generation and verification
 *
 * Supports arbitrary field comparisons: ==, !=, >, <, >=, <=, and range checks
 */

import { poseidon } from 'circomlibjs';
import { groth16 } from 'snarkjs';
import type { Credential } from './credential';

/**
 * Predicate type enumeration
 */
export enum PredicateType {
  EQ = 0, // Equal
  NEQ = 1, // Not equal
  GT = 2, // Greater than
  LT = 3, // Less than
  GTE = 4, // Greater than or equal
  LTE = 5, // Less than or equal
  RANGE = 6, // Range check (min <= value <= max)
}

/**
 * Field selector for credential fields
 */
export enum FieldSelector {
  BIRTH_YEAR = 0,
  NATIONALITY = 1,
}

/**
 * Predicate specification
 */
export interface PredicateSpec {
  /** Field to check */
  field: FieldSelector;
  /** Type of predicate */
  type: PredicateType;
  /** Target value (or minimum for range) */
  value: number;
  /** Maximum value (only for RANGE predicate) */
  maxValue?: number;
}

/**
 * Generic predicate proof
 */
export interface PredicateProof {
  /** Proof type identifier */
  type: 'PredicateProof';
  /** Predicate specification */
  predicate: PredicateSpec;
  /** Public signals */
  publicSignals: {
    credentialCommitment: string;
    predicateType: number;
    targetValue: number;
    rangeMax: number;
    fieldSelector: number;
    nonce: string;
    timestamp: number;
    satisfied: number;
  };
  /** ZK proof */
  proof: {
    pi_a: string[];
    pi_b: string[][];
    pi_c: string[];
    protocol: string;
    curve: string;
  };
}

/**
 * Generate a generic predicate proof
 *
 * @param credential - Credential to prove predicate about
 * @param predicateSpec - Specification of the predicate to prove
 * @param nonce - Unique nonce for this proof
 * @param timestamp - Timestamp in milliseconds
 * @param wasmPath - Path to compiled circuit WASM
 * @param zkeyPath - Path to proving key
 * @returns Predicate proof
 */
export async function generatePredicateProof(
  credential: Credential,
  predicateSpec: PredicateSpec,
  nonce: string,
  timestamp: number,
  wasmPath: string,
  zkeyPath: string,
): Promise<PredicateProof> {
  // Validate inputs
  if (credential.birthYear < 1900 || credential.birthYear > 2100) {
    throw new Error('Birth year must be between 1900 and 2100');
  }

  if (credential.nationality < 0 || credential.nationality > 999) {
    throw new Error('Nationality code must be between 0 and 999');
  }

  if (predicateSpec.type === PredicateType.RANGE && !predicateSpec.maxValue) {
    throw new Error('maxValue is required for RANGE predicate');
  }

  // Compute credential commitment
  const commitment = poseidon([
    BigInt(credential.birthYear),
    BigInt(credential.nationality),
    BigInt(credential.nonce),
  ]);

  // Prepare circuit inputs
  const input = {
    // Public inputs
    credentialCommitment: commitment.toString(),
    predicateType: predicateSpec.type,
    targetValue: predicateSpec.value,
    rangeMax: predicateSpec.maxValue || 0,
    fieldSelector: predicateSpec.field,
    nonce: BigInt(nonce).toString(),
    timestamp,

    // Private inputs
    birthYear: credential.birthYear,
    nationality: credential.nationality,
    credentialNonce: BigInt(credential.nonce).toString(),
  };

  // Generate proof
  const { proof, publicSignals } = await groth16.fullProve(input, wasmPath, zkeyPath);

  return {
    type: 'PredicateProof',
    predicate: predicateSpec,
    publicSignals: {
      credentialCommitment: publicSignals[0],
      predicateType: parseInt(publicSignals[1]),
      targetValue: parseInt(publicSignals[2]),
      rangeMax: parseInt(publicSignals[3]),
      fieldSelector: parseInt(publicSignals[4]),
      nonce: publicSignals[5],
      timestamp: parseInt(publicSignals[6]),
      satisfied: parseInt(publicSignals[7]),
    },
    proof: {
      pi_a: proof.pi_a.slice(0, 2),
      pi_b: [proof.pi_b[0].slice(0, 2), proof.pi_b[1].slice(0, 2)],
      pi_c: proof.pi_c.slice(0, 2),
      protocol: proof.protocol,
      curve: proof.curve,
    },
  };
}

/**
 * Verify a generic predicate proof
 *
 * @param proof - Predicate proof to verify
 * @param vkeyPath - Path to verification key
 * @returns True if proof is valid
 */
export async function verifyPredicateProof(
  proof: PredicateProof,
  vkeyPath: string,
): Promise<boolean> {
  // Validate that predicate was satisfied
  if (proof.publicSignals.satisfied !== 1) {
    return false;
  }

  // Validate predicate specification matches public signals
  if (proof.predicate.type !== proof.publicSignals.predicateType) {
    return false;
  }

  if (proof.predicate.value !== proof.publicSignals.targetValue) {
    return false;
  }

  if (proof.predicate.field !== proof.publicSignals.fieldSelector) {
    return false;
  }

  if (
    proof.predicate.type === PredicateType.RANGE &&
    proof.predicate.maxValue !== proof.publicSignals.rangeMax
  ) {
    return false;
  }

  // Reconstruct public signals array
  const publicSignals = [
    proof.publicSignals.credentialCommitment,
    proof.publicSignals.predicateType.toString(),
    proof.publicSignals.targetValue.toString(),
    proof.publicSignals.rangeMax.toString(),
    proof.publicSignals.fieldSelector.toString(),
    proof.publicSignals.nonce,
    proof.publicSignals.timestamp.toString(),
    proof.publicSignals.satisfied.toString(),
  ];

  // Reconstruct proof object
  const proofObj = {
    pi_a: [...proof.proof.pi_a, '1'],
    pi_b: [
      [...proof.proof.pi_b[0], '1'],
      [...proof.proof.pi_b[1], '1'],
      ['1', '0', '0'],
    ],
    pi_c: [...proof.proof.pi_c, '1'],
    protocol: proof.proof.protocol,
    curve: proof.proof.curve,
  };

  // Load verification key
  const fs = await import('fs');
  const vkey = JSON.parse(fs.readFileSync(vkeyPath, 'utf-8'));

  // Verify proof
  return await groth16.verify(vkey, publicSignals, proofObj);
}

/**
 * Helper: Create age range predicate (minAge <= age <= maxAge)
 *
 * @param minAge - Minimum age
 * @param maxAge - Maximum age
 * @param currentYear - Current year (defaults to Date.now())
 * @returns Predicate specification
 */
export function createAgeRangePredicate(
  minAge: number,
  maxAge: number,
  currentYear?: number,
): PredicateSpec {
  const year = currentYear || new Date().getFullYear();
  const maxBirthYear = year - minAge;
  const minBirthYear = year - maxAge;

  return {
    field: FieldSelector.BIRTH_YEAR,
    type: PredicateType.RANGE,
    value: minBirthYear,
    maxValue: maxBirthYear,
  };
}

/**
 * Helper: Create minimum age predicate (age >= minAge)
 *
 * @param minAge - Minimum age
 * @param currentYear - Current year (defaults to Date.now())
 * @returns Predicate specification
 */
export function createMinAgePredicate(minAge: number, currentYear?: number): PredicateSpec {
  const year = currentYear || new Date().getFullYear();
  const maxBirthYear = year - minAge;

  return {
    field: FieldSelector.BIRTH_YEAR,
    type: PredicateType.LTE,
    value: maxBirthYear,
  };
}

/**
 * Helper: Create nationality equality predicate
 *
 * @param nationalityCode - ISO 3166-1 numeric nationality code
 * @returns Predicate specification
 */
export function createNationalityPredicate(nationalityCode: number): PredicateSpec {
  return {
    field: FieldSelector.NATIONALITY,
    type: PredicateType.EQ,
    value: nationalityCode,
  };
}

/**
 * Helper: Create nationality exclusion predicate
 *
 * @param nationalityCode - ISO 3166-1 numeric nationality code to exclude
 * @returns Predicate specification
 */
export function createNationalityExclusionPredicate(nationalityCode: number): PredicateSpec {
  return {
    field: FieldSelector.NATIONALITY,
    type: PredicateType.NEQ,
    value: nationalityCode,
  };
}
