/**
 * Converts snarkjs proof format to Solidity calldata format.
 *
 * CRITICAL: snarkjs stores pi_b as [[b00, b01], [b10, b11]] but Solidity's
 * pairing precompile expects REVERSED inner pairs: [[b01, b00], [b11, b10]].
 * This is required for bn128 pairing checks to work correctly on-chain.
 */

import { AgeProof, NationalityProof } from '@zk-id/core';

export interface ProofCalldata {
  pA: [bigint, bigint];
  pB: [[bigint, bigint], [bigint, bigint]];
  pC: [bigint, bigint];
}

export interface AgeProofCalldata extends ProofCalldata {
  nonce: bigint;
  requestTimestamp: bigint;
  minAge: bigint;
  currentYear: bigint;
}

export interface NationalityProofCalldata extends ProofCalldata {
  nonce: bigint;
  requestTimestamp: bigint;
  targetNationality: bigint;
}

/**
 * Convert raw snarkjs proof to Solidity calldata format.
 * Reverses inner pairs of pi_b for correct pairing verification.
 */
export function proofToCalldata(proof: {
  pi_a: string[];
  pi_b: string[][];
  pi_c: string[];
}): ProofCalldata {
  return {
    pA: [BigInt(proof.pi_a[0]), BigInt(proof.pi_a[1])],
    // REVERSED: [b01, b00], [b11, b10]
    pB: [
      [BigInt(proof.pi_b[0][1]), BigInt(proof.pi_b[0][0])],
      [BigInt(proof.pi_b[1][1]), BigInt(proof.pi_b[1][0])],
    ],
    pC: [BigInt(proof.pi_c[0]), BigInt(proof.pi_c[1])],
  };
}

/**
 * Convert AgeProof to Solidity calldata format with public signals.
 */
export function ageProofToCalldata(proof: AgeProof): AgeProofCalldata {
  const baseProof = proofToCalldata(proof.proof);
  return {
    ...baseProof,
    nonce: BigInt(proof.publicSignals.nonce),
    requestTimestamp: BigInt(proof.publicSignals.requestTimestamp),
    minAge: BigInt(proof.publicSignals.minAge),
    currentYear: BigInt(proof.publicSignals.currentYear),
  };
}

/**
 * Convert NationalityProof to Solidity calldata format with public signals.
 */
export function nationalityProofToCalldata(proof: NationalityProof): NationalityProofCalldata {
  const baseProof = proofToCalldata(proof.proof);
  return {
    ...baseProof,
    nonce: BigInt(proof.publicSignals.nonce),
    requestTimestamp: BigInt(proof.publicSignals.requestTimestamp),
    targetNationality: BigInt(proof.publicSignals.targetNationality),
  };
}
