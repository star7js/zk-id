/**
 * Poseidon hash utilities using circomlibjs
 *
 * Poseidon is a ZK-friendly hash function optimized for use in SNARKs
 */

import { buildPoseidon } from 'circomlibjs';

/** Poseidon hash function instance from circomlibjs. */
interface PoseidonHasher {
  (inputs: (number | bigint)[]): Uint8Array;
  F: { toObject(hash: Uint8Array): bigint };
}

let poseidonInstance: PoseidonHasher | null = null;

/**
 * Initialize the Poseidon hash function (lazy loaded)
 */
async function getPoseidon(): Promise<PoseidonHasher> {
  if (!poseidonInstance) {
    poseidonInstance = (await buildPoseidon()) as unknown as PoseidonHasher;
  }
  return poseidonInstance;
}

/**
 * Compute Poseidon hash of inputs
 *
 * @param inputs - Array of numbers or bigints to hash
 * @returns The hash as a bigint
 */
export async function poseidonHash(inputs: (number | bigint)[]): Promise<bigint> {
  const poseidon = await getPoseidon();
  const hash = poseidon(inputs);
  return poseidon.F.toObject(hash);
}

/**
 * Compute Poseidon hash and return as hex string
 */
export async function poseidonHashHex(inputs: (number | bigint)[]): Promise<string> {
  const hash = await poseidonHash(inputs);
  return '0x' + hash.toString(16).padStart(64, '0');
}

// ---------------------------------------------------------------------------
// Domain separation tags
// ---------------------------------------------------------------------------
// Each context that uses Poseidon should prefix a unique numeric tag as the
// first input. This prevents cross-context collisions by construction.
// These tags MUST match the constants used in the Circom circuits.

/** Domain tag for credential commitments: Poseidon(0, birthYear, nationality, salt) */
export const DOMAIN_CREDENTIAL = 0n;

/** Domain tag for nullifiers: Poseidon(1, credentialHash, scopeHash) */
export const DOMAIN_NULLIFIER = 1n;

/** Domain tag for Merkle tree nodes: Poseidon(2, left, right) */
export const DOMAIN_MERKLE = 2n;

/** Domain tag for scope hashes: Poseidon(3, scopeNum) */
export const DOMAIN_SCOPE = 3n;

/**
 * Compute Poseidon hash with domain separation.
 *
 * Prepends the domain tag as the first input to prevent cross-context collisions.
 * E.g., poseidonHashDomain(DOMAIN_CREDENTIAL, [birthYear, nationality, salt])
 *       computes Poseidon(0, birthYear, nationality, salt).
 *
 * @param domain - Domain separation tag (must match circuit constant)
 * @param inputs - Array of field elements to hash
 * @returns The hash as a bigint
 */
export async function poseidonHashDomain(
  domain: bigint,
  inputs: (number | bigint)[],
): Promise<bigint> {
  return poseidonHash([domain, ...inputs]);
}
