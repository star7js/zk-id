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
    poseidonInstance = await buildPoseidon() as unknown as PoseidonHasher;
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
