/**
 * Poseidon hash utilities using circomlibjs
 *
 * Poseidon is a ZK-friendly hash function optimized for use in SNARKs
 */

import { buildPoseidon } from 'circomlibjs';

let poseidonInstance: any = null;

/**
 * Initialize the Poseidon hash function (lazy loaded)
 */
async function getPoseidon() {
  if (!poseidonInstance) {
    poseidonInstance = await buildPoseidon();
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
