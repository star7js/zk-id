import { Credential } from './types';
import { poseidonHash } from './poseidon';
import { randomBytes } from 'crypto';
import { validateBirthYear, validateNationality, validateHexString } from './validation';

/**
 * Creates a new credential with the given birth year and nationality
 *
 * @param birthYear - The user's birth year (e.g., 1995)
 * @param nationality - The user's nationality (ISO 3166-1 numeric code, e.g., 840 for USA)
 * @returns A new Credential object with commitment
 */
export async function createCredential(
  birthYear: number,
  nationality: number
): Promise<Credential> {
  validateBirthYear(birthYear);
  validateNationality(nationality);

  // Generate random salt (32 bytes = 256 bits of entropy)
  const salt = randomBytes(32).toString('hex');

  // Compute Poseidon commitment with 3 inputs
  // NOTE: Field element encoding safety
  // - Salt is 256 bits, but BN128 scalar field is ~254 bits (p ≈ 2^254)
  // - BigInt('0x' + salt) may produce values > field prime
  // - circomlibjs Poseidon automatically performs modular reduction (value mod p)
  // - No truncation occurs - reduction is cryptographically sound
  // - Same encoding pattern used consistently in prover.ts
  const commitment = await poseidonHash([
    birthYear,
    nationality,
    BigInt('0x' + salt),
  ]);

  // Generate unique ID
  const id = randomBytes(16).toString('hex');

  return {
    id,
    birthYear,
    nationality,
    salt,
    commitment: commitment.toString(),
    createdAt: new Date().toISOString(),
  };
}

/**
 * Validates that a credential is well-formed
 */
export function validateCredential(credential: Credential): boolean {
  if (!credential.id || !credential.salt || !credential.commitment) {
    return false;
  }

  if (credential.birthYear < 1900 || credential.birthYear > new Date().getFullYear()) {
    return false;
  }

  if (credential.nationality < 1 || credential.nationality > 999) {
    return false;
  }

  return true;
}

/**
 * Derives the commitment from a credential (for verification)
 */
export async function deriveCommitment(
  birthYear: number,
  nationality: number,
  salt: string
): Promise<string> {
  validateBirthYear(birthYear);
  validateNationality(nationality);
  validateHexString(salt, 'salt');

  // NOTE: 256-bit salt → BigInt conversion is safe for BN128 field (~254 bits)
  // Poseidon hash performs automatic modular reduction if needed
  const commitment = await poseidonHash([
    birthYear,
    nationality,
    BigInt('0x' + salt),
  ]);
  return commitment.toString();
}
