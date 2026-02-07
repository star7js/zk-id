import { Credential } from './types';
import { poseidonHash } from './poseidon';
import { randomBytes } from 'crypto';

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
  // Validate birth year
  if (birthYear < 1900 || birthYear > new Date().getFullYear()) {
    throw new Error('Invalid birth year');
  }

  // Validate nationality (ISO 3166-1 numeric codes are 1-999)
  if (nationality < 1 || nationality > 999) {
    throw new Error('Invalid nationality code');
  }

  // Generate random salt (32 bytes = 256 bits of entropy)
  const salt = randomBytes(32).toString('hex');

  // Compute Poseidon commitment with 3 inputs
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
  const commitment = await poseidonHash([
    birthYear,
    nationality,
    BigInt('0x' + salt),
  ]);
  return commitment.toString();
}
