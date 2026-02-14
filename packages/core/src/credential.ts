import { Credential } from './types';
import { poseidonHashDomain, DOMAIN_CREDENTIAL } from './poseidon';
import { randomBytes } from 'crypto';
import {
  validateBirthYear,
  validateNationality,
  validateHexString,
  MIN_BIRTH_YEAR,
  MIN_NATIONALITY,
  MAX_NATIONALITY,
} from './validation';

/**
 * Creates a new credential with the given birth year and nationality
 *
 * @param birthYear - The user's birth year (e.g., 1995)
 * @param nationality - The user's nationality (ISO 3166-1 numeric code, e.g., 840 for USA)
 * @returns A new Credential object with commitment
 */
export async function createCredential(
  birthYear: number,
  nationality: number,
): Promise<Credential> {
  validateBirthYear(birthYear);
  validateNationality(nationality);

  // Generate random salt (31 bytes = 248 bits of entropy)
  // 31 bytes ensures the value is always below the BN128 field prime (~2^254),
  // avoiding modular reduction and the resulting non-uniformity.
  const salt = randomBytes(31).toString('hex');

  // Compute Poseidon commitment with domain separation:
  // Poseidon(DOMAIN_CREDENTIAL, birthYear, nationality, salt)
  // The domain tag prevents cross-context hash collisions.
  const commitment = await poseidonHashDomain(DOMAIN_CREDENTIAL, [
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
 *
 * @param credential - The credential to validate
 * @returns true if the credential is valid, false otherwise
 */
export function validateCredential(credential: Credential): boolean {
  if (
    !credential.id ||
    typeof credential.id !== 'string' ||
    !credential.salt ||
    typeof credential.salt !== 'string' ||
    !credential.commitment ||
    typeof credential.commitment !== 'string'
  ) {
    return false;
  }

  if (!/^[0-9a-fA-F]+$/.test(credential.salt)) {
    return false;
  }

  if (
    !Number.isInteger(credential.birthYear) ||
    credential.birthYear < MIN_BIRTH_YEAR ||
    credential.birthYear > new Date().getFullYear()
  ) {
    return false;
  }

  if (
    !Number.isInteger(credential.nationality) ||
    credential.nationality < MIN_NATIONALITY ||
    credential.nationality > MAX_NATIONALITY
  ) {
    return false;
  }

  return true;
}

/**
 * Derives the commitment from a credential (for verification)
 *
 * @param birthYear - The user's birth year
 * @param nationality - The user's nationality code
 * @param salt - The credential salt (hex string)
 * @returns The Poseidon commitment hash as a string
 */
export async function deriveCommitment(
  birthYear: number,
  nationality: number,
  salt: string,
): Promise<string> {
  validateBirthYear(birthYear);
  validateNationality(nationality);
  validateHexString(salt, 'salt');

  // Domain-separated: Poseidon(DOMAIN_CREDENTIAL, birthYear, nationality, salt)
  const commitment = await poseidonHashDomain(DOMAIN_CREDENTIAL, [
    birthYear,
    nationality,
    BigInt('0x' + salt),
  ]);
  return commitment.toString();
}
