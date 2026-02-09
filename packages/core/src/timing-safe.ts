import { timingSafeEqual } from 'crypto';

/**
 * Constant-time string comparison to prevent timing attacks
 * @param a First string to compare
 * @param b Second string to compare
 * @returns true if strings are equal, false otherwise
 */
export function constantTimeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) {
    return false;
  }

  const bufA = Buffer.from(a, 'utf8');
  const bufB = Buffer.from(b, 'utf8');

  return timingSafeEqual(bufA, bufB);
}

/**
 * Constant-time array comparison to prevent timing attacks
 * Always iterates through all elements regardless of where differences occur
 * @param a First array to compare
 * @param b Second array to compare
 * @returns true if arrays are equal, false otherwise
 */
export function constantTimeArrayEqual(a: string[], b: string[]): boolean {
  if (a.length !== b.length) {
    return false;
  }

  let result = 0;
  for (let i = 0; i < a.length; i++) {
    // XOR accumulation - any difference will set result to non-zero
    // Always iterate all elements to maintain constant time
    result |= a[i] === b[i] ? 0 : 1;
  }

  return result === 0;
}
