import { timingSafeEqual } from 'crypto';

/**
 * Constant-time string comparison to prevent timing attacks
 * @param a First string to compare
 * @param b Second string to compare
 * @returns true if strings are equal, false otherwise
 */
export function constantTimeEqual(a: string, b: string): boolean {
  const bufA = Buffer.from(a, 'utf8');
  const bufB = Buffer.from(b, 'utf8');

  // Pad the shorter buffer to match the longer one to prevent length leakage
  const maxLength = Math.max(bufA.length, bufB.length);
  const paddedA = Buffer.alloc(maxLength);
  const paddedB = Buffer.alloc(maxLength);
  bufA.copy(paddedA);
  bufB.copy(paddedB);

  // Always run timingSafeEqual regardless of length
  const buffersEqual = timingSafeEqual(paddedA, paddedB);

  // Combine timing-safe buffer comparison with length check
  return buffersEqual && a.length === b.length;
}

/**
 * Constant-time array comparison to prevent timing attacks
 * Always iterates through all elements regardless of where differences occur
 * @param a First array to compare
 * @param b Second array to compare
 * @returns true if arrays are equal, false otherwise
 */
export function constantTimeArrayEqual(a: string[], b: string[]): boolean {
  const maxLen = Math.max(a.length, b.length);
  let result = 0;

  // Length difference contributes to result
  result |= a.length ^ b.length;

  for (let i = 0; i < maxLen; i++) {
    const elemA = i < a.length ? a[i] : '';
    const elemB = i < b.length ? b[i] : '';
    result |= constantTimeEqual(elemA, elemB) ? 0 : 1;
  }

  return result === 0;
}
