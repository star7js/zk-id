/**
 * Nullifier system for sybil resistance.
 *
 * Nullifiers enable "prove once per context" semantics — a user can prove
 * they meet a requirement (e.g., age >= 18) for a specific scope (e.g.,
 * voting in election X) and the verifier can detect if the same credential
 * is used twice within that scope, WITHOUT learning the user's identity.
 *
 * This is the same pattern used by Worldcoin (World ID), Semaphore, and
 * Tornado Cash. It is critical for:
 *   - Sybil-resistant voting / airdrops
 *   - Rate-limited anonymous actions
 *   - Anonymous reputation systems
 *
 * The nullifier is computed as:
 *   nullifier = Poseidon(credentialSecret, scopeHash)
 *
 * where:
 *   - credentialSecret = Poseidon(birthYear, nationality, salt) (the commitment)
 *   - scopeHash = Poseidon(scope) where scope is an external identifier
 *
 * The nullifier is deterministic: the same credential + scope always produces
 * the same nullifier, so verifiers can detect double-use. But different
 * scopes produce different nullifiers, so actions are unlinkable across scopes.
 */

import { poseidonHash } from './poseidon';
import { validateScopeId, validateBigIntString } from './validation';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/**
 * Scope identifier for nullifier computation.
 * Examples: "election-2026", "airdrop-round-3", "forum-registration"
 */
export interface NullifierScope {
  /** Human-readable scope identifier */
  id: string;
  /** Numeric hash of the scope (for circuit use) */
  scopeHash: string;
}

/**
 * A computed nullifier bound to a credential and scope.
 */
export interface NullifierOutput {
  /** The nullifier value (deterministic per credential+scope) */
  nullifier: string;
  /** The scope this nullifier is bound to */
  scope: NullifierScope;
  /** The credential commitment this nullifier derives from */
  commitment: string;
}

/**
 * Store for tracking used nullifiers (verifier-side).
 */
export interface NullifierStore {
  /** Check if a nullifier has been used in the given scope */
  hasBeenUsed(nullifier: string, scopeId: string): Promise<boolean>;
  /** Mark a nullifier as used */
  markUsed(nullifier: string, scopeId: string): Promise<void>;
  /** Get the count of used nullifiers in a scope */
  getUsedCount(scopeId: string): Promise<number>;
}

// ---------------------------------------------------------------------------
// Nullifier Computation
// ---------------------------------------------------------------------------

/**
 * Create a nullifier scope from a string identifier.
 *
 * The scope string is hashed to produce a field element suitable for
 * circuit inputs.
 *
 * @param scopeId - Human-readable scope identifier (e.g., "election-2026")
 * @returns A NullifierScope with hashed scope value
 */
export async function createNullifierScope(scopeId: string): Promise<NullifierScope> {
  validateScopeId(scopeId);

  // Convert scope string to a numeric value by encoding as field element
  // Use a simple but deterministic encoding: hash the UTF-8 bytes
  const encoder = new TextEncoder();
  const bytes = encoder.encode(scopeId);
  // Convert first 31 bytes to a BigInt (to stay within BN128 field)
  let scopeNum = 0n;
  for (let i = 0; i < Math.min(bytes.length, 31); i++) {
    scopeNum = (scopeNum << 8n) | BigInt(bytes[i]);
  }

  const scopeHash = await poseidonHash([scopeNum]);

  return {
    id: scopeId,
    scopeHash: scopeHash.toString(),
  };
}

/**
 * Compute a nullifier for a credential within a scope.
 *
 * The nullifier is deterministic: the same (commitment, scope) pair
 * always produces the same nullifier. This enables sybil detection
 * without revealing the underlying credential.
 *
 * @param commitment - The credential commitment (Poseidon hash)
 * @param scope      - The nullifier scope
 * @returns The nullifier output
 */
export async function computeNullifier(
  commitment: string,
  scope: NullifierScope
): Promise<NullifierOutput> {
  validateBigIntString(commitment, 'commitment');
  validateBigIntString(scope.scopeHash, 'scope.scopeHash');

  const commitmentBigInt = BigInt(commitment);
  const scopeHashBigInt = BigInt(scope.scopeHash);

  const nullifier = await poseidonHash([commitmentBigInt, scopeHashBigInt]);

  return {
    nullifier: nullifier.toString(),
    scope,
    commitment,
  };
}

/**
 * Verify that a nullifier hasn't been used, and mark it as used.
 *
 * @param nullifier - The nullifier to check
 * @param scopeId   - The scope identifier
 * @param store     - The nullifier store
 * @returns Object indicating whether the nullifier was fresh (first use)
 */
export async function consumeNullifier(
  nullifier: string,
  scopeId: string,
  store: NullifierStore
): Promise<{ fresh: boolean; error?: string }> {
  const alreadyUsed = await store.hasBeenUsed(nullifier, scopeId);
  if (alreadyUsed) {
    return {
      fresh: false,
      error: 'Nullifier already used in this scope (duplicate action detected)',
    };
  }

  await store.markUsed(nullifier, scopeId);
  return { fresh: true };
}

// ---------------------------------------------------------------------------
// In-Memory NullifierStore (for testing and demos)
// ---------------------------------------------------------------------------

/**
 * In-memory nullifier store. Not suitable for production — use a
 * persistent store (Redis, Postgres, etc.) in real deployments.
 */
export class InMemoryNullifierStore implements NullifierStore {
  private used: Map<string, Set<string>> = new Map();

  /**
   * Check if a nullifier has been used in the given scope
   *
   * @param nullifier - The nullifier to check
   * @param scopeId - The scope identifier
   * @returns true if the nullifier has been used, false otherwise
   */
  async hasBeenUsed(nullifier: string, scopeId: string): Promise<boolean> {
    const scopeSet = this.used.get(scopeId);
    return scopeSet?.has(nullifier) ?? false;
  }

  /**
   * Mark a nullifier as used in the given scope
   *
   * @param nullifier - The nullifier to mark as used
   * @param scopeId - The scope identifier
   */
  async markUsed(nullifier: string, scopeId: string): Promise<void> {
    let scopeSet = this.used.get(scopeId);
    if (!scopeSet) {
      scopeSet = new Set();
      this.used.set(scopeId, scopeSet);
    }
    scopeSet.add(nullifier);
  }

  /**
   * Get the count of used nullifiers in a scope
   *
   * @param scopeId - The scope identifier
   * @returns The number of nullifiers used in this scope
   */
  async getUsedCount(scopeId: string): Promise<number> {
    return this.used.get(scopeId)?.size ?? 0;
  }
}
