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

import { createHash } from 'crypto';
import {
  poseidonHashDomain,
  DOMAIN_NULLIFIER,
  DOMAIN_SCOPE,
} from './poseidon';
import { validateScopeId, validateBigIntString, BN128_FIELD_ORDER } from './validation';

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
  /**
   * Atomically check if a nullifier has been used and mark it if not.
   * Returns true if the nullifier was fresh (first use), false if already used.
   *
   * This MUST be atomic to prevent TOCTOU races where two concurrent requests
   * both see the nullifier as unused and both succeed.
   *
   * Implementations:
   *   - Redis: Use SETNX or a Lua script
   *   - PostgreSQL: Use INSERT ... ON CONFLICT DO NOTHING with RETURNING
   *   - In-memory: Synchronized check-and-set
   */
  checkAndMarkUsed(nullifier: string, scopeId: string): Promise<boolean>;
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

  // Hash the full scope string with SHA-256 to get a deterministic digest,
  // then reduce mod BN128 field order to get a valid field element.
  // This avoids the previous truncation-at-31-bytes approach which caused
  // collisions for scope IDs that shared the same first 31 UTF-8 bytes.
  const sha256Digest = createHash('sha256').update(scopeId, 'utf8').digest();
  const scopeNum = BigInt('0x' + sha256Digest.toString('hex')) % BN128_FIELD_ORDER;

  const scopeHash = await poseidonHashDomain(DOMAIN_SCOPE, [scopeNum]);

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
  scope: NullifierScope,
): Promise<NullifierOutput> {
  validateBigIntString(commitment, 'commitment');
  validateBigIntString(scope.scopeHash, 'scope.scopeHash');

  const commitmentBigInt = BigInt(commitment);
  const scopeHashBigInt = BigInt(scope.scopeHash);

  const nullifier = await poseidonHashDomain(DOMAIN_NULLIFIER, [commitmentBigInt, scopeHashBigInt]);

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
  store: NullifierStore,
): Promise<{ fresh: boolean; error?: string }> {
  // Use atomic checkAndMarkUsed to prevent TOCTOU race conditions.
  // Without atomicity, two concurrent requests could both pass the
  // hasBeenUsed check before either calls markUsed.
  const wasFresh = await store.checkAndMarkUsed(nullifier, scopeId);
  if (!wasFresh) {
    return {
      fresh: false,
      error: 'Nullifier already used in this scope (duplicate action detected)',
    };
  }
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

  constructor() {
    if (typeof process !== 'undefined' && process.env.NODE_ENV === 'production') {
      console.warn(
        '[zk-id] InMemoryNullifierStore is not suitable for production. ' +
          'Nullifier state will be lost on restart, breaking sybil resistance. Use a persistent store (Redis, PostgreSQL).',
      );
    }
  }

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

  /**
   * Atomically check if a nullifier has been used and mark it if not.
   * In-memory implementation is single-threaded so this is naturally atomic.
   * Production stores (Redis, Postgres) must implement this with SETNX/INSERT ON CONFLICT.
   *
   * @param nullifier - The nullifier to check and mark
   * @param scopeId - The scope identifier
   * @returns true if the nullifier was fresh (first use), false if already used
   */
  async checkAndMarkUsed(nullifier: string, scopeId: string): Promise<boolean> {
    let scopeSet = this.used.get(scopeId);
    if (!scopeSet) {
      scopeSet = new Set();
      this.used.set(scopeId, scopeSet);
    }
    if (scopeSet.has(nullifier)) {
      return false;
    }
    scopeSet.add(nullifier);
    return true;
  }
}
