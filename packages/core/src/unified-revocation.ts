/**
 * Unified Revocation Manager
 *
 * Single entry-point for credential lifecycle management. Uses two
 * cleanly separated stores:
 *
 *   1. ValidCredentialTree (Merkle tree) — source of truth for ZK proofs.
 *      "In tree" = valid. Removals invalidate Merkle witnesses.
 *
 *   2. IssuedCredentialIndex (append-only set) — records every commitment
 *      that was ever issued. Never deleted from. Lets us distinguish
 *      "revoked" (was issued, removed from tree) from "never issued".
 *
 * The old RevocationStore (blacklist) is no longer used here. It remains
 * available as a standalone component for consumers that need it.
 */

import {
  ValidCredentialTree,
  RevocationWitness,
  RevocationRootInfo,
  IssuedCredentialIndex,
} from './types';

// ---------------------------------------------------------------------------
// In-memory IssuedCredentialIndex
// ---------------------------------------------------------------------------

/**
 * Simple append-only set tracking which commitments were ever issued.
 * Production deployments should use a persistent store (Postgres, Redis, etc.).
 */
export class InMemoryIssuedCredentialIndex implements IssuedCredentialIndex {
  private readonly issued = new Set<string>();

  private normalizeCommitment(commitment: string): string {
    try {
      return BigInt(commitment).toString();
    } catch {
      throw new Error('Invalid commitment format');
    }
  }

  async record(commitment: string): Promise<void> {
    this.issued.add(this.normalizeCommitment(commitment));
  }

  async wasIssued(commitment: string): Promise<boolean> {
    return this.issued.has(this.normalizeCommitment(commitment));
  }

  async issuedCount(): Promise<number> {
    return this.issued.size;
  }
}

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface UnifiedRevocationConfig {
  /** The Merkle-tree valid-set (source of truth for ZK proofs). */
  validTree: ValidCredentialTree;
  /** Append-only index of issued credentials (distinguishes revoked from never-issued). */
  issuedIndex?: IssuedCredentialIndex;
}

/** Credential status as determined by the unified manager. */
export type CredentialStatus = 'valid' | 'revoked' | 'unknown';

// ---------------------------------------------------------------------------
// Unified Manager
// ---------------------------------------------------------------------------

/**
 * Manages the full credential lifecycle through a single API.
 *
 * ```ts
 * const manager = new UnifiedRevocationManager({
 *   validTree: new InMemoryValidCredentialTree(10),
 *   issuedIndex: new InMemoryIssuedCredentialIndex(),
 * });
 *
 * await manager.addCredential(commitment);    // tree + issued index
 * await manager.revokeCredential(commitment); // removes from tree
 * await manager.getStatus(commitment);        // 'revoked'
 * ```
 */
export class UnifiedRevocationManager {
  private readonly validTree: ValidCredentialTree;
  private readonly issuedIndex?: IssuedCredentialIndex;

  constructor(config: UnifiedRevocationConfig) {
    this.validTree = config.validTree;
    this.issuedIndex = config.issuedIndex;
  }

  // -----------------------------------------------------------------------
  // Credential lifecycle
  // -----------------------------------------------------------------------

  /**
   * Issue a credential: adds to the Merkle tree and records in the
   * issued-credential index.
   */
  async addCredential(commitment: string): Promise<void> {
    await this.validTree.add(commitment);
    if (this.issuedIndex) {
      await this.issuedIndex.record(commitment);
    }
  }

  /**
   * Revoke a credential by removing it from the Merkle tree.
   *
   * After revocation any existing Merkle witnesses become stale and
   * proofs using the old root will fail the freshness check.
   *
   * The issued-credential index is NOT modified (append-only) so the
   * commitment can still be recognized as "was issued, now revoked".
   */
  async revokeCredential(commitment: string): Promise<void> {
    await this.validTree.remove(commitment);
  }

  /**
   * Re-activate a previously revoked credential by adding it back
   * to the Merkle tree.
   */
  async reactivateCredential(commitment: string): Promise<void> {
    await this.validTree.add(commitment);
  }

  // -----------------------------------------------------------------------
  // Status queries
  // -----------------------------------------------------------------------

  /**
   * Get the precise status of a credential:
   *   - `'valid'`   — in the Merkle tree (can generate inclusion proofs)
   *   - `'revoked'` — was issued but no longer in the tree
   *   - `'unknown'` — never recorded in the issued index
   *
   * Without an issued index, absent credentials are reported as `'unknown'`.
   */
  async getStatus(commitment: string): Promise<CredentialStatus> {
    if (await this.validTree.contains(commitment)) {
      return 'valid';
    }
    if (this.issuedIndex && (await this.issuedIndex.wasIssued(commitment))) {
      return 'revoked';
    }
    return 'unknown';
  }

  /** Check if a credential is currently in the valid set. */
  async isValid(commitment: string): Promise<boolean> {
    return this.validTree.contains(commitment);
  }

  /**
   * Check if a credential has been revoked.
   *
   * Returns `true` only when the credential was issued (recorded in the
   * issued index) but is no longer in the Merkle tree. Returns `false`
   * for valid credentials AND for unknown commitments.
   */
  async isRevoked(commitment: string): Promise<boolean> {
    return (await this.getStatus(commitment)) === 'revoked';
  }

  // -----------------------------------------------------------------------
  // Tree accessors (delegate to ValidCredentialTree)
  // -----------------------------------------------------------------------

  /** Get the current Merkle root. */
  async getRoot(): Promise<string> {
    return this.validTree.getRoot();
  }

  /** Get Merkle root with version metadata. */
  async getRootInfo(): Promise<RevocationRootInfo | null> {
    if (this.validTree.getRootInfo) {
      return this.validTree.getRootInfo();
    }
    return null;
  }

  /** Generate a Merkle witness for a credential. */
  async getWitness(commitment: string): Promise<RevocationWitness | null> {
    return this.validTree.getWitness(commitment);
  }

  /** Number of currently valid credentials (in the tree). */
  async validCount(): Promise<number> {
    return this.validTree.size();
  }

  /** Number of credentials ever issued (if issued index is configured). */
  async issuedCount(): Promise<number> {
    if (this.issuedIndex) {
      return this.issuedIndex.issuedCount();
    }
    return 0;
  }
}
