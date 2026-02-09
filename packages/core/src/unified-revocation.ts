/**
 * Unified Revocation Manager
 *
 * Resolves the dual-model problem where RevocationStore (blacklist) and
 * ValidCredentialTree (whitelist) could get out of sync. This manager
 * coordinates both stores so that:
 *
 *   - Issuing adds to the valid-set (whitelist)
 *   - Revoking removes from the valid-set AND records in the blacklist
 *   - Status checks are consistent regardless of which model is queried
 *
 * The ValidCredentialTree is the source of truth for ZK proofs (Merkle
 * inclusion). The RevocationStore serves as a fast lookup cache and
 * audit trail of revocation events.
 */

import { RevocationStore, ValidCredentialTree, RevocationWitness, RevocationRootInfo } from './types';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface UnifiedRevocationConfig {
  /** The Merkle-tree valid-set (source of truth for ZK proofs). */
  validTree: ValidCredentialTree;
  /** Optional blacklist store for fast lookup and audit trail. */
  revocationStore?: RevocationStore;
}

// ---------------------------------------------------------------------------
// Unified Manager
// ---------------------------------------------------------------------------

/**
 * Coordinates revocation across both the valid-credential tree (whitelist)
 * and the revocation store (blacklist), ensuring they stay in sync.
 *
 * ```ts
 * const manager = new UnifiedRevocationManager({
 *   validTree: new InMemoryValidCredentialTree(10),
 *   revocationStore: new InMemoryRevocationStore(), // optional
 * });
 *
 * await manager.addCredential(commitment);    // adds to tree
 * await manager.revokeCredential(commitment); // removes from tree + adds to blacklist
 * await manager.isRevoked(commitment);        // true (checks tree membership)
 * ```
 */
export class UnifiedRevocationManager {
  private readonly validTree: ValidCredentialTree;
  private readonly revocationStore?: RevocationStore;

  constructor(config: UnifiedRevocationConfig) {
    this.validTree = config.validTree;
    this.revocationStore = config.revocationStore;
  }

  // -----------------------------------------------------------------------
  // Credential lifecycle
  // -----------------------------------------------------------------------

  /**
   * Register a credential as valid (adds to Merkle tree).
   * Call this when issuing a new credential.
   */
  async addCredential(commitment: string): Promise<void> {
    await this.validTree.add(commitment);
  }

  /**
   * Revoke a credential.
   *
   * 1. Removes from the valid-credential tree (invalidates Merkle proofs)
   * 2. Records in the revocation store (fast lookup + audit trail)
   *
   * After revocation, any existing Merkle witnesses become stale and
   * proofs using the old root will fail the root freshness check.
   */
  async revokeCredential(commitment: string): Promise<void> {
    // Remove from whitelist first (source of truth for ZK proofs)
    await this.validTree.remove(commitment);

    // Record in blacklist for fast lookup
    if (this.revocationStore) {
      await this.revocationStore.revoke(commitment);
    }
  }

  /**
   * Check if a credential has been revoked.
   *
   * Uses the valid-credential tree (whitelist) as the source of truth:
   * a credential is revoked if it's NOT in the valid set.
   *
   * Falls back to the revocation store if the tree doesn't contain
   * the credential (could be revoked or never issued).
   */
  async isRevoked(commitment: string): Promise<boolean> {
    const inTree = await this.validTree.contains(commitment);
    if (inTree) {
      return false; // In valid set → not revoked
    }

    // Not in tree. Could be revoked or never issued.
    // Check blacklist for explicit revocation record.
    if (this.revocationStore) {
      return this.revocationStore.isRevoked(commitment);
    }

    // No blacklist configured; absence from tree = revoked
    return true;
  }

  /**
   * Re-activate a previously revoked credential.
   * Adds back to the valid-credential tree.
   */
  async reactivateCredential(commitment: string): Promise<void> {
    await this.validTree.add(commitment);
    // Note: we intentionally do NOT remove from RevocationStore
    // to preserve the audit trail of the revocation event.
  }

  // -----------------------------------------------------------------------
  // Tree accessors (delegate to ValidCredentialTree)
  // -----------------------------------------------------------------------

  /** Check if a credential is in the valid set. */
  async isValid(commitment: string): Promise<boolean> {
    return this.validTree.contains(commitment);
  }

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

  /** Get the number of valid credentials. */
  async validCount(): Promise<number> {
    return this.validTree.size();
  }

  /** Get the number of explicitly revoked credentials (blacklist). */
  async revokedCount(): Promise<number> {
    if (this.revocationStore) {
      return this.revocationStore.getRevokedCount();
    }
    return 0;
  }
}
