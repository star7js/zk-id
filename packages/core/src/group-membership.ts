/**
 * Group membership layer.
 *
 * Enables proving membership in arbitrary groups (student body, alumni, veterans,
 * employees) by leveraging the existing Merkle tree infrastructure. A "group" is
 * a named Merkle tree of credential commitments. The existing age-verify-revocable
 * circuit can be reused to prove group membership via Merkle inclusion.
 *
 * Key insight: Group membership proof reuses the same pattern as revocation --
 * the credential commitment is a leaf in the group's Merkle tree, and the Merkle
 * root is the group identifier. No new circuits needed.
 */

import { InMemoryValidCredentialTree } from './valid-credential-tree';
import { ValidCredentialTree, RevocationWitness } from './types';
import { ZkIdValidationError } from './errors';

// ---------------------------------------------------------------------------
// Group Types
// ---------------------------------------------------------------------------

/**
 * A named group of credentials.
 */
export interface Group {
  /** Unique identifier for the group */
  id: string;
  /** Human-readable name */
  name: string;
  /** Description of the group */
  description: string;
  /** Underlying Merkle tree of member commitments */
  tree: ValidCredentialTree;
}

// ---------------------------------------------------------------------------
// Group Registry
// ---------------------------------------------------------------------------

/**
 * Registry for managing credential groups.
 *
 * Each group maintains its own Merkle tree of member commitments. Applications
 * can use the Merkle root as the group identifier and generate membership proofs
 * using the existing revocable proof circuits.
 */
export class GroupRegistry {
  private groups = new Map<string, Group>();

  /**
   * Create a new group.
   *
   * @param id - Unique identifier for the group
   * @param name - Human-readable name
   * @param description - Description of the group
   * @param treeDepth - Merkle tree depth (default: 10, max capacity: 1024 members)
   * @returns The created group
   * @throws ZkIdValidationError if group ID already exists
   */
  createGroup(
    id: string,
    name: string,
    description: string,
    treeDepth: number = 10,
  ): Group {
    if (this.groups.has(id)) {
      throw new ZkIdValidationError(`Group with id '${id}' already exists`, 'groupId');
    }

    if (!id || id.length === 0) {
      throw new ZkIdValidationError('Group id must be a non-empty string', 'groupId');
    }

    if (!name || name.length === 0) {
      throw new ZkIdValidationError('Group name must be a non-empty string', 'name');
    }

    const tree = new InMemoryValidCredentialTree(treeDepth);
    const group: Group = {
      id,
      name,
      description,
      tree,
    };

    this.groups.set(id, group);
    return group;
  }

  /**
   * Add a member to a group.
   *
   * @param groupId - Group identifier
   * @param commitment - Credential commitment to add
   * @throws ZkIdValidationError if group does not exist
   */
  async addMember(groupId: string, commitment: string): Promise<void> {
    const group = this.getGroup(groupId);
    if (!group) {
      throw new ZkIdValidationError(`Group '${groupId}' not found`, 'groupId');
    }

    await group.tree.add(commitment);
  }

  /**
   * Remove a member from a group.
   *
   * @param groupId - Group identifier
   * @param commitment - Credential commitment to remove
   * @throws ZkIdValidationError if group does not exist
   */
  async removeMember(groupId: string, commitment: string): Promise<void> {
    const group = this.getGroup(groupId);
    if (!group) {
      throw new ZkIdValidationError(`Group '${groupId}' not found`, 'groupId');
    }

    await group.tree.remove(commitment);
  }

  /**
   * Check if a credential is a member of a group.
   *
   * @param groupId - Group identifier
   * @param commitment - Credential commitment to check
   * @returns true if the credential is in the group
   * @throws ZkIdValidationError if group does not exist
   */
  async isMember(groupId: string, commitment: string): Promise<boolean> {
    const group = this.getGroup(groupId);
    if (!group) {
      throw new ZkIdValidationError(`Group '${groupId}' not found`, 'groupId');
    }

    return group.tree.contains(commitment);
  }

  /**
   * Get a membership witness (Merkle proof) for a credential in a group.
   *
   * The witness can be used with the age-verify-revocable circuit to prove
   * group membership in zero knowledge.
   *
   * @param groupId - Group identifier
   * @param commitment - Credential commitment
   * @returns Merkle witness, or null if not a member
   * @throws ZkIdValidationError if group does not exist
   */
  async getMembershipWitness(
    groupId: string,
    commitment: string,
  ): Promise<RevocationWitness | null> {
    const group = this.getGroup(groupId);
    if (!group) {
      throw new ZkIdValidationError(`Group '${groupId}' not found`, 'groupId');
    }

    return group.tree.getWitness(commitment);
  }

  /**
   * Get the Merkle root of a group's tree.
   *
   * The root serves as the group identifier in zero-knowledge proofs.
   *
   * @param groupId - Group identifier
   * @returns Merkle root as hex string
   * @throws ZkIdValidationError if group does not exist
   */
  async getGroupRoot(groupId: string): Promise<string> {
    const group = this.getGroup(groupId);
    if (!group) {
      throw new ZkIdValidationError(`Group '${groupId}' not found`, 'groupId');
    }

    return group.tree.getRoot();
  }

  /**
   * List all groups.
   *
   * @returns Array of all groups
   */
  listGroups(): Group[] {
    return Array.from(this.groups.values());
  }

  /**
   * Get a group by ID.
   *
   * @param groupId - Group identifier
   * @returns The group, or undefined if not found
   */
  getGroup(groupId: string): Group | undefined {
    return this.groups.get(groupId);
  }
}
