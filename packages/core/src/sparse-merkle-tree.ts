/**
 * Sparse Merkle Tree
 *
 * A memory-efficient Merkle tree that only stores occupied nodes.
 * Unlike the dense InMemoryValidCredentialTree which pre-allocates all
 * 2^depth leaf slots, this tree stores O(n × depth) nodes where n is
 * the number of non-empty leaves.
 *
 * Key advantages over the dense tree:
 *
 *   1. Hash-addressed leaves — leaf position = hash(commitment) mod 2^depth,
 *      making positions deterministic and reproducible across nodes.
 *
 *   2. No capacity pre-allocation — memory grows with actual usage.
 *
 *   3. Non-membership proofs — can prove a commitment is NOT in the tree
 *      by showing the leaf at its computed position is empty.
 *
 * The tree implements ValidCredentialTree so it's a drop-in replacement
 * for the dense tree in UnifiedRevocationManager and elsewhere.
 */

import { poseidonHash } from './poseidon';
import { ValidCredentialTree, RevocationWitness, RevocationRootInfo } from './types';
import { ZkIdConfigError, ZkIdValidationError, ZkIdCryptoError } from './errors';

const DEFAULT_SMT_DEPTH = 20;
const MAX_SMT_DEPTH = 254; // BN128 field ≈ 254 bits

/**
 * Sparse Merkle tree implementation.
 *
 * ```ts
 * const tree = new SparseMerkleTree(20);
 * await tree.add(commitment);
 * const witness = await tree.getWitness(commitment);         // membership
 * const absent  = await tree.getNonMembershipWitness(other);  // non-membership
 * ```
 */
export class SparseMerkleTree implements ValidCredentialTree {
  /** Sparse node storage: "level:index" → hash value */
  private nodes = new Map<string, bigint>();
  /** Tracks which commitments are in the tree and their leaf indices */
  private commitments = new Map<string, bigint>();
  private readonly depth: number;
  private zeroHashes: bigint[] = [];
  private rootVersion = 0;
  private updatedAt = new Date().toISOString();
  private ready: Promise<void>;

  constructor(depth: number = DEFAULT_SMT_DEPTH) {
    if (depth < 1 || depth > MAX_SMT_DEPTH) {
      throw new ZkIdConfigError(`Invalid SMT depth ${depth}. Use 1..${MAX_SMT_DEPTH}.`);
    }
    this.depth = depth;
    this.ready = this.initialize();
  }

  private async initialize(): Promise<void> {
    // Pre-compute zero hashes: H(0,0), H(H(0,0), H(0,0)), etc.
    this.zeroHashes = [0n];
    for (let i = 0; i < this.depth; i++) {
      const prev = this.zeroHashes[i];
      this.zeroHashes.push(await poseidonHash([prev, prev]));
    }
  }

  private async ensureReady(): Promise<void> {
    await this.ready;
  }

  // ---------------------------------------------------------------------------
  // Sparse node access
  // ---------------------------------------------------------------------------

  private nodeKey(level: number, index: bigint): string {
    return `${level}:${index}`;
  }

  /** Read a node, falling back to the zero hash for that level. */
  private getNode(level: number, index: bigint): bigint {
    return this.nodes.get(this.nodeKey(level, index)) ?? this.zeroHashes[level];
  }

  /** Write a node. Deletes the entry when it equals the zero hash (saves memory). */
  private setNode(level: number, index: bigint, value: bigint): void {
    if (value === this.zeroHashes[level]) {
      this.nodes.delete(this.nodeKey(level, index));
    } else {
      this.nodes.set(this.nodeKey(level, index), value);
    }
  }

  // ---------------------------------------------------------------------------
  // Leaf addressing
  // ---------------------------------------------------------------------------

  /**
   * Compute the leaf index for a commitment.
   * Uses the lower `depth` bits of poseidonHash([commitment]).
   */
  private async leafIndex(commitment: bigint): Promise<bigint> {
    const hash = await poseidonHash([commitment]);
    const mask = (1n << BigInt(this.depth)) - 1n;
    return hash & mask;
  }

  private normalizeCommitment(commitment: string): string {
    try {
      return BigInt(commitment).toString();
    } catch {
      throw new ZkIdValidationError('Invalid commitment format', 'commitment');
    }
  }

  // ---------------------------------------------------------------------------
  // ValidCredentialTree interface
  // ---------------------------------------------------------------------------

  async add(commitment: string): Promise<void> {
    await this.ensureReady();
    const normalized = this.normalizeCommitment(commitment);
    if (this.commitments.has(normalized)) return; // idempotent

    const leaf = BigInt(normalized);
    const index = await this.leafIndex(leaf);

    // Check for collision: different commitment mapped to same leaf
    const existing = this.getNode(0, index);
    if (existing !== 0n && existing !== leaf) {
      throw new ZkIdCryptoError('Leaf collision in sparse Merkle tree');
    }

    this.commitments.set(normalized, index);
    this.setNode(0, index, leaf);
    await this.updatePath(index);
    this.bumpVersion();
  }

  async remove(commitment: string): Promise<void> {
    await this.ensureReady();
    const normalized = this.normalizeCommitment(commitment);
    const index = this.commitments.get(normalized);
    if (index === undefined) return; // idempotent

    this.commitments.delete(normalized);
    this.setNode(0, index, 0n); // setNode deletes when value == zeroHash
    await this.updatePath(index);
    this.bumpVersion();
  }

  async contains(commitment: string): Promise<boolean> {
    const normalized = this.normalizeCommitment(commitment);
    return this.commitments.has(normalized);
  }

  async getRoot(): Promise<string> {
    await this.ensureReady();
    return this.getNode(this.depth, 0n).toString();
  }

  async getRootInfo(): Promise<RevocationRootInfo> {
    const root = await this.getRoot();
    return { root, version: this.rootVersion, updatedAt: this.updatedAt };
  }

  async getWitness(commitment: string): Promise<RevocationWitness | null> {
    await this.ensureReady();
    const normalized = this.normalizeCommitment(commitment);
    const index = this.commitments.get(normalized);
    if (index === undefined) return null;
    return this.buildWitness(index);
  }

  async size(): Promise<number> {
    return this.commitments.size;
  }

  // ---------------------------------------------------------------------------
  // Non-membership proofs (sparse tree exclusive feature)
  // ---------------------------------------------------------------------------

  /**
   * Generate a non-membership witness proving a commitment is NOT in the tree.
   *
   * The witness shows the Merkle path to the leaf position where the
   * commitment *would* be stored. If the leaf at that position is empty
   * (zero), this proves non-membership.
   *
   * Returns `null` if the commitment IS in the tree (use getWitness instead).
   */
  async getNonMembershipWitness(commitment: string): Promise<RevocationWitness | null> {
    await this.ensureReady();
    const normalized = this.normalizeCommitment(commitment);
    if (this.commitments.has(normalized)) return null; // IS in tree

    const leaf = BigInt(normalized);
    const index = await this.leafIndex(leaf);
    if (this.getNode(0, index) !== 0n) {
      return null;
    }
    return this.buildWitness(index);
  }

  // ---------------------------------------------------------------------------
  // Tree depth accessor
  // ---------------------------------------------------------------------------

  /** Return the configured tree depth. */
  getDepth(): number {
    return this.depth;
  }

  /** Return the number of occupied nodes in sparse storage. */
  nodeCount(): number {
    return this.nodes.size;
  }

  // ---------------------------------------------------------------------------
  // Internal helpers
  // ---------------------------------------------------------------------------

  private async buildWitness(index: bigint): Promise<RevocationWitness> {
    const siblings: string[] = [];
    const pathIndices: number[] = [];
    let cursor = index;

    for (let level = 0; level < this.depth; level++) {
      const siblingIndex = cursor ^ 1n;
      siblings.push(this.getNode(level, siblingIndex).toString());
      pathIndices.push(Number(cursor & 1n));
      cursor = cursor >> 1n;
    }

    const root = this.getNode(this.depth, 0n).toString();
    return { root, pathIndices, siblings };
  }

  private async updatePath(index: bigint): Promise<void> {
    let cursor = index;
    for (let level = 0; level < this.depth; level++) {
      const parent = cursor >> 1n;
      const leftIndex = cursor & ~1n;
      const rightIndex = cursor | 1n;

      const left = this.getNode(level, leftIndex);
      const right = this.getNode(level, rightIndex);
      const hash = await poseidonHash([left, right]);

      this.setNode(level + 1, parent, hash);
      cursor = parent;
    }
  }

  private bumpVersion(): void {
    this.rootVersion += 1;
    this.updatedAt = new Date().toISOString();
  }
}
