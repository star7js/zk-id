import { poseidonHash, poseidonHashDomain, DOMAIN_MERKLE } from './poseidon';
import { ValidCredentialTree, RevocationWitness, RevocationRootInfo } from './types';
import { ZkIdConfigError, ZkIdValidationError } from './errors';

const DEFAULT_TREE_DEPTH = 10;
const MAX_TREE_DEPTH = 20;

/**
 * In-memory Merkle tree for valid credential set with incremental updates.
 *
 * Maintains cached layers and only recomputes the affected path on mutations,
 * reducing complexity from O(2^depth) per query to O(depth) per mutation
 * and O(1) per read.
 */
export class InMemoryValidCredentialTree implements ValidCredentialTree {
  private leaves: bigint[] = [];
  private indexByCommitment = new Map<string, number>();
  private freeIndices: number[] = [];
  private depth: number;
  private rootVersion = 0;
  private updatedAt = new Date().toISOString();

  // Incremental tree optimization
  private layers: bigint[][] = [];
  private zeroHashes: bigint[] = [];
  private ready: Promise<void>;

  constructor(depth: number = DEFAULT_TREE_DEPTH) {
    if (depth < 1 || depth > MAX_TREE_DEPTH) {
      throw new ZkIdConfigError(`Invalid Merkle depth ${depth}. Use 1..${MAX_TREE_DEPTH}.`);
    }
    this.depth = depth;
    this.ready = this.initialize();
    if (typeof process !== 'undefined' && process.env.NODE_ENV === 'production') {
      console.warn(
        '[zk-id] InMemoryValidCredentialTree is not suitable for production. ' +
          'The valid credential set will be lost on restart. Use a persistent tree (PostgreSQL, Redis).',
      );
    }
  }

  private async initialize(): Promise<void> {
    // Pre-compute zero hashes for empty subtrees at each level
    this.zeroHashes = [0n]; // Level 0: empty leaf
    for (let i = 0; i < this.depth; i++) {
      const prevZero = this.zeroHashes[i];
      this.zeroHashes.push(await poseidonHashDomain(DOMAIN_MERKLE, [prevZero, prevZero]));
    }

    // Initialize layers array filled with zero hashes
    const totalLeaves = 1 << this.depth;
    this.layers = [new Array(totalLeaves).fill(0n)];

    for (let level = 0; level < this.depth; level++) {
      const prevLayerSize = this.layers[level].length;
      const nextLayerSize = prevLayerSize / 2;
      this.layers.push(new Array(nextLayerSize).fill(this.zeroHashes[level + 1]));
    }
  }

  private async ensureReady(): Promise<void> {
    await this.ready;
  }

  async add(commitment: string): Promise<void> {
    await this.ensureReady();

    const normalized = this.normalizeCommitment(commitment);
    if (this.indexByCommitment.has(normalized)) {
      return;
    }

    const maxLeaves = 1 << this.depth;
    if (this.leaves.length >= maxLeaves && this.freeIndices.length === 0) {
      throw new ZkIdConfigError('Valid credential tree is full for configured depth.');
    }

    const leaf = BigInt(normalized);
    const reuseIndex = this.freeIndices.pop();
    const index = reuseIndex !== undefined ? reuseIndex : this.leaves.length;
    if (index === this.leaves.length) {
      this.leaves.push(leaf);
    } else {
      this.leaves[index] = leaf;
    }
    this.indexByCommitment.set(normalized, index);

    // Update cached layers along the path
    this.layers[0][index] = leaf;
    await this.updatePath(index);

    this.bumpVersion();
  }

  async remove(commitment: string): Promise<void> {
    await this.ensureReady();

    const normalized = this.normalizeCommitment(commitment);
    const index = this.indexByCommitment.get(normalized);
    if (index === undefined) {
      return;
    }

    this.leaves[index] = 0n;
    this.indexByCommitment.delete(normalized);
    this.freeIndices.push(index);

    // Update cached layers along the path
    this.layers[0][index] = 0n;
    await this.updatePath(index);

    this.bumpVersion();
  }

  async contains(commitment: string): Promise<boolean> {
    const normalized = this.normalizeCommitment(commitment);
    return this.indexByCommitment.has(normalized);
  }

  async getRoot(): Promise<string> {
    await this.ensureReady();
    return this.layers[this.depth][0].toString();
  }

  async getRootInfo(): Promise<RevocationRootInfo> {
    const root = await this.getRoot();
    return {
      root,
      version: this.rootVersion,
      updatedAt: this.updatedAt,
    };
  }

  async getWitness(commitment: string): Promise<RevocationWitness | null> {
    await this.ensureReady();

    const normalized = this.normalizeCommitment(commitment);
    const index = this.indexByCommitment.get(normalized);
    if (index === undefined) {
      return null;
    }

    const siblings: string[] = [];
    const pathIndices: number[] = [];
    let cursor = index;

    for (let level = 0; level < this.depth; level++) {
      const siblingIndex = cursor ^ 1;
      siblings.push(this.layers[level][siblingIndex].toString());
      pathIndices.push(cursor % 2);
      cursor = Math.floor(cursor / 2);
    }

    const root = this.layers[this.depth][0].toString();
    return { root, pathIndices, siblings };
  }

  async size(): Promise<number> {
    return this.indexByCommitment.size;
  }

  /**
   * Update the Merkle path from a leaf index to the root.
   * Only recomputes hashes along the affected path (O(depth) operations).
   */
  private async updatePath(index: number): Promise<void> {
    let cursor = index;

    for (let level = 0; level < this.depth; level++) {
      const parent = Math.floor(cursor / 2);
      const leftIndex = cursor & ~1;
      const rightIndex = cursor | 1;

      const left = this.layers[level][leftIndex];
      const right = this.layers[level][rightIndex];
      const hash = await poseidonHashDomain(DOMAIN_MERKLE, [left, right]);

      this.layers[level + 1][parent] = hash;
      cursor = parent;
    }
  }

  private normalizeCommitment(commitment: string): string {
    try {
      return BigInt(commitment).toString();
    } catch {
      throw new ZkIdValidationError('Invalid commitment format', 'commitment');
    }
  }

  private bumpVersion(): void {
    this.rootVersion += 1;
    this.updatedAt = new Date().toISOString();
  }
}
