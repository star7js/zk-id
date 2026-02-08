import { poseidonHash } from './poseidon';
import { ValidCredentialTree, RevocationWitness } from './types';

const DEFAULT_TREE_DEPTH = 10;
const MAX_TREE_DEPTH = 20;

/**
 * In-memory Merkle tree for valid credential set (demo scaffold).
 *
 * This builds the full tree on each query and is not optimized.
 * Do not use as-is in production.
 */
export class InMemoryValidCredentialTree implements ValidCredentialTree {
  private leaves: bigint[] = [];
  private indexByCommitment = new Map<string, number>();
  private freeIndices: number[] = [];
  private depth: number;
  private rootVersion = 0;
  private updatedAt = new Date().toISOString();

  constructor(depth: number = DEFAULT_TREE_DEPTH) {
    if (depth < 1 || depth > MAX_TREE_DEPTH) {
      throw new Error(`Invalid Merkle depth ${depth}. Use 1..${MAX_TREE_DEPTH}.`);
    }
    this.depth = depth;
  }

  async add(commitment: string): Promise<void> {
    const normalized = this.normalizeCommitment(commitment);
    if (this.indexByCommitment.has(normalized)) {
      return;
    }

    const maxLeaves = 1 << this.depth;
    if (this.leaves.length >= maxLeaves && this.freeIndices.length === 0) {
      throw new Error('Valid credential tree is full for configured depth.');
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
    this.bumpVersion();
  }

  async remove(commitment: string): Promise<void> {
    const normalized = this.normalizeCommitment(commitment);
    const index = this.indexByCommitment.get(normalized);
    if (index === undefined) {
      return;
    }

    this.leaves[index] = 0n;
    this.indexByCommitment.delete(normalized);
    this.freeIndices.push(index);
    this.bumpVersion();
  }

  async contains(commitment: string): Promise<boolean> {
    const normalized = this.normalizeCommitment(commitment);
    return this.indexByCommitment.has(normalized);
  }

  async getRoot(): Promise<string> {
    const layers = await this.buildLayers();
    return layers[layers.length - 1][0].toString();
  }

  async getRootInfo(): Promise<{ root: string; version: number; updatedAt: string }> {
    const root = await this.getRoot();
    return {
      root,
      version: this.rootVersion,
      updatedAt: this.updatedAt,
    };
  }

  async getWitness(commitment: string): Promise<RevocationWitness | null> {
    const normalized = this.normalizeCommitment(commitment);
    const index = this.indexByCommitment.get(normalized);
    if (index === undefined) {
      return null;
    }

    const layers = await this.buildLayers();
    const siblings: string[] = [];
    const pathIndices: number[] = [];
    let cursor = index;

    for (let level = 0; level < this.depth; level++) {
      const siblingIndex = cursor ^ 1;
      siblings.push(layers[level][siblingIndex].toString());
      pathIndices.push(cursor % 2);
      cursor = Math.floor(cursor / 2);
    }

    const root = layers[layers.length - 1][0].toString();
    return { root, pathIndices, siblings };
  }

  async size(): Promise<number> {
    return this.indexByCommitment.size;
  }

  private async buildLayers(): Promise<bigint[][]> {
    const totalLeaves = 1 << this.depth;
    const baseLayer = this.leaves.slice();
    while (baseLayer.length < totalLeaves) {
      baseLayer.push(0n);
    }

    const layers: bigint[][] = [baseLayer];
    for (let level = 0; level < this.depth; level++) {
      const prev = layers[level];
      const next: bigint[] = [];
      for (let i = 0; i < prev.length; i += 2) {
        const left = prev[i];
        const right = prev[i + 1];
        const hash = await poseidonHash([left, right]);
        next.push(hash);
      }
      layers.push(next);
    }

    return layers;
  }

  private normalizeCommitment(commitment: string): string {
    try {
      return BigInt(commitment).toString();
    } catch (error) {
      throw new Error('Invalid commitment format');
    }
  }

  private bumpVersion(): void {
    this.rootVersion += 1;
    this.updatedAt = new Date().toISOString();
  }
}
