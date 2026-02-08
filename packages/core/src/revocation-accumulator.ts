import { poseidonHash } from './poseidon';
import { RevocationAccumulator, RevocationWitness } from './types';

const DEFAULT_TREE_DEPTH = 10;
const MAX_TREE_DEPTH = 20;

/**
 * In-memory Merkle revocation accumulator (demo scaffold).
 *
 * This builds the full tree on each query and is not optimized.
 * Do not use as-is in production.
 */
export class InMemoryMerkleRevocationAccumulator implements RevocationAccumulator {
  private leaves: bigint[] = [];
  private indexByCommitment = new Map<string, number>();
  private depth: number;

  constructor(depth: number = DEFAULT_TREE_DEPTH) {
    if (depth < 1 || depth > MAX_TREE_DEPTH) {
      throw new Error(`Invalid Merkle depth ${depth}. Use 1..${MAX_TREE_DEPTH}.`);
    }
    this.depth = depth;
  }

  async getRoot(): Promise<string> {
    const layers = await this.buildLayers();
    return layers[layers.length - 1][0].toString();
  }

  async isRevoked(commitment: string): Promise<boolean> {
    return this.indexByCommitment.has(commitment);
  }

  async revoke(commitment: string): Promise<void> {
    if (this.indexByCommitment.has(commitment)) {
      return;
    }

    const maxLeaves = 1 << this.depth;
    if (this.leaves.length >= maxLeaves) {
      throw new Error('Revocation tree is full for configured depth.');
    }

    const leaf = BigInt(commitment);
    this.indexByCommitment.set(commitment, this.leaves.length);
    this.leaves.push(leaf);
  }

  async getWitness(commitment: string): Promise<RevocationWitness | null> {
    const index = this.indexByCommitment.get(commitment);
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
}
