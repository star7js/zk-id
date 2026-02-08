import { poseidonHash, RevocationWitness, ValidCredentialTree } from '@zk-id/core';

export interface PostgresValidCredentialTreeOptions {
  /** Merkle tree depth (default: 10) */
  depth?: number;
  /** Postgres schema name (default: public) */
  schema?: string;
  /** Table name for valid credentials (default: zkid_valid_credentials) */
  table?: string;
  /** Table name for root metadata (default: zkid_valid_root_meta) */
  metaTable?: string;
  /** Disable automatic schema initialization */
  autoInit?: boolean;
}

export interface SqlClient {
  query<T = any>(text: string, params?: any[]): Promise<{ rows: T[] }>;
}

const DEFAULT_TREE_DEPTH = 10;
const MAX_TREE_DEPTH = 20;

/**
 * Postgres-backed valid credential Merkle tree.
 *
 * Notes:
 * - Stores active commitments with stable indices.
 * - Reuses inactive indices when available.
 * - Computes Merkle root/witnesses on demand (not optimized).
 */
export class PostgresValidCredentialTree implements ValidCredentialTree {
  private client: SqlClient;
  private depth: number;
  private schema: string;
  private table: string;
  private metaTable: string;
  private initPromise?: Promise<void>;

  constructor(client: SqlClient, options: PostgresValidCredentialTreeOptions = {}) {
    this.client = client;
    this.depth = options.depth ?? DEFAULT_TREE_DEPTH;
    if (this.depth < 1 || this.depth > MAX_TREE_DEPTH) {
      throw new Error(`Invalid Merkle depth ${this.depth}. Use 1..${MAX_TREE_DEPTH}.`);
    }
    this.schema = this.validateIdentifier(options.schema ?? 'public', 'schema');
    this.table = this.validateIdentifier(options.table ?? 'zkid_valid_credentials', 'table');
    this.metaTable = this.validateIdentifier(options.metaTable ?? 'zkid_valid_root_meta', 'meta table');
    if (options.autoInit !== false) {
      this.initPromise = this.init();
    }
  }

  async init(): Promise<void> {
    const credTable = this.qualifiedTable();
    const metaTable = this.qualifiedMetaTable();

    await this.client.query(
      `CREATE TABLE IF NOT EXISTS ${credTable} (
        idx INTEGER PRIMARY KEY,
        commitment TEXT NOT NULL,
        active BOOLEAN NOT NULL DEFAULT TRUE,
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      );`
    );
    await this.client.query(
      `CREATE UNIQUE INDEX IF NOT EXISTS ${this.table}_commitment_idx ON ${credTable} (commitment);`
    );
    await this.client.query(
      `CREATE INDEX IF NOT EXISTS ${this.table}_active_idx ON ${credTable} (active);`
    );

    await this.client.query(
      `CREATE TABLE IF NOT EXISTS ${metaTable} (
        id INTEGER PRIMARY KEY,
        version BIGINT NOT NULL,
        updated_at TIMESTAMPTZ NOT NULL,
        depth INTEGER NOT NULL
      );`
    );
    await this.client.query(
      `INSERT INTO ${metaTable} (id, version, updated_at, depth)
       VALUES (1, 0, NOW(), $1)
       ON CONFLICT (id) DO NOTHING;`,
      [this.depth]
    );

    const { rows } = await this.client.query<{ depth: number }>(
      `SELECT depth FROM ${metaTable} WHERE id = 1;`
    );
    const storedDepth = rows[0]?.depth;
    if (storedDepth !== undefined && storedDepth !== this.depth) {
      throw new Error(
        `Merkle depth mismatch: configured=${this.depth}, stored=${storedDepth}`
      );
    }
  }

  async add(commitment: string): Promise<void> {
    await this.ensureInit();
    const normalized = this.normalizeCommitment(commitment);
    const maxLeaves = 1 << this.depth;

    await this.client.query('BEGIN');
    try {
      const existing = await this.client.query<{ idx: number; active: boolean }>(
        `SELECT idx, active FROM ${this.qualifiedTable()} WHERE commitment = $1;`,
        [normalized]
      );
      if (existing.rows.length > 0) {
        const row = existing.rows[0];
        if (!row.active) {
          await this.client.query(
            `UPDATE ${this.qualifiedTable()}
             SET active = TRUE, updated_at = NOW()
             WHERE idx = $1;`,
            [row.idx]
          );
          await this.bumpVersion();
        }
        await this.client.query('COMMIT');
        return;
      }

      const free = await this.client.query<{ idx: number }>(
        `SELECT idx FROM ${this.qualifiedTable()}
         WHERE active = FALSE
         ORDER BY idx ASC
         LIMIT 1
         FOR UPDATE SKIP LOCKED;`
      );

      if (free.rows.length > 0) {
        const idx = free.rows[0].idx;
        await this.client.query(
          `UPDATE ${this.qualifiedTable()}
           SET commitment = $1, active = TRUE, updated_at = NOW()
           WHERE idx = $2;`,
          [normalized, idx]
        );
        await this.bumpVersion();
        await this.client.query('COMMIT');
        return;
      }

      const { rows: maxRows } = await this.client.query<{ max_idx: number }>(
        `SELECT COALESCE(MAX(idx), -1) AS max_idx FROM ${this.qualifiedTable()};`
      );
      const nextIdx = (maxRows[0]?.max_idx ?? -1) + 1;
      if (nextIdx >= maxLeaves) {
        throw new Error('Valid credential tree is full for configured depth.');
      }

      await this.client.query(
        `INSERT INTO ${this.qualifiedTable()} (idx, commitment, active, updated_at)
         VALUES ($1, $2, TRUE, NOW());`,
        [nextIdx, normalized]
      );
      await this.bumpVersion();
      await this.client.query('COMMIT');
    } catch (error) {
      await this.client.query('ROLLBACK');
      throw error;
    }
  }

  async remove(commitment: string): Promise<void> {
    await this.ensureInit();
    const normalized = this.normalizeCommitment(commitment);

    await this.client.query('BEGIN');
    try {
      const { rows } = await this.client.query<{ idx: number; active: boolean }>(
        `SELECT idx, active FROM ${this.qualifiedTable()} WHERE commitment = $1;`,
        [normalized]
      );
      if (rows.length === 0 || !rows[0].active) {
        await this.client.query('COMMIT');
        return;
      }

      await this.client.query(
        `UPDATE ${this.qualifiedTable()}
         SET active = FALSE, updated_at = NOW()
         WHERE idx = $1;`,
        [rows[0].idx]
      );
      await this.bumpVersion();
      await this.client.query('COMMIT');
    } catch (error) {
      await this.client.query('ROLLBACK');
      throw error;
    }
  }

  async contains(commitment: string): Promise<boolean> {
    await this.ensureInit();
    const normalized = this.normalizeCommitment(commitment);
    const { rows } = await this.client.query<{ exists: boolean }>(
      `SELECT EXISTS(
         SELECT 1 FROM ${this.qualifiedTable()}
         WHERE commitment = $1 AND active = TRUE
       ) AS exists;`,
      [normalized]
    );
    return rows[0]?.exists ?? false;
  }

  async getRoot(): Promise<string> {
    await this.ensureInit();
    const layers = await this.buildLayers();
    return layers[layers.length - 1][0].toString();
  }

  async getRootInfo(): Promise<{ root: string; version: number; updatedAt: string }> {
    await this.ensureInit();
    const root = await this.getRoot();
    const { rows } = await this.client.query<{ version: string; updated_at: string }>(
      `SELECT version, updated_at FROM ${this.qualifiedMetaTable()} WHERE id = 1;`
    );
    const version = rows[0]?.version ? Number(rows[0].version) : 0;
    const updatedAt = rows[0]?.updated_at
      ? new Date(rows[0].updated_at).toISOString()
      : new Date().toISOString();
    return { root, version, updatedAt };
  }

  async getWitness(commitment: string): Promise<RevocationWitness | null> {
    await this.ensureInit();
    const normalized = this.normalizeCommitment(commitment);
    const { rows } = await this.client.query<{ idx: number }>(
      `SELECT idx FROM ${this.qualifiedTable()}
       WHERE commitment = $1 AND active = TRUE;`,
      [normalized]
    );
    if (rows.length === 0) {
      return null;
    }

    const index = rows[0].idx;
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
    await this.ensureInit();
    const { rows } = await this.client.query<{ count: string }>(
      `SELECT COUNT(*) AS count FROM ${this.qualifiedTable()} WHERE active = TRUE;`
    );
    return Number(rows[0]?.count ?? 0);
  }

  private async ensureInit(): Promise<void> {
    if (!this.initPromise) {
      this.initPromise = this.init();
    }
    await this.initPromise;
  }

  private async buildLayers(): Promise<bigint[][]> {
    const totalLeaves = 1 << this.depth;
    const baseLayer: bigint[] = Array.from({ length: totalLeaves }, () => 0n);
    const { rows } = await this.client.query<{ idx: number; commitment: string }>(
      `SELECT idx, commitment FROM ${this.qualifiedTable()} WHERE active = TRUE;`
    );
    for (const row of rows) {
      if (row.idx >= 0 && row.idx < totalLeaves) {
        baseLayer[row.idx] = BigInt(row.commitment);
      }
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

  private async bumpVersion(): Promise<void> {
    await this.client.query(
      `UPDATE ${this.qualifiedMetaTable()}
       SET version = version + 1, updated_at = NOW()
       WHERE id = 1;`
    );
  }

  private normalizeCommitment(commitment: string): string {
    try {
      return BigInt(commitment).toString();
    } catch {
      throw new Error('Invalid commitment format');
    }
  }

  private qualifiedTable(): string {
    return `${this.schema}.${this.table}`;
  }

  private qualifiedMetaTable(): string {
    return `${this.schema}.${this.metaTable}`;
  }

  private validateIdentifier(value: string, label: string): string {
    if (!/^[a-zA-Z_][a-zA-Z0-9_]*$/.test(value)) {
      throw new Error(`Invalid ${label} identifier: ${value}`);
    }
    return value;
  }
}
