/**
 * Browser wallet for zk-id credential management and proof generation.
 *
 * Provides persistent credential storage via a pluggable `CredentialStore`
 * (IndexedDB for browsers, in-memory for testing/Node.js) and implements
 * the `WalletConnector` interface so it can be used directly with `ZkIdClient`.
 */

import {
  ProofRequest,
  ProofResponse,
  Credential,
  SignedCredential,
  RevocationWitness,
  generateAgeProof,
  generateNationalityProof,
  generateAgeProofRevocable,
} from '@zk-id/core';
import type { WalletConnector } from './client';

// ---------------------------------------------------------------------------
// CredentialStore interface
// ---------------------------------------------------------------------------

/**
 * Pluggable persistent storage for signed credentials.
 *
 * - `IndexedDBCredentialStore` for real browsers.
 * - `InMemoryCredentialStore` for testing and server-side Node.js.
 */
export interface CredentialStore {
  /** Retrieve a credential by ID. */
  get(id: string): Promise<SignedCredential | null>;
  /** Return all stored credentials. */
  getAll(): Promise<SignedCredential[]>;
  /** Store or overwrite a credential. */
  put(credential: SignedCredential): Promise<void>;
  /** Delete a credential by ID. */
  delete(id: string): Promise<void>;
  /** Remove all credentials. */
  clear(): Promise<void>;
}

// ---------------------------------------------------------------------------
// InMemoryCredentialStore
// ---------------------------------------------------------------------------

/**
 * In-memory credential store for testing and Node.js environments.
 */
export class InMemoryCredentialStore implements CredentialStore {
  private store = new Map<string, SignedCredential>();

  async get(id: string): Promise<SignedCredential | null> {
    return this.store.get(id) ?? null;
  }

  async getAll(): Promise<SignedCredential[]> {
    return Array.from(this.store.values());
  }

  async put(credential: SignedCredential): Promise<void> {
    this.store.set(credential.credential.id, credential);
  }

  async delete(id: string): Promise<void> {
    this.store.delete(id);
  }

  async clear(): Promise<void> {
    this.store.clear();
  }
}

// ---------------------------------------------------------------------------
// IndexedDBCredentialStore
// ---------------------------------------------------------------------------

const IDB_DEFAULT_DB = 'zk-id-wallet';
const IDB_DEFAULT_STORE = 'credentials';
const IDB_VERSION = 1;

export interface IndexedDBCredentialStoreOptions {
  /** Database name (default: "zk-id-wallet") */
  dbName?: string;
  /** Object store name (default: "credentials") */
  storeName?: string;
}

/**
 * IndexedDB-backed credential store for browsers.
 *
 * Credentials are stored as JSON objects keyed by `credential.id`.
 * The store is created lazily on first access.
 */
export class IndexedDBCredentialStore implements CredentialStore {
  private readonly dbName: string;
  private readonly storeName: string;
  private dbPromise: Promise<IDBDatabase> | null = null;

  constructor(options: IndexedDBCredentialStoreOptions = {}) {
    this.dbName = options.dbName ?? IDB_DEFAULT_DB;
    this.storeName = options.storeName ?? IDB_DEFAULT_STORE;
  }

  private openDB(): Promise<IDBDatabase> {
    if (this.dbPromise) return this.dbPromise;

    this.dbPromise = new Promise<IDBDatabase>((resolve, reject) => {
      const request = indexedDB.open(this.dbName, IDB_VERSION);

      request.onupgradeneeded = () => {
        const db = request.result;
        if (!db.objectStoreNames.contains(this.storeName)) {
          db.createObjectStore(this.storeName, { keyPath: 'credential.id' });
        }
      };

      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error);
    });

    return this.dbPromise;
  }

  async get(id: string): Promise<SignedCredential | null> {
    const db = await this.openDB();
    return new Promise((resolve, reject) => {
      const tx = db.transaction(this.storeName, 'readonly');
      const store = tx.objectStore(this.storeName);
      const request = store.get(id);
      request.onsuccess = () => resolve(request.result ?? null);
      request.onerror = () => reject(request.error);
    });
  }

  async getAll(): Promise<SignedCredential[]> {
    const db = await this.openDB();
    return new Promise((resolve, reject) => {
      const tx = db.transaction(this.storeName, 'readonly');
      const store = tx.objectStore(this.storeName);
      const request = store.getAll();
      request.onsuccess = () => resolve(request.result ?? []);
      request.onerror = () => reject(request.error);
    });
  }

  async put(credential: SignedCredential): Promise<void> {
    const db = await this.openDB();
    return new Promise((resolve, reject) => {
      const tx = db.transaction(this.storeName, 'readwrite');
      const store = tx.objectStore(this.storeName);
      const request = store.put(credential);
      request.onsuccess = () => resolve();
      request.onerror = () => reject(request.error);
    });
  }

  async delete(id: string): Promise<void> {
    const db = await this.openDB();
    return new Promise((resolve, reject) => {
      const tx = db.transaction(this.storeName, 'readwrite');
      const store = tx.objectStore(this.storeName);
      const request = store.delete(id);
      request.onsuccess = () => resolve();
      request.onerror = () => reject(request.error);
    });
  }

  async clear(): Promise<void> {
    const db = await this.openDB();
    return new Promise((resolve, reject) => {
      const tx = db.transaction(this.storeName, 'readwrite');
      const store = tx.objectStore(this.storeName);
      const request = store.clear();
      request.onsuccess = () => resolve();
      request.onerror = () => reject(request.error);
    });
  }
}

// ---------------------------------------------------------------------------
// BrowserWallet
// ---------------------------------------------------------------------------

export interface BrowserWalletConfig {
  /** Persistent credential storage backend. */
  credentialStore: CredentialStore;
  /** Paths to circuit WASM and zkey artifacts for proof generation. */
  circuitPaths: {
    ageWasm: string;
    ageZkey: string;
    nationalityWasm?: string;
    nationalityZkey?: string;
    ageRevocableWasm?: string;
    ageRevocableZkey?: string;
  };
  /**
   * Optional endpoint for fetching the current revocation root.
   * Required for revocable proofs.
   */
  revocationRootEndpoint?: string;
  /**
   * Optional callback invoked when a site requests a proof.
   * Receives the proof request and the list of eligible credentials.
   * Should return the credential ID to use, or null to reject.
   *
   * If not provided, the wallet auto-selects the most recently issued credential.
   */
  onProofRequest?: (
    request: ProofRequest,
    credentials: SignedCredential[],
  ) => Promise<string | null>;
}

/**
 * Browser-based credential wallet implementing `WalletConnector`.
 *
 * Manages credential lifecycle (add, remove, list, export, import) and
 * generates zero-knowledge proofs locally without revealing private data.
 *
 * ```ts
 * const store = new InMemoryCredentialStore(); // or IndexedDBCredentialStore
 * const wallet = new BrowserWallet({
 *   credentialStore: store,
 *   circuitPaths: {
 *     ageWasm: '/circuits/age-verify.wasm',
 *     ageZkey: '/circuits/age-verify.zkey',
 *   },
 * });
 *
 * await wallet.addCredential(signedCredential);
 * const client = new ZkIdClient({
 *   verificationEndpoint: '/api/verify',
 *   walletConnector: wallet,
 * });
 * ```
 */
export class BrowserWallet implements WalletConnector {
  private readonly config: BrowserWalletConfig;

  constructor(config: BrowserWalletConfig) {
    this.config = config;
  }

  // -- WalletConnector interface ---------------------------------------------

  async isAvailable(): Promise<boolean> {
    return true;
  }

  async requestProof(request: ProofRequest): Promise<ProofResponse> {
    const credentials = await this.config.credentialStore.getAll();
    if (credentials.length === 0) {
      throw new Error('No credentials stored in wallet');
    }

    // Credential selection
    const selectedId = this.config.onProofRequest
      ? await this.config.onProofRequest(request, credentials)
      : this.autoSelectCredential(credentials);

    if (selectedId === null) {
      throw new Error('Proof request was rejected by user');
    }

    const signedCredential = credentials.find((c) => c.credential.id === selectedId);
    if (!signedCredential) {
      throw new Error(`Credential ${selectedId} not found in wallet`);
    }

    const credential = signedCredential.credential;
    const timestampMs = Date.parse(request.timestamp);

    if (request.claimType === 'age') {
      if (!request.minAge) {
        throw new Error('minAge is required for age proof');
      }
      const proof = await generateAgeProof(
        credential,
        request.minAge,
        request.nonce,
        timestampMs,
        this.config.circuitPaths.ageWasm,
        this.config.circuitPaths.ageZkey,
      );
      return {
        credentialId: credential.id,
        claimType: 'age',
        proof,
        signedCredential,
        nonce: request.nonce,
        requestTimestamp: request.timestamp,
      };
    }

    if (request.claimType === 'nationality') {
      if (!request.targetNationality) {
        throw new Error('targetNationality is required for nationality proof');
      }
      if (!this.config.circuitPaths.nationalityWasm || !this.config.circuitPaths.nationalityZkey) {
        throw new Error('Nationality circuit paths not configured');
      }
      const proof = await generateNationalityProof(
        credential,
        request.targetNationality,
        request.nonce,
        timestampMs,
        this.config.circuitPaths.nationalityWasm,
        this.config.circuitPaths.nationalityZkey,
      );
      return {
        credentialId: credential.id,
        claimType: 'nationality',
        proof,
        signedCredential,
        nonce: request.nonce,
        requestTimestamp: request.timestamp,
      };
    }

    if (request.claimType === 'age-revocable') {
      if (!request.minAge) {
        throw new Error('minAge is required for age-revocable proof');
      }
      if (
        !this.config.circuitPaths.ageRevocableWasm ||
        !this.config.circuitPaths.ageRevocableZkey
      ) {
        throw new Error('Age-revocable circuit paths not configured');
      }

      const witness = await this.fetchWitness(credential);
      const proof = await generateAgeProofRevocable(
        credential,
        request.minAge,
        request.nonce,
        timestampMs,
        witness,
        this.config.circuitPaths.ageRevocableWasm,
        this.config.circuitPaths.ageRevocableZkey,
      );
      return {
        credentialId: credential.id,
        claimType: 'age-revocable',
        proof,
        signedCredential,
        nonce: request.nonce,
        requestTimestamp: request.timestamp,
      };
    }

    throw new Error(`Unsupported claim type: ${request.claimType}`);
  }

  // -- Credential management -------------------------------------------------

  /** Store a signed credential in the wallet. */
  async addCredential(signedCredential: SignedCredential): Promise<void> {
    await this.config.credentialStore.put(signedCredential);
  }

  /** Remove a credential by ID. */
  async removeCredential(id: string): Promise<void> {
    await this.config.credentialStore.delete(id);
  }

  /** List all stored credentials. */
  async listCredentials(): Promise<SignedCredential[]> {
    return this.config.credentialStore.getAll();
  }

  /** Retrieve a single credential by ID. */
  async getCredential(id: string): Promise<SignedCredential | null> {
    return this.config.credentialStore.get(id);
  }

  /** Return the number of stored credentials. */
  async credentialCount(): Promise<number> {
    const all = await this.config.credentialStore.getAll();
    return all.length;
  }

  // -- Backup & recovery -----------------------------------------------------

  /**
   * Export a credential as a JSON string for backup.
   * The exported string can be imported on another device.
   */
  async exportCredential(id: string): Promise<string> {
    const credential = await this.config.credentialStore.get(id);
    if (!credential) {
      throw new Error(`Credential ${id} not found`);
    }
    return JSON.stringify(credential);
  }

  /**
   * Import a credential from a JSON string (e.g., from a backup).
   * Validates the structure before storing.
   */
  async importCredential(json: string): Promise<SignedCredential> {
    const parsed = JSON.parse(json) as SignedCredential;

    // Basic structural validation
    if (
      !parsed.credential ||
      !parsed.credential.id ||
      !parsed.credential.birthYear ||
      !parsed.credential.salt ||
      !parsed.credential.commitment ||
      !parsed.issuer ||
      !parsed.signature
    ) {
      throw new Error('Invalid credential format');
    }

    await this.config.credentialStore.put(parsed);
    return parsed;
  }

  /**
   * Export all credentials as a JSON string for full wallet backup.
   */
  async exportAll(): Promise<string> {
    const credentials = await this.config.credentialStore.getAll();
    return JSON.stringify(credentials);
  }

  /**
   * Import multiple credentials from a JSON array string (full wallet restore).
   */
  async importAll(json: string): Promise<number> {
    const parsed = JSON.parse(json) as SignedCredential[];
    if (!Array.isArray(parsed)) {
      throw new Error('Expected a JSON array of credentials');
    }
    for (const credential of parsed) {
      await this.config.credentialStore.put(credential);
    }
    return parsed.length;
  }

  // -- Private helpers -------------------------------------------------------

  /**
   * Auto-select the most recently issued credential.
   */
  private autoSelectCredential(credentials: SignedCredential[]): string {
    const sorted = [...credentials].sort((a, b) => {
      const timeA = Date.parse(a.issuedAt) || 0;
      const timeB = Date.parse(b.issuedAt) || 0;
      return timeB - timeA; // newest first
    });
    return sorted[0].credential.id;
  }

  /**
   * Fetch a Merkle witness for a credential from the revocation root endpoint.
   * The endpoint is expected to accept a commitment query parameter and return
   * a RevocationWitness JSON object.
   */
  private async fetchWitness(credential: Credential): Promise<RevocationWitness> {
    if (!this.config.revocationRootEndpoint) {
      throw new Error('revocationRootEndpoint is required for revocable proofs');
    }

    const witnessUrl = this.config.revocationRootEndpoint.replace(/\/root\/?$/, '/witness');
    const url = `${witnessUrl}?commitment=${encodeURIComponent(credential.commitment)}`;

    const response = await fetch(url);
    if (!response.ok) {
      throw new Error(`Failed to fetch witness: ${response.statusText}`);
    }

    return (await response.json()) as RevocationWitness;
  }
}
