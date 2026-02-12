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
  ZkIdCredentialError,
  ZkIdConfigError,
  ZkIdProofError,
  BBSProofResponse,
  SerializedBBSCredential,
  deserializeBBSCredential,
  deriveBBSSchemaDisclosureProof,
  SCHEMA_REGISTRY,
  serializeBBSProof,
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

/**
 * Pluggable persistent storage for BBS+ credentials.
 */
export interface BBSCredentialStore {
  /** Retrieve a BBS credential by ID. */
  get(id: string): Promise<SerializedBBSCredential | null>;
  /** Return all stored BBS credentials. */
  getAll(): Promise<SerializedBBSCredential[]>;
  /** Store or overwrite a BBS credential. */
  put(credential: SerializedBBSCredential): Promise<void>;
  /** Delete a BBS credential by ID. */
  delete(id: string): Promise<void>;
  /** Remove all BBS credentials. */
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

/**
 * In-memory BBS+ credential store for testing and Node.js environments.
 */
export class InMemoryBBSCredentialStore implements BBSCredentialStore {
  private store = new Map<string, SerializedBBSCredential>();

  async get(id: string): Promise<SerializedBBSCredential | null> {
    return this.store.get(id) ?? null;
  }

  async getAll(): Promise<SerializedBBSCredential[]> {
    return Array.from(this.store.values());
  }

  async put(credential: SerializedBBSCredential): Promise<void> {
    const id = String(credential.fields.id || `cred-${Date.now()}`);
    this.store.set(id, credential);
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
  /** Optional BBS+ credential storage backend. */
  bbsCredentialStore?: BBSCredentialStore;
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
      throw new ZkIdCredentialError('No credentials stored in wallet', 'CREDENTIAL_NOT_FOUND');
    }

    // Credential selection
    const selectedId = this.config.onProofRequest
      ? await this.config.onProofRequest(request, credentials)
      : this.autoSelectCredential(credentials);

    if (selectedId === null) {
      throw new ZkIdProofError('Proof request was rejected by user');
    }

    const signedCredential = credentials.find((c) => c.credential.id === selectedId);
    if (!signedCredential) {
      throw new ZkIdCredentialError(
        `Credential ${selectedId} not found in wallet`,
        'CREDENTIAL_NOT_FOUND',
      );
    }

    const credential = signedCredential.credential;
    const timestampMs = Date.parse(request.timestamp);

    if (request.claimType === 'age') {
      if (!request.minAge) {
        throw new ZkIdConfigError('minAge is required for age proof');
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
        throw new ZkIdConfigError('targetNationality is required for nationality proof');
      }
      if (!this.config.circuitPaths.nationalityWasm || !this.config.circuitPaths.nationalityZkey) {
        throw new ZkIdConfigError('Nationality circuit paths not configured');
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
        throw new ZkIdConfigError('minAge is required for age-revocable proof');
      }
      if (
        !this.config.circuitPaths.ageRevocableWasm ||
        !this.config.circuitPaths.ageRevocableZkey
      ) {
        throw new ZkIdConfigError('Age-revocable circuit paths not configured');
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

    throw new ZkIdProofError(`Unsupported claim type: ${request.claimType}`, 'UNKNOWN_PROOF_TYPE');
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
      throw new ZkIdCredentialError(`Credential ${id} not found`, 'CREDENTIAL_NOT_FOUND');
    }
    return JSON.stringify(credential);
  }

  /**
   * Import a credential from a JSON string (e.g., from a backup).
   * Validates the structure before storing.
   */
  async importCredential(json: string): Promise<SignedCredential> {
    let parsed: SignedCredential;
    try {
      parsed = JSON.parse(json) as SignedCredential;
    } catch (error) {
      throw new ZkIdCredentialError(
        `Failed to parse credential JSON: ${error instanceof Error ? error.message : String(error)}`,
        'INVALID_CREDENTIAL_FORMAT',
      );
    }

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
      throw new ZkIdCredentialError('Invalid credential format', 'INVALID_CREDENTIAL_FORMAT');
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
    let parsed: SignedCredential[];
    try {
      parsed = JSON.parse(json) as SignedCredential[];
    } catch (error) {
      throw new ZkIdCredentialError(
        `Failed to parse credentials JSON: ${error instanceof Error ? error.message : String(error)}`,
        'INVALID_CREDENTIAL_FORMAT',
      );
    }
    if (!Array.isArray(parsed)) {
      throw new ZkIdCredentialError(
        'Expected a JSON array of credentials',
        'INVALID_CREDENTIAL_FORMAT',
      );
    }
    for (const credential of parsed) {
      await this.config.credentialStore.put(credential);
    }
    return parsed.length;
  }

  // -- BBS+ Credential Methods -----------------------------------------------

  /**
   * Store a BBS+ credential in the wallet.
   */
  async storeBBSCredential(credential: SerializedBBSCredential): Promise<void> {
    if (!this.config.bbsCredentialStore) {
      throw new ZkIdConfigError('BBS credential store not configured');
    }
    await this.config.bbsCredentialStore.put(credential);
  }

  /**
   * Get all stored BBS+ credentials.
   */
  async getBBSCredentials(): Promise<SerializedBBSCredential[]> {
    if (!this.config.bbsCredentialStore) {
      return [];
    }
    return this.config.bbsCredentialStore.getAll();
  }

  /**
   * Generate a BBS+ selective disclosure proof.
   *
   * @param credentialId - ID of the BBS credential to use
   * @param revealedFields - Array of field names to reveal
   * @param nonce - Nonce from the verifier
   * @returns BBS proof response
   */
  async generateBBSDisclosureProof(
    credentialId: string,
    revealedFields: string[],
    nonce: string,
  ): Promise<BBSProofResponse> {
    if (!this.config.bbsCredentialStore) {
      throw new ZkIdConfigError('BBS credential store not configured');
    }

    // Get the credential
    const serialized = await this.config.bbsCredentialStore.get(credentialId);
    if (!serialized) {
      throw new ZkIdCredentialError(
        `BBS credential ${credentialId} not found`,
        'CREDENTIAL_NOT_FOUND',
      );
    }

    // Get the schema
    const schema = SCHEMA_REGISTRY.get(serialized.schemaId);
    if (!schema) {
      throw new ZkIdConfigError(`Unknown schema: ${serialized.schemaId}`);
    }

    // Deserialize the credential
    const credential = deserializeBBSCredential(serialized, schema);

    // Generate the disclosure proof
    const disclosureProof = await deriveBBSSchemaDisclosureProof(
      credential,
      schema,
      revealedFields,
      nonce,
    );

    // Extract revealed field values
    const revealedFieldValues: Record<string, unknown> = {};
    for (const fieldName of revealedFields) {
      if (serialized.fields[fieldName] !== undefined) {
        revealedFieldValues[fieldName] = serialized.fields[fieldName];
      }
    }

    // Serialize the proof using the standard format from bbs.ts
    const proofSerialized = serializeBBSProof(disclosureProof);

    return {
      credentialId,
      schemaId: serialized.schemaId,
      proof: proofSerialized,
      revealedFields: revealedFieldValues,
      nonce,
      requestTimestamp: new Date().toISOString(),
    };
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
      throw new ZkIdConfigError('revocationRootEndpoint is required for revocable proofs');
    }

    const witnessUrl = this.config.revocationRootEndpoint.replace(/\/root\/?$/, '/witness');
    const url = `${witnessUrl}?commitment=${encodeURIComponent(credential.commitment)}`;

    const response = await fetch(url);
    if (!response.ok) {
      throw new ZkIdProofError(`Failed to fetch witness: ${response.statusText}`);
    }

    return (await response.json()) as RevocationWitness;
  }
}

/**
 * OpenID4VP Wallet Adapter
 *
 * Extends BrowserWallet to support OpenID4VP (OpenID for Verifiable Presentations)
 * authorization requests and presentation generation.
 *
 * This enables zk-id wallets to interoperate with standard OpenID4VP verifiers.
 */

import { v4 as uuidv4 } from 'uuid';
import type {
  AuthorizationRequest,
  PresentationSubmission,
  PresentationResponse,
  InputDescriptor,
} from './server';

export interface OpenID4VPWalletConfig extends BrowserWalletConfig {
  /** Wallet identifier (DID or URL) */
  walletId?: string;
}

export class OpenID4VPWallet extends BrowserWallet {
  private walletId: string;

  constructor(config: OpenID4VPWalletConfig) {
    super(config);
    this.walletId = config.walletId || 'zk-id-wallet';
  }

  /**
   * Parse an OpenID4VP authorization request URL
   *
   * @param authRequestUrl - Authorization request URL or object
   * @returns Parsed authorization request
   */
  parseAuthorizationRequest(authRequestUrl: string | AuthorizationRequest): AuthorizationRequest {
    if (typeof authRequestUrl === 'object') {
      return authRequestUrl;
    }

    // Parse URL-encoded request
    try {
      const url = new URL(authRequestUrl);
      const params = url.searchParams;

      // Check if request is passed by value or by reference
      if (params.has('request_uri')) {
        throw new Error('request_uri (request by reference) is not yet supported');
      }

      if (params.has('request')) {
        // JWT-encoded request (not yet supported)
        throw new Error('JWT-encoded requests are not yet supported');
      }

      // Direct parameters
      const presentationDefinitionParam = params.get('presentation_definition');
      if (!presentationDefinitionParam) {
        throw new Error('Missing presentation_definition parameter');
      }

      return {
        presentation_definition: JSON.parse(presentationDefinitionParam),
        response_mode: params.get('response_mode') || 'direct_post',
        response_uri: params.get('response_uri') || '',
        nonce: params.get('nonce') || '',
        client_id: params.get('client_id') || '',
        state: params.get('state') || '',
      };
    } catch (error) {
      throw new Error(`Failed to parse authorization request: ${error}`);
    }
  }

  /**
   * Generate a verifiable presentation for an OpenID4VP authorization request
   *
   * @param authRequest - Authorization request from verifier
   * @returns Presentation response ready to submit
   */
  async generatePresentation(
    authRequest: AuthorizationRequest | string,
  ): Promise<PresentationResponse> {
    const request =
      typeof authRequest === 'string' ? this.parseAuthorizationRequest(authRequest) : authRequest;

    // Get all credentials from wallet
    const credentials = await (this as any).config.credentialStore.getAll();
    if (credentials.length === 0) {
      throw new Error('No credentials available in wallet');
    }

    // Use the first credential (in production, user would select)
    const signedCredential = credentials[0];
    const credential = signedCredential.credential;

    // Analyze presentation definition to determine what proof to generate
    const inputDescriptor = request.presentation_definition.input_descriptors[0];
    const proofRequest = this.inputDescriptorToProofRequest(inputDescriptor, request.nonce);

    // Generate the appropriate proof
    let zkProof;
    const timestampMs = new Date(proofRequest.timestamp).getTime();

    if (proofRequest.claimType === 'age' && proofRequest.minAge) {
      zkProof = await generateAgeProof(
        credential,
        proofRequest.minAge,
        proofRequest.nonce,
        timestampMs,
        (this as any).config.circuitPaths.ageWasm,
        (this as any).config.circuitPaths.ageZkey,
      );
    } else if (proofRequest.claimType === 'nationality' && proofRequest.targetNationality) {
      zkProof = await generateNationalityProof(
        credential,
        proofRequest.targetNationality,
        proofRequest.nonce,
        timestampMs,
        (this as any).config.circuitPaths.nationalityWasm,
        (this as any).config.circuitPaths.nationalityZkey,
      );
    } else {
      throw new Error(`Unsupported claim type: ${proofRequest.claimType}`);
    }

    // Build presentation submission
    const presentationSubmission = {
      id: uuidv4(),
      definition_id: request.presentation_definition.id,
      descriptor_map: [
        {
          id: inputDescriptor.id,
          format: 'zk-id/proof-v1',
          path: '$.verifiableCredential[0]',
        },
      ],
    };

    // Build verifiable presentation
    const vp = {
      '@context': [
        'https://www.w3.org/2018/credentials/v1',
        'https://identity.foundation/presentation-exchange/submission/v1',
      ],
      type: ['VerifiablePresentation', 'PresentationSubmission'],
      presentation_submission: presentationSubmission,
      verifiableCredential: [zkProof],
      holder: this.walletId,
    };

    // Encode VP token
    const vpToken = Buffer.from(JSON.stringify(vp)).toString('base64');

    return {
      vp_token: vpToken,
      state: request.state,
      presentation_submission: presentationSubmission,
    };
  }

  /**
   * Handle a BBS+ selective disclosure request and generate a presentation
   *
   * @param authRequest - Authorization request specifying schema and required fields
   * @returns Presentation response with BBS+ disclosure proof
   */
  async handleBBSDisclosureRequest(
    authRequest: AuthorizationRequest | string,
  ): Promise<PresentationResponse> {
    const request =
      typeof authRequest === 'string' ? this.parseAuthorizationRequest(authRequest) : authRequest;

    // Get all BBS credentials from wallet
    const bbsCredentials = await (this as any).getBBSCredentials();
    if (bbsCredentials.length === 0) {
      throw new Error('No BBS credentials available in wallet');
    }

    // Extract schema ID from input descriptor
    const inputDescriptor = request.presentation_definition.input_descriptors[0];
    let schemaId: string | undefined;
    const requiredFields: string[] = [];

    for (const field of inputDescriptor.constraints.fields) {
      // Extract schema ID
      if (field.path.some((p) => p.includes('schemaId')) && field.filter?.enum) {
        schemaId = field.filter.enum[0] as string;
      }

      // Extract required fields
      const fieldMatch = field.path[0]?.match(/\$\.revealedFields\.(.+)/);
      if (fieldMatch) {
        requiredFields.push(fieldMatch[1]);
      }
    }

    if (!schemaId) {
      throw new Error('Could not determine schema ID from authorization request');
    }

    // Find matching credential
    const matchingCredential = bbsCredentials.find(
      (cred: SerializedBBSCredential) => cred.schemaId === schemaId,
    );
    if (!matchingCredential) {
      throw new Error(`No credential found for schema: ${schemaId}`);
    }

    const credentialId = String(matchingCredential.fields.id);

    // Generate BBS disclosure proof
    const bbsProof = await (this as any).generateBBSDisclosureProof(
      credentialId,
      requiredFields,
      request.nonce,
    );

    // Build presentation submission
    const presentationSubmission = {
      id: uuidv4(),
      definition_id: request.presentation_definition.id,
      descriptor_map: [
        {
          id: inputDescriptor.id,
          format: 'bbs-disclosure/proof-v1',
          path: '$.verifiableCredential[0]',
        },
      ],
    };

    // Build verifiable presentation
    const vp = {
      '@context': [
        'https://www.w3.org/2018/credentials/v1',
        'https://identity.foundation/presentation-exchange/submission/v1',
      ],
      type: ['VerifiablePresentation', 'PresentationSubmission'],
      presentation_submission: presentationSubmission,
      verifiableCredential: [bbsProof],
      holder: this.walletId,
    };

    // Encode VP token
    const vpToken = Buffer.from(JSON.stringify(vp)).toString('base64');

    return {
      vp_token: vpToken,
      state: request.state,
      presentation_submission: presentationSubmission,
    };
  }

  /**
   * Submit a presentation to the verifier's response URI
   *
   * @param authRequest - Authorization request
   * @param presentation - Generated presentation
   * @returns true if submission succeeded
   */
  async submitPresentation(
    authRequest: AuthorizationRequest | string,
    presentation: PresentationResponse,
  ): Promise<boolean> {
    const request =
      typeof authRequest === 'string' ? this.parseAuthorizationRequest(authRequest) : authRequest;

    try {
      const response = await fetch(request.response_uri, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(presentation),
      });

      return response.ok;
    } catch (error) {
      console.error('Failed to submit presentation:', error);
      return false;
    }
  }

  /**
   * Convert a DIF Presentation Exchange input descriptor to a zk-id ProofRequest
   *
   * @param descriptor - Input descriptor from presentation definition
   * @param nonce - Nonce from authorization request
   * @returns ProofRequest for zk-id proof generation
   */
  private inputDescriptorToProofRequest(descriptor: InputDescriptor, nonce: string): ProofRequest {
    // Analyze constraints to determine claim type and parameters
    let claimType: 'age' | 'nationality' | 'age-revocable' = 'age';
    let minAge: number | undefined;
    let targetNationality: number | undefined;

    for (const field of descriptor.constraints.fields) {
      // Check for type field to determine proof type
      if (field.path.some((p) => p.includes('type')) && field.filter?.pattern) {
        if (field.filter.pattern.includes('AgeProof')) {
          claimType = 'age';
        } else if (field.filter.pattern.includes('NationalityProof')) {
          claimType = 'nationality';
        }
      }

      // Extract minimum age
      if (field.path.some((p) => p.includes('minAge')) && field.filter?.minimum) {
        minAge = field.filter.minimum;
      }

      // Extract target nationality
      if (field.path.some((p) => p.includes('targetNationality'))) {
        if (field.filter?.enum && field.filter.enum.length > 0) {
          targetNationality = field.filter.enum[0] as number;
        }
      }
    }

    return {
      claimType,
      minAge,
      targetNationality,
      nonce,
      timestamp: new Date().toISOString(),
    };
  }
}

// Re-export OpenID4VP types from server.ts for convenience
export type {
  AuthorizationRequest,
  PresentationDefinition,
  InputDescriptor,
  Constraints,
  Field,
  Filter,
  PresentationSubmission,
  DescriptorMapEntry,
  VerifiablePresentation,
  PresentationResponse,
} from './server';
