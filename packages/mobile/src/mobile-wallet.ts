/**
 * Mobile wallet for credential management and proof generation
 *
 * Platform-agnostic implementation with no DOM/browser dependencies.
 * All I/O (storage, HTTP) is injected via adapters.
 */

import {
  type SignedCredential,
  type Credential,
  type ProofRequest,
  type ProofResponse,
  type BBSProofResponse,
  type SerializedBBSCredential,
  generateAgeProof,
  generateNationalityProof,
  deserializeBBSCredential,
  deriveBBSSchemaDisclosureProof,
  serializeBBSProof,
  ZkIdCredentialError,
} from '@zk-id/core';

import type { MobileCredentialStore, MobileBBSCredentialStore } from './credential-store.js';

/**
 * Mobile wallet configuration
 */
export interface MobileWalletConfig {
  /** Credential storage (EdDSA-signed) */
  credentialStore: MobileCredentialStore | any; // Allow any for compatibility with InMemoryCredentialStore
  /** Optional BBS+ credential storage */
  bbsCredentialStore?: MobileBBSCredentialStore | any;
  /** Paths to circuit artifacts (WASM + zkey) */
  circuitPaths: {
    ageWasm: string;
    ageZkey: string;
    nationalityWasm?: string;
    nationalityZkey?: string;
  };
}

/**
 * Mobile wallet for credential management and proof generation.
 *
 * No DOM dependencies - works in React Native, Expo, and vanilla Node.js.
 */
export class MobileWallet {
  constructor(private config: MobileWalletConfig) {}

  // ---------------------------------------------------------------------------
  // Credential Management (EdDSA)
  // ---------------------------------------------------------------------------

  /**
   * Add a credential to the wallet
   */
  async addCredential(credential: SignedCredential): Promise<void> {
    await this.config.credentialStore.put(credential);
  }

  /**
   * Remove a credential from the wallet
   */
  async removeCredential(id: string): Promise<void> {
    await this.config.credentialStore.delete(id);
  }

  /**
   * List all credentials
   */
  async listCredentials(): Promise<SignedCredential[]> {
    return await this.config.credentialStore.getAll();
  }

  /**
   * Get a specific credential by ID
   */
  async getCredential(id: string): Promise<SignedCredential | null> {
    return await this.config.credentialStore.get(id);
  }

  /**
   * Export all credentials as JSON (for backup/migration)
   */
  async exportCredentials(): Promise<string> {
    const credentials = await this.config.credentialStore.getAll();
    return JSON.stringify(credentials, null, 2);
  }

  /**
   * Import credentials from JSON (for restore)
   */
  async importCredentials(json: string): Promise<void> {
    const credentials = JSON.parse(json) as SignedCredential[];
    for (const cred of credentials) {
      await this.config.credentialStore.put(cred);
    }
  }

  // ---------------------------------------------------------------------------
  // BBS+ Credential Management
  // ---------------------------------------------------------------------------

  /**
   * Add a BBS+ credential to the wallet
   */
  async addBBSCredential(credential: SerializedBBSCredential): Promise<void> {
    if (!this.config.bbsCredentialStore) {
      throw new ZkIdCredentialError('BBS+ credential store not configured');
    }
    await this.config.bbsCredentialStore.put(credential);
  }

  /**
   * Remove a BBS+ credential from the wallet
   */
  async removeBBSCredential(id: string): Promise<void> {
    if (!this.config.bbsCredentialStore) {
      throw new ZkIdCredentialError('BBS+ credential store not configured');
    }
    await this.config.bbsCredentialStore.delete(id);
  }

  /**
   * List all BBS+ credentials
   */
  async listBBSCredentials(): Promise<SerializedBBSCredential[]> {
    if (!this.config.bbsCredentialStore) {
      return [];
    }
    return await this.config.bbsCredentialStore.getAll();
  }

  // ---------------------------------------------------------------------------
  // Proof Generation (EdDSA credentials)
  // ---------------------------------------------------------------------------

  /**
   * Generate an age proof from a credential
   *
   * @param credentialId - ID of the credential to use (or null to use most recent)
   * @param minAge - Minimum age to prove
   * @param nonce - Challenge nonce from verifier
   * @returns ZK proof response
   */
  async generateAgeProof(
    credentialId: string | null,
    minAge: number,
    nonce: string,
  ): Promise<ProofResponse> {
    const credential = await this.selectCredential(credentialId);
    const timestampMs = Date.now();

    const zkProof = await generateAgeProof(
      credential.credential,
      minAge,
      nonce,
      timestampMs,
      this.config.circuitPaths.ageWasm,
      this.config.circuitPaths.ageZkey,
    );

    return {
      proof: zkProof,
      issuerSignature: credential.issuerSignature,
      issuerPublicKey: credential.issuerPublicKey,
      nonce,
      requestTimestamp: new Date(timestampMs).toISOString(),
    };
  }

  /**
   * Generate a nationality proof from a credential
   *
   * @param credentialId - ID of the credential to use (or null to use most recent)
   * @param targetNationality - Nationality code to prove (e.g., "US", "FR")
   * @param nonce - Challenge nonce from verifier
   * @returns ZK proof response
   */
  async generateNationalityProof(
    credentialId: string | null,
    targetNationality: string,
    nonce: string,
  ): Promise<ProofResponse> {
    if (!this.config.circuitPaths.nationalityWasm || !this.config.circuitPaths.nationalityZkey) {
      throw new ZkIdCredentialError('Nationality circuit paths not configured');
    }

    const credential = await this.selectCredential(credentialId);
    const timestampMs = Date.now();

    const zkProof = await generateNationalityProof(
      credential.credential,
      targetNationality,
      nonce,
      timestampMs,
      this.config.circuitPaths.nationalityWasm,
      this.config.circuitPaths.nationalityZkey,
    );

    return {
      proof: zkProof,
      issuerSignature: credential.issuerSignature,
      issuerPublicKey: credential.issuerPublicKey,
      nonce,
      requestTimestamp: new Date(timestampMs).toISOString(),
    };
  }

  /**
   * Handle a generic proof request (auto-detect proof type)
   */
  async handleProofRequest(request: ProofRequest): Promise<ProofResponse> {
    const credentialId = null; // Auto-select

    if (request.claimType === 'age' && request.minAge !== undefined) {
      return this.generateAgeProof(credentialId, request.minAge, request.nonce);
    } else if (request.claimType === 'nationality' && request.targetNationality) {
      return this.generateNationalityProof(credentialId, request.targetNationality, request.nonce);
    } else {
      throw new ZkIdCredentialError(`Unsupported claim type: ${request.claimType}`);
    }
  }

  // ---------------------------------------------------------------------------
  // BBS+ Proof Generation
  // ---------------------------------------------------------------------------

  /**
   * Generate a BBS+ selective disclosure proof
   *
   * @param credentialId - ID of the BBS+ credential
   * @param disclosureFields - Fields to disclose
   * @param nonce - Challenge nonce
   * @returns BBS+ proof response
   */
  async generateBBSProof(
    credentialId: string | null,
    disclosureFields: string[],
    nonce: string,
  ): Promise<BBSProofResponse> {
    if (!this.config.bbsCredentialStore) {
      throw new ZkIdCredentialError('BBS+ credential store not configured');
    }

    const credentials = await this.config.bbsCredentialStore.getAll();
    if (credentials.length === 0) {
      throw new ZkIdCredentialError('No BBS+ credentials available');
    }

    const serialized = credentialId
      ? await this.config.bbsCredentialStore.get(credentialId)
      : credentials[0];

    if (!serialized) {
      throw new ZkIdCredentialError(`BBS+ credential not found: ${credentialId}`);
    }

    const credential = deserializeBBSCredential(serialized);

    const proof = await deriveBBSSchemaDisclosureProof(
      credential,
      disclosureFields,
      new TextEncoder().encode(nonce),
    );

    const revealedFieldValues: Record<string, any> = {};
    for (const field of disclosureFields) {
      revealedFieldValues[field] = credential.fields[field];
    }

    return {
      proof: serializeBBSProof(proof),
      revealedFields: revealedFieldValues,
      nonce,
      requestTimestamp: new Date().toISOString(),
    };
  }

  // ---------------------------------------------------------------------------
  // Helper Methods
  // ---------------------------------------------------------------------------

  /**
   * Select a credential by ID, or auto-select the most recent
   */
  private async selectCredential(credentialId: string | null): Promise<SignedCredential> {
    if (credentialId) {
      const credential = await this.config.credentialStore.get(credentialId);
      if (!credential) {
        throw new ZkIdCredentialError(`Credential not found: ${credentialId}`);
      }
      return credential;
    }

    // Auto-select most recent
    const credentials = await this.config.credentialStore.getAll();
    if (credentials.length === 0) {
      throw new ZkIdCredentialError('No credentials available in wallet');
    }

    const sorted = [...credentials].sort((a, b) => {
      const timeA = Date.parse(a.issuedAt) || 0;
      const timeB = Date.parse(b.issuedAt) || 0;
      return timeB - timeA; // newest first
    });

    return sorted[0];
  }
}
