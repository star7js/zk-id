/**
 * Client-side SDK for zk-id (browser)
 *
 * This runs in the user's browser and handles:
 * - Requesting proofs from the user's credential wallet
 * - Generating proofs locally (privacy-preserving)
 * - Submitting proofs to the website's backend
 */

import {
  ProofRequest,
  ProofResponse,
  Credential,
  SignedCredential,
  ValidCredentialTree,
  generateAgeProof,
  generateNationalityProof,
  generateAgeProofRevocable,
  PROTOCOL_VERSION,
  isProtocolCompatible,
} from '@zk-id/core';

export interface ZkIdClientConfig {
  /** URL of the website's proof verification endpoint */
  verificationEndpoint: string;
  /** Optional custom wallet connector */
  walletConnector?: WalletConnector;
  /**
   * Control when to send the protocol version header.
   * - "same-origin" (default): only send for same-origin endpoints in browsers
   * - "always": always send header
   * - "never": never send header
   */
  protocolVersionHeader?: 'same-origin' | 'always' | 'never';
}

export interface WalletConnector {
  /** Check if a wallet is available */
  isAvailable(): Promise<boolean>;
  /** Request a proof from the wallet */
  requestProof(request: ProofRequest): Promise<ProofResponse>;
}

/**
 * Client SDK for integrating zk-id into web applications
 */
export class ZkIdClient {
  private config: ZkIdClientConfig;

  constructor(config: ZkIdClientConfig) {
    this.config = config;
  }

  /**
   * Request age verification from the user
   *
   * @param minAge - Minimum age requirement (e.g., 18, 21)
   * @returns true if verification succeeds, false otherwise
   */
  async verifyAge(minAge: number): Promise<boolean> {
    try {
      // Create proof request
      const request: ProofRequest = {
        claimType: 'age',
        minAge,
        nonce: this.generateNonce(),
        timestamp: new Date().toISOString(),
      };

      // Get proof from wallet (or generate locally)
      const proofResponse = await this.requestProof(request);

      // Submit proof to backend for verification
      const isValid = await this.submitProof(proofResponse);

      return isValid;
    } catch (error) {
      console.error('[zk-id] Age verification failed:', error);
      return false;
    }
  }

  /**
   * Request nationality verification from the user
   *
   * @param targetNationality - Target nationality code (ISO 3166-1 numeric)
   * @returns true if verification succeeds, false otherwise
   */
  async verifyNationality(targetNationality: number): Promise<boolean> {
    try {
      // Create proof request
      const request: ProofRequest = {
        claimType: 'nationality',
        targetNationality,
        nonce: this.generateNonce(),
        timestamp: new Date().toISOString(),
      };

      // Get proof from wallet (or generate locally)
      const proofResponse = await this.requestProof(request);

      // Submit proof to backend for verification
      const isValid = await this.submitProof(proofResponse);

      return isValid;
    } catch (error) {
      console.error('[zk-id] Nationality verification failed:', error);
      return false;
    }
  }

  /**
   * Request revocable age verification from the user
   *
   * @param minAge - Minimum age requirement (e.g., 18, 21)
   * @returns true if verification succeeds, false otherwise
   */
  async verifyAgeRevocable(minAge: number): Promise<boolean> {
    try {
      // Create proof request
      const request: ProofRequest = {
        claimType: 'age-revocable',
        minAge,
        nonce: this.generateNonce(),
        timestamp: new Date().toISOString(),
      };

      // Get proof from wallet (or generate locally)
      const proofResponse = await this.requestProof(request);

      // Submit proof to backend for verification
      const isValid = await this.submitProof(proofResponse);

      return isValid;
    } catch (error) {
      console.error('[zk-id] Revocable age verification failed:', error);
      return false;
    }
  }

  /**
   * Request a proof from the user's wallet
   */
  private async requestProof(request: ProofRequest): Promise<ProofResponse> {
    // If wallet connector is available, use it
    if (this.config.walletConnector) {
      const isAvailable = await this.config.walletConnector.isAvailable();
      if (isAvailable) {
        return this.config.walletConnector.requestProof(request);
      }
    }

    // Otherwise, show UI to guide user to get a credential
    throw new Error('No credential wallet found. Please obtain a credential first.');
  }

  /**
   * Submit proof to backend for verification
   */
  private async submitProof(proofResponse: ProofResponse): Promise<boolean> {
    const shouldSendProtocolHeader = this.shouldSendProtocolHeader();
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
    };
    if (shouldSendProtocolHeader) {
      headers['X-ZkId-Protocol-Version'] = PROTOCOL_VERSION;
    }

    const response = await fetch(this.config.verificationEndpoint, {
      method: 'POST',
      headers,
      body: JSON.stringify(proofResponse),
    });

    if (!response.ok) {
      throw new Error(`Verification failed: ${response.statusText}`);
    }

    // Check protocol version compatibility
    const serverProtocolVersion =
      response.headers && typeof response.headers.get === 'function'
        ? response.headers.get('X-ZkId-Protocol-Version')
        : null;
    if (serverProtocolVersion && !isProtocolCompatible(PROTOCOL_VERSION, serverProtocolVersion)) {
      console.warn(
        `[zk-id] Protocol version mismatch: client=${PROTOCOL_VERSION}, server=${serverProtocolVersion}. ` +
        'This may cause compatibility issues.'
      );
    }

    const result = await response.json();
    return result.verified === true;
  }

  /**
   * Generate a random nonce for replay protection
   */
  private generateNonce(): string {
    const array = new Uint8Array(16);
    crypto.getRandomValues(array);
    return Array.from(array, byte => byte.toString(16).padStart(2, '0')).join('');
  }

  /**
   * Check if user has a credential wallet available
   */
  async hasWallet(): Promise<boolean> {
    if (!this.config.walletConnector) {
      return false;
    }
    return this.config.walletConnector.isAvailable();
  }

  private shouldSendProtocolHeader(): boolean {
    const policy = this.config.protocolVersionHeader ?? 'same-origin';
    if (policy === 'always') {
      return true;
    }
    if (policy === 'never') {
      return false;
    }

    if (typeof window === 'undefined' || !window.location) {
      // Non-browser environment: no CORS preflight concerns.
      return true;
    }

    try {
      const endpoint = new URL(this.config.verificationEndpoint, window.location.href);
      return endpoint.origin === window.location.origin;
    } catch {
      return true;
    }
  }
}

export interface InMemoryWalletConfig {
  circuitPaths: {
    ageWasm: string;
    ageZkey: string;
    nationalityWasm?: string;
    nationalityZkey?: string;
    ageRevocableWasm?: string;
    ageRevocableZkey?: string;
  };
  validCredentialTree?: ValidCredentialTree;
}

/**
 * Simple in-memory wallet for demo purposes
 * (Production would use browser extension, mobile app, or OS-level wallet)
 */
export class InMemoryWallet implements WalletConnector {
  private credentials: Map<string, SignedCredential> = new Map();
  private config: InMemoryWalletConfig;

  constructor(config: InMemoryWalletConfig) {
    this.config = config;
  }

  async isAvailable(): Promise<boolean> {
    return true;
  }

  async requestProof(request: ProofRequest): Promise<ProofResponse> {
    // In a real wallet, this would:
    // 1. Show UI asking user for consent
    // 2. Select appropriate credential
    // 3. Generate proof locally using wasm
    // 4. Return proof without revealing private data

    // Find a stored credential (use first available)
    const signedCredential = Array.from(this.credentials.values())[0];
    if (!signedCredential) {
      throw new Error('No credentials stored in wallet');
    }
    const credential = signedCredential.credential;

    // Generate proof based on claim type
    if (request.claimType === 'age') {
      if (!request.minAge) {
        throw new Error('minAge is required for age proof');
      }

      const proof = await generateAgeProof(
        credential,
        request.minAge,
        request.nonce,
        Date.parse(request.timestamp),
        this.config.circuitPaths.ageWasm,
        this.config.circuitPaths.ageZkey
      );

      return {
        credentialId: credential.id,
        claimType: 'age',
        proof,
        signedCredential,
        nonce: request.nonce,
        requestTimestamp: request.timestamp,
      };
    } else if (request.claimType === 'nationality') {
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
        Date.parse(request.timestamp),
        this.config.circuitPaths.nationalityWasm,
        this.config.circuitPaths.nationalityZkey
      );

      return {
        credentialId: credential.id,
        claimType: 'nationality',
        proof,
        signedCredential,
        nonce: request.nonce,
        requestTimestamp: request.timestamp,
      };
    } else if (request.claimType === 'age-revocable') {
      if (!request.minAge) {
        throw new Error('minAge is required for age-revocable proof');
      }

      if (!this.config.circuitPaths.ageRevocableWasm || !this.config.circuitPaths.ageRevocableZkey) {
        throw new Error('Age-revocable circuit paths not configured');
      }

      if (!this.config.validCredentialTree) {
        throw new Error('Valid credential tree not configured for revocable proofs');
      }

      const witness = await this.config.validCredentialTree.getWitness(credential.commitment);
      if (!witness) {
        throw new Error('Credential not found in valid credential tree');
      }

      const proof = await generateAgeProofRevocable(
        credential,
        request.minAge,
        request.nonce,
        Date.parse(request.timestamp),
        witness,
        this.config.circuitPaths.ageRevocableWasm,
        this.config.circuitPaths.ageRevocableZkey
      );

      return {
        credentialId: credential.id,
        claimType: 'age-revocable',
        proof,
        signedCredential,
        nonce: request.nonce,
        requestTimestamp: request.timestamp,
      };
    } else {
      throw new Error(`Unsupported claim type: ${request.claimType}`);
    }
  }

  addCredential(credential: Credential): void {
    throw new Error('addCredential is deprecated. Use addSignedCredential instead.');
  }

  addSignedCredential(signedCredential: SignedCredential): void {
    this.credentials.set(signedCredential.credential.id, signedCredential);
  }
}
