/**
 * Client-side SDK for zk-id (browser)
 *
 * This runs in the user's browser and handles:
 * - Requesting proofs from the user's credential wallet
 * - Generating proofs locally (privacy-preserving)
 * - Submitting proofs to the website's backend
 */

import { ProofRequest, ProofResponse, Credential, generateAgeProof, generateNationalityProof } from '@zk-id/core';

export interface ZkIdClientConfig {
  /** URL of the website's proof verification endpoint */
  verificationEndpoint: string;
  /** Optional custom wallet connector */
  walletConnector?: WalletConnector;
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
    const response = await fetch(this.config.verificationEndpoint, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(proofResponse),
    });

    if (!response.ok) {
      throw new Error(`Verification failed: ${response.statusText}`);
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
}

export interface InMemoryWalletConfig {
  circuitPaths: {
    ageWasm: string;
    ageZkey: string;
    nationalityWasm?: string;
    nationalityZkey?: string;
  };
}

/**
 * Simple in-memory wallet for demo purposes
 * (Production would use browser extension, mobile app, or OS-level wallet)
 */
export class InMemoryWallet implements WalletConnector {
  private credentials: Map<string, Credential> = new Map();
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
    const credential = Array.from(this.credentials.values())[0];
    if (!credential) {
      throw new Error('No credentials stored in wallet');
    }

    // Generate proof based on claim type
    if (request.claimType === 'age') {
      if (!request.minAge) {
        throw new Error('minAge is required for age proof');
      }

      const proof = await generateAgeProof(
        credential,
        request.minAge,
        this.config.circuitPaths.ageWasm,
        this.config.circuitPaths.ageZkey
      );

      return {
        credentialId: credential.id,
        claimType: 'age',
        proof,
        nonce: request.nonce,
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
        this.config.circuitPaths.nationalityWasm,
        this.config.circuitPaths.nationalityZkey
      );

      return {
        credentialId: credential.id,
        claimType: 'nationality',
        proof,
        nonce: request.nonce,
      };
    } else {
      throw new Error(`Unsupported claim type: ${request.claimType}`);
    }
  }

  addCredential(credential: Credential): void {
    this.credentials.set(credential.id, credential);
  }
}
