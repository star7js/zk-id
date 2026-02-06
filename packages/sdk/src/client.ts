/**
 * Client-side SDK for zk-id (browser)
 *
 * This runs in the user's browser and handles:
 * - Requesting proofs from the user's credential wallet
 * - Generating proofs locally (privacy-preserving)
 * - Submitting proofs to the website's backend
 */

import { ProofRequest, ProofResponse, AgeProof } from '@zk-id/core';

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

/**
 * Simple in-memory wallet for demo purposes
 * (Production would use browser extension, mobile app, or OS-level wallet)
 */
export class InMemoryWallet implements WalletConnector {
  private credentials: Map<string, any> = new Map();

  async isAvailable(): Promise<boolean> {
    return true;
  }

  async requestProof(request: ProofRequest): Promise<ProofResponse> {
    // In a real wallet, this would:
    // 1. Show UI asking user for consent
    // 2. Select appropriate credential
    // 3. Generate proof locally using wasm
    // 4. Return proof without revealing private data

    throw new Error('Demo wallet: implement proof generation');
  }

  addCredential(credential: any): void {
    this.credentials.set(credential.id, credential);
  }
}
