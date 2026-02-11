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
  RevocationRootInfo,
  RevocationWitness,
  PROTOCOL_VERSION,
  isProtocolCompatible,
  ZkIdConfigError,
  ZkIdCredentialError,
  ZkIdProofError,
  ZkIdError,
  VerificationScenario,
} from '@zk-id/core';

export interface ZkIdClientConfig {
  /** URL of the website's proof verification endpoint */
  verificationEndpoint: string;
  /** Optional custom wallet connector */
  walletConnector?: WalletConnector;
  /** Optional revocation root endpoint (e.g., /api/revocation/root) */
  revocationRootEndpoint?: string;
  /**
   * Control when to send the protocol version header.
   * - "same-origin" (default): only send for same-origin endpoints in browsers
   * - "always": always send header
   * - "never": never send header
   */
  protocolVersionHeader?: 'same-origin' | 'always' | 'never';
  /** Maximum acceptable root age in ms. fetchRevocationRootInfo() warns when root exceeds this age. */
  maxRevocationRootAgeMs?: number;
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
      // Re-throw ZkIdError subclasses to preserve error context
      if (error instanceof ZkIdError) {
        throw error;
      }
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
      // Re-throw ZkIdError subclasses to preserve error context
      if (error instanceof ZkIdError) {
        throw error;
      }
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
      // Re-throw ZkIdError subclasses to preserve error context
      if (error instanceof ZkIdError) {
        throw error;
      }
      console.error('[zk-id] Revocable age verification failed:', error);
      return false;
    }
  }

  /**
   * Verify a complete scenario with multiple claims.
   *
   * Creates a multi-claim request from the scenario, generates proofs for each
   * claim, submits them, and returns true only if all pass.
   *
   * Note: Each claim is verified independently with its own nonce to avoid
   * replay protection failures on servers that enforce nonce uniqueness.
   *
   * @param scenario - The verification scenario to verify
   * @returns true if all scenario claims verify successfully, false otherwise
   */
  async verifyScenario(scenario: VerificationScenario): Promise<boolean> {
    try {
      const timestamp = new Date().toISOString();

      // Generate and verify each proof with its own nonce
      for (const claim of scenario.claims) {
        const proofRequest: ProofRequest = {
          claimType: claim.claimType,
          minAge: claim.minAge,
          targetNationality: claim.targetNationality,
          nonce: this.generateNonce(),
          timestamp,
        };

        // Get proof from wallet (or generate locally)
        const proofResponse = await this.requestProof(proofRequest);

        // Submit proof to backend for verification
        const isValid = await this.submitProof(proofResponse);

        // If any proof fails, the entire scenario fails
        if (!isValid) {
          return false;
        }
      }

      // All proofs passed
      return true;
    } catch (error) {
      // Re-throw ZkIdError subclasses to preserve error context
      if (error instanceof ZkIdError) {
        throw error;
      }
      console.error('[zk-id] Scenario verification failed:', error);
      return false;
    }
  }

  /**
   * Fetch current revocation root info from server (if configured).
   *
   * When `maxRevocationRootAgeMs` is set in config, logs a warning if the
   * returned root is older than the threshold.
   */
  async fetchRevocationRootInfo(): Promise<RevocationRootInfo> {
    if (!this.config.revocationRootEndpoint) {
      throw new ZkIdConfigError('revocationRootEndpoint not configured');
    }

    const response = await fetch(this.config.revocationRootEndpoint, {
      method: 'GET',
      headers: this.buildHeaders(),
    });

    if (!response.ok) {
      throw new ZkIdProofError(`Failed to fetch revocation root: ${response.statusText}`);
    }

    const info = (await response.json()) as RevocationRootInfo;

    if (this.config.maxRevocationRootAgeMs !== undefined && info.updatedAt) {
      const rootAgeMs = Date.now() - Date.parse(info.updatedAt);
      if (rootAgeMs > this.config.maxRevocationRootAgeMs) {
        console.warn(
          `[zk-id] Revocation root is stale: age=${Math.round(rootAgeMs / 1000)}s, ` +
            `max=${Math.round(this.config.maxRevocationRootAgeMs / 1000)}s`,
        );
      }
    }

    return info;
  }

  /**
   * Check if a stored witness is still valid against the current root.
   *
   * @param witness - The revocation witness to check
   * @returns true if the witness root matches the current root, false otherwise
   * @throws Error if revocationRootEndpoint is not configured
   */
  async isWitnessFresh(witness: RevocationWitness): Promise<boolean> {
    const currentRootInfo = await this.fetchRevocationRootInfo();
    return witness.root === currentRootInfo.root;
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
    throw new ZkIdCredentialError(
      'No credential wallet found. Please obtain a credential first.',
      'CREDENTIAL_NOT_FOUND',
    );
  }

  /**
   * Submit proof to backend for verification
   */
  private async submitProof(proofResponse: ProofResponse): Promise<boolean> {
    const headers = this.buildHeaders();
    headers['Content-Type'] = 'application/json';

    const response = await fetch(this.config.verificationEndpoint, {
      method: 'POST',
      headers,
      body: JSON.stringify(proofResponse),
    });

    if (!response.ok) {
      throw new ZkIdProofError(`Verification failed: ${response.statusText}`);
    }

    // Check protocol version compatibility
    const serverProtocolVersion =
      response.headers && typeof response.headers.get === 'function'
        ? response.headers.get('X-ZkId-Protocol-Version')
        : null;
    if (serverProtocolVersion && !isProtocolCompatible(PROTOCOL_VERSION, serverProtocolVersion)) {
      console.warn(
        `[zk-id] Protocol version mismatch: client=${PROTOCOL_VERSION}, server=${serverProtocolVersion}. ` +
          'This may cause compatibility issues.',
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
    return Array.from(array, (byte) => byte.toString(16).padStart(2, '0')).join('');
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

  private buildHeaders(): Record<string, string> {
    const headers: Record<string, string> = {};
    if (this.shouldSendProtocolHeader()) {
      headers['X-ZkId-Protocol-Version'] = PROTOCOL_VERSION;
    }
    return headers;
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
      throw new ZkIdCredentialError('No credentials stored in wallet', 'CREDENTIAL_NOT_FOUND');
    }
    const credential = signedCredential.credential;

    // Generate proof based on claim type
    if (request.claimType === 'age') {
      if (!request.minAge) {
        throw new ZkIdConfigError('minAge is required for age proof');
      }

      const proof = await generateAgeProof(
        credential,
        request.minAge,
        request.nonce,
        Date.parse(request.timestamp),
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
    } else if (request.claimType === 'nationality') {
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
        Date.parse(request.timestamp),
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
    } else if (request.claimType === 'age-revocable') {
      if (!request.minAge) {
        throw new ZkIdConfigError('minAge is required for age-revocable proof');
      }

      if (
        !this.config.circuitPaths.ageRevocableWasm ||
        !this.config.circuitPaths.ageRevocableZkey
      ) {
        throw new ZkIdConfigError('Age-revocable circuit paths not configured');
      }

      if (!this.config.validCredentialTree) {
        throw new ZkIdConfigError('Valid credential tree not configured for revocable proofs');
      }

      const witness = await this.config.validCredentialTree.getWitness(credential.commitment);
      if (!witness) {
        throw new ZkIdCredentialError(
          'Credential not found in valid credential tree',
          'CREDENTIAL_NOT_FOUND',
        );
      }

      const proof = await generateAgeProofRevocable(
        credential,
        request.minAge,
        request.nonce,
        Date.parse(request.timestamp),
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
    } else {
      throw new ZkIdProofError(
        `Unsupported claim type: ${request.claimType}`,
        'UNKNOWN_PROOF_TYPE',
      );
    }
  }

  addCredential(_credential: Credential): void {
    throw new ZkIdConfigError('addCredential is deprecated. Use addSignedCredential instead.');
  }

  addSignedCredential(signedCredential: SignedCredential): void {
    this.credentials.set(signedCredential.credential.id, signedCredential);
  }
}
