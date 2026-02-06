/**
 * Server-side SDK for zk-id (Node.js/backend)
 *
 * This runs on the website's backend and handles:
 * - Receiving proof submissions from clients
 * - Verifying proofs cryptographically
 * - Managing verification keys
 * - Rate limiting and abuse prevention
 */

import { ProofResponse, AgeProof, VerificationKey, verifyAgeProof, validateProofConstraints } from '@zk-id/core';
import { readFileSync } from 'fs';

export interface ZkIdServerConfig {
  /** Path to the verification key file */
  verificationKeyPath: string;
  /** Optional nonce storage for replay protection */
  nonceStore?: NonceStore;
  /** Optional rate limiter */
  rateLimiter?: RateLimiter;
}

export interface NonceStore {
  /** Check if nonce has been used */
  has(nonce: string): Promise<boolean>;
  /** Mark nonce as used */
  add(nonce: string): Promise<void>;
}

export interface RateLimiter {
  /** Check if request should be allowed */
  allowRequest(identifier: string): Promise<boolean>;
}

/**
 * Server SDK for verifying zk-id proofs
 */
export class ZkIdServer {
  private config: ZkIdServerConfig;
  private verificationKey: VerificationKey;

  constructor(config: ZkIdServerConfig) {
    this.config = config;
    this.verificationKey = this.loadVerificationKey();
  }

  /**
   * Verify a proof submission from a client
   *
   * @param proofResponse - The proof response from the client
   * @param clientIdentifier - Optional client IP/session for rate limiting
   * @returns Verification result with details
   */
  async verifyProof(
    proofResponse: ProofResponse,
    clientIdentifier?: string
  ): Promise<VerificationResult> {
    // Rate limiting
    if (this.config.rateLimiter && clientIdentifier) {
      const allowed = await this.config.rateLimiter.allowRequest(clientIdentifier);
      if (!allowed) {
        return {
          verified: false,
          error: 'Rate limit exceeded',
        };
      }
    }

    // Replay protection
    if (this.config.nonceStore) {
      const nonceUsed = await this.config.nonceStore.has(proofResponse.nonce);
      if (nonceUsed) {
        return {
          verified: false,
          error: 'Nonce already used (replay attack detected)',
        };
      }
    }

    // Validate proof constraints
    const constraintCheck = validateProofConstraints(proofResponse.proof);
    if (!constraintCheck.valid) {
      return {
        verified: false,
        error: `Invalid proof constraints: ${constraintCheck.errors.join(', ')}`,
      };
    }

    // Cryptographically verify the proof
    try {
      const isValid = await verifyAgeProof(proofResponse.proof, this.verificationKey);

      if (isValid) {
        // Mark nonce as used
        if (this.config.nonceStore) {
          await this.config.nonceStore.add(proofResponse.nonce);
        }

        return {
          verified: true,
          claimType: proofResponse.claimType,
          minAge: proofResponse.proof.publicSignals.minAge,
        };
      } else {
        return {
          verified: false,
          error: 'Proof verification failed',
        };
      }
    } catch (error) {
      return {
        verified: false,
        error: `Verification error: ${error}`,
      };
    }
  }

  /**
   * Load verification key from file
   */
  private loadVerificationKey(): VerificationKey {
    const data = readFileSync(this.config.verificationKeyPath, 'utf8');
    return JSON.parse(data);
  }
}

export interface VerificationResult {
  verified: boolean;
  claimType?: string;
  minAge?: number;
  error?: string;
}

/**
 * Simple in-memory nonce store (for demo)
 * Production should use Redis or database
 */
export class InMemoryNonceStore implements NonceStore {
  private nonces: Set<string> = new Set();

  async has(nonce: string): Promise<boolean> {
    return this.nonces.has(nonce);
  }

  async add(nonce: string): Promise<void> {
    this.nonces.add(nonce);

    // Auto-expire after 5 minutes
    setTimeout(() => this.nonces.delete(nonce), 5 * 60 * 1000);
  }
}

/**
 * Simple rate limiter (for demo)
 * Production should use token bucket or sliding window
 */
export class SimpleRateLimiter implements RateLimiter {
  private requests: Map<string, number[]> = new Map();
  private limit: number;
  private windowMs: number;

  constructor(limit: number = 10, windowMs: number = 60000) {
    this.limit = limit;
    this.windowMs = windowMs;
  }

  async allowRequest(identifier: string): Promise<boolean> {
    const now = Date.now();
    const requests = this.requests.get(identifier) || [];

    // Remove old requests outside the window
    const recentRequests = requests.filter(time => now - time < this.windowMs);

    if (recentRequests.length >= this.limit) {
      return false;
    }

    recentRequests.push(now);
    this.requests.set(identifier, recentRequests);

    return true;
  }
}
