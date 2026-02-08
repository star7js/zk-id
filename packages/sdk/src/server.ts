/**
 * Server-side SDK for zk-id (Node.js/backend)
 *
 * This runs on the website's backend and handles:
 * - Receiving proof submissions from clients
 * - Verifying proofs cryptographically
 * - Managing verification keys
 * - Rate limiting and abuse prevention
 */

import {
  ProofResponse,
  AgeProof,
  NationalityProof,
  VerificationKey,
  RevocationStore,
  SignedCredential,
  credentialSignaturePayload,
  AgeProofSigned,
  NationalityProofSigned,
  verifyAgeProofSignedWithIssuer,
  verifyNationalityProofSignedWithIssuer,
  verifyAgeProof,
  verifyNationalityProof,
  validateProofConstraints,
  validateNationalityProofConstraints,
} from '@zk-id/core';
import { readFileSync } from 'fs';
import { EventEmitter } from 'events';
import { KeyObject, randomBytes, verify as cryptoVerify } from 'crypto';

export interface ZkIdServerConfig {
  /** Path to the age verification key file */
  verificationKeyPath?: string;
  /** Optional in-memory verification keys (for KMS/HSM integrations) */
  verificationKeys?: VerificationKeySet;
  /** Optional path to nationality verification key file */
  nationalityVerificationKeyPath?: string;
  /** Optional path to signed age verification key file */
  signedVerificationKeyPath?: string;
  /** Optional path to signed nationality verification key file */
  signedNationalityVerificationKeyPath?: string;
  /** Optional nonce storage for replay protection */
  nonceStore?: NonceStore;
  /** Optional rate limiter */
  rateLimiter?: RateLimiter;
  /** Optional revocation store for checking revoked credentials */
  revocationStore?: RevocationStore;
  /** Optional challenge store for server-issued nonces */
  challengeStore?: ChallengeStore;
  /** Challenge TTL in ms (default: 5 minutes) */
  challengeTtlMs?: number;
  /** Map of trusted issuer names to their public keys */
  issuerPublicKeys?: Record<string, KeyObject>;
  /** Map of trusted issuer names to BabyJub public key bits (for signed circuits) */
  issuerPublicKeyBits?: Record<string, string[]>;
  /** Optional issuer registry for key rotation and status checks */
  issuerRegistry?: IssuerRegistry;
  /** Require signed credentials (default: true) */
  requireSignedCredentials?: boolean;
  /** Enforce a required minimum age (server policy) */
  requiredMinAge?: number;
  /** Enforce a required nationality code (server policy) */
  requiredNationality?: number;
  /** Optional required policy object (preferred over requiredMinAge/requiredNationality) */
  requiredPolicy?: RequiredPolicy;
  /** Maximum allowed clock skew for request timestamps (ms) */
  maxRequestAgeMs?: number;
}

export interface VerificationKeySet {
  age: VerificationKey;
  nationality?: VerificationKey;
  signedAge?: VerificationKey;
  signedNationality?: VerificationKey;
}

export interface VerificationKeyProvider {
  getVerificationKeys(): Promise<VerificationKeySet>;
}

export interface NonceStore {
  /** Check if nonce has been used */
  has(nonce: string): Promise<boolean>;
  /** Mark nonce as used */
  add(nonce: string): Promise<void>;
}

export interface ChallengeStore {
  /** Issue a nonce challenge with a timestamp and TTL */
  issue(nonce: string, requestTimestampMs: number, ttlMs: number): Promise<void>;
  /** Consume a nonce challenge and return its timestamp, or null if missing/expired */
  consume(nonce: string): Promise<number | null>;
}

export interface RateLimiter {
  /** Check if request should be allowed */
  allowRequest(identifier: string): Promise<boolean>;
}

export interface IssuerRecord {
  issuer: string;
  publicKey: KeyObject;
  status?: 'active' | 'revoked' | 'suspended';
  validFrom?: string;
  validTo?: string;
}

export interface IssuerRegistry {
  getIssuer(issuer: string): Promise<IssuerRecord | null>;
}

/**
 * Simple in-memory issuer registry (demo)
 */
export class InMemoryIssuerRegistry implements IssuerRegistry {
  private issuers: Map<string, IssuerRecord>;

  constructor(records: IssuerRecord[] = []) {
    this.issuers = new Map(records.map((r) => [r.issuer, r]));
  }

  async getIssuer(issuer: string): Promise<IssuerRecord | null> {
    return this.issuers.get(issuer) || null;
  }

  upsert(record: IssuerRecord): void {
    this.issuers.set(record.issuer, record);
  }
}

export interface RequiredPolicy {
  minAge?: number;
  nationality?: number;
}

export interface VerificationEvent {
  /** ISO timestamp of verification */
  timestamp: string;
  /** Type of claim verified */
  claimType: string;
  /** Whether verification succeeded */
  verified: boolean;
  /** Time taken for verification in milliseconds */
  verificationTimeMs: number;
  /** Optional client identifier (IP, session, etc.) */
  clientIdentifier?: string;
  /** Error message if verification failed */
  error?: string;
}

export interface SignedProofRequest {
  claimType: 'age' | 'nationality';
  issuer: string;
  nonce: string;
  requestTimestamp: string;
  proof: AgeProofSigned | NationalityProofSigned;
}

export interface ProofChallenge {
  nonce: string;
  requestTimestamp: string;
}

const DEFAULT_CHALLENGE_TTL_MS = 5 * 60 * 1000;

/**
 * Server SDK for verifying zk-id proofs
 */
export class ZkIdServer extends EventEmitter {
  private config: ZkIdServerConfig;
  private verificationKey: VerificationKey;
  private nationalityVerificationKey?: VerificationKey;
  private signedVerificationKey?: VerificationKey;
  private signedNationalityVerificationKey?: VerificationKey;

  constructor(config: ZkIdServerConfig) {
    super();
    this.config = config;
    if (config.verificationKeys?.age) {
      this.verificationKey = config.verificationKeys.age;
    } else if (config.verificationKeyPath) {
      this.verificationKey = this.loadVerificationKey(config.verificationKeyPath);
    } else {
      throw new Error('verificationKeyPath or verificationKeys.age is required');
    }

    if (config.verificationKeys?.nationality) {
      this.nationalityVerificationKey = config.verificationKeys.nationality;
    } else if (config.nationalityVerificationKeyPath) {
      this.nationalityVerificationKey = this.loadVerificationKey(
        config.nationalityVerificationKeyPath
      );
    }

    if (config.verificationKeys?.signedAge) {
      this.signedVerificationKey = config.verificationKeys.signedAge;
    } else if (config.signedVerificationKeyPath) {
      this.signedVerificationKey = this.loadVerificationKey(
        config.signedVerificationKeyPath
      );
    }

    if (config.verificationKeys?.signedNationality) {
      this.signedNationalityVerificationKey = config.verificationKeys.signedNationality;
    } else if (config.signedNationalityVerificationKeyPath) {
      this.signedNationalityVerificationKey = this.loadVerificationKey(
        config.signedNationalityVerificationKeyPath
      );
    }
  }

  /**
   * Generate a server-issued nonce + timestamp challenge.
   */
  async createChallenge(): Promise<ProofChallenge> {
    const nonce = randomBytes(32).toString('hex');
    const requestTimestamp = new Date().toISOString();

    if (this.config.challengeStore) {
      const requestTimestampMs = Date.parse(requestTimestamp);
      const ttlMs = this.config.challengeTtlMs ?? DEFAULT_CHALLENGE_TTL_MS;
      await this.config.challengeStore.issue(nonce, requestTimestampMs, ttlMs);
    }

    return { nonce, requestTimestamp };
  }

  /**
   * Create a server instance using a verification key provider (KMS/HSM friendly).
   */
  static async createWithKeyProvider(
    config: Omit<ZkIdServerConfig, 'verificationKeys'> & {
      verificationKeyProvider: VerificationKeyProvider;
    }
  ): Promise<ZkIdServer> {
    const { verificationKeyProvider, ...rest } = config;
    const verificationKeys = await verificationKeyProvider.getVerificationKeys();
    return new ZkIdServer({ ...rest, verificationKeys });
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
    const startTime = Date.now();
    const requireSigned = this.config.requireSignedCredentials !== false;

    // Rate limiting
    if (this.config.rateLimiter && clientIdentifier) {
      const allowed = await this.config.rateLimiter.allowRequest(clientIdentifier);
      if (!allowed) {
        const result = {
          verified: false,
          error: 'Rate limit exceeded',
        };
        this.emitVerificationEvent(proofResponse.claimType, result, startTime, clientIdentifier);
        return result;
      }
    }

    // Signed credential validation (issuer trust + binding)
    if (requireSigned) {
      const signedCredential = proofResponse.signedCredential;
      if (!signedCredential) {
        const result = { verified: false, error: 'Signed credential required' };
        this.emitVerificationEvent(proofResponse.claimType, result, startTime, clientIdentifier);
        return result;
      }

      const bindingCheck = await this.validateSignedCredentialBinding(
        signedCredential,
        proofResponse
      );
      if (!bindingCheck.valid) {
        const result = { verified: false, error: bindingCheck.error };
        this.emitVerificationEvent(proofResponse.claimType, result, startTime, clientIdentifier);
        return result;
      }
    }

    // Server-side policy enforcement
    const requiredPolicy = this.config.requiredPolicy;
    if (proofResponse.claimType === 'age') {
      const requiredMinAge = requiredPolicy?.minAge ?? this.config.requiredMinAge;
      if (requiredMinAge !== undefined) {
        const proof = proofResponse.proof as AgeProof;
        if (proof.publicSignals.minAge !== requiredMinAge) {
          const result = {
            verified: false,
            error: 'Proof does not satisfy required minimum age',
          };
          this.emitVerificationEvent(proofResponse.claimType, result, startTime, clientIdentifier);
          return result;
        }
      }
    }
    if (proofResponse.claimType === 'nationality') {
      const requiredNationality =
        requiredPolicy?.nationality ?? this.config.requiredNationality;
      if (requiredNationality !== undefined) {
        const proof = proofResponse.proof as NationalityProof;
        if (proof.publicSignals.targetNationality !== requiredNationality) {
          const result = {
            verified: false,
            error: 'Proof does not satisfy required nationality',
          };
          this.emitVerificationEvent(proofResponse.claimType, result, startTime, clientIdentifier);
          return result;
        }
      }
    }

    // Request timestamp freshness check (optional)
    const requestTimestamp = proofResponse.requestTimestamp;
    if (!requestTimestamp) {
      const result = {
        verified: false,
        error: 'Missing request timestamp',
      };
      this.emitVerificationEvent(proofResponse.claimType, result, startTime, clientIdentifier);
      return result;
    }
    const requestMs = Date.parse(requestTimestamp);
    if (Number.isNaN(requestMs)) {
      const result = {
        verified: false,
        error: 'Invalid request timestamp',
      };
      this.emitVerificationEvent(proofResponse.claimType, result, startTime, clientIdentifier);
      return result;
    }
    if (this.config.maxRequestAgeMs !== undefined) {
      const ageMs = Math.abs(Date.now() - requestMs);
      if (ageMs > this.config.maxRequestAgeMs) {
        const result = {
          verified: false,
          error: 'Request timestamp outside allowed window',
        };
        this.emitVerificationEvent(proofResponse.claimType, result, startTime, clientIdentifier);
        return result;
      }
    }

    const challengeError = await this.validateChallenge(proofResponse.nonce, requestMs);
    if (challengeError) {
      const result = { verified: false, error: challengeError };
      this.emitVerificationEvent(proofResponse.claimType, result, startTime, clientIdentifier);
      return result;
    }

    // Nonce binding: ensure proof public nonce matches the request nonce
    const proofNonce = this.getProofNonce(proofResponse);
    if (proofNonce !== proofResponse.nonce) {
      const result = {
        verified: false,
        error: 'Proof nonce does not match request nonce',
      };
      this.emitVerificationEvent(proofResponse.claimType, result, startTime, clientIdentifier);
      return result;
    }

    // Timestamp binding: ensure proof public timestamp matches request timestamp
    {
      const proofTimestamp = this.getProofTimestamp(proofResponse);
      if (proofTimestamp !== requestMs) {
        const result = {
          verified: false,
          error: 'Proof timestamp does not match request timestamp',
        };
        this.emitVerificationEvent(proofResponse.claimType, result, startTime, clientIdentifier);
        return result;
      }
    }

    // Replay protection
    if (this.config.nonceStore) {
      const nonceUsed = await this.config.nonceStore.has(proofResponse.nonce);
      if (nonceUsed) {
        const result = {
          verified: false,
          error: 'Nonce already used (replay attack detected)',
        };
        this.emitVerificationEvent(proofResponse.claimType, result, startTime, clientIdentifier);
        return result;
      }
    }

    // Revocation check (use credential commitment)
    if (this.config.revocationStore) {
      const commitment = this.getCredentialCommitmentFromProof(proofResponse);
      const isRevoked = await this.config.revocationStore.isRevoked(commitment);
      if (isRevoked) {
        const result = {
          verified: false,
          error: 'Credential has been revoked',
        };
        this.emitVerificationEvent(proofResponse.claimType, result, startTime, clientIdentifier);
        return result;
      }
    }

    // Dispatch based on claim type
    let result: VerificationResult;
    if (proofResponse.claimType === 'age') {
      result = await this.verifyAgeProofInternal(proofResponse);
    } else if (proofResponse.claimType === 'nationality') {
      result = await this.verifyNationalityProofInternal(proofResponse);
    } else {
      result = {
        verified: false,
        error: 'Unknown claim type',
      };
    }

    this.emitVerificationEvent(proofResponse.claimType, result, startTime, clientIdentifier);
    return result;
  }

  /**
   * Verify a signed proof submission (issuer signature checked in-circuit)
   */
  async verifySignedProof(
    request: SignedProofRequest,
    clientIdentifier?: string
  ): Promise<VerificationResult> {
    const startTime = Date.now();

    // Rate limiting
    if (this.config.rateLimiter && clientIdentifier) {
      const allowed = await this.config.rateLimiter.allowRequest(clientIdentifier);
      if (!allowed) {
        const result = { verified: false, error: 'Rate limit exceeded' };
        this.emitVerificationEvent(request.claimType, result, startTime, clientIdentifier);
        return result;
      }
    }

    // Validate timestamp and nonce binding
    const requestMs = Date.parse(request.requestTimestamp);
    if (Number.isNaN(requestMs)) {
      const result = { verified: false, error: 'Invalid request timestamp' };
      this.emitVerificationEvent(request.claimType, result, startTime, clientIdentifier);
      return result;
    }

    if (this.config.maxRequestAgeMs !== undefined) {
      const ageMs = Math.abs(Date.now() - requestMs);
      if (ageMs > this.config.maxRequestAgeMs) {
        const result = { verified: false, error: 'Request timestamp outside allowed window' };
        this.emitVerificationEvent(request.claimType, result, startTime, clientIdentifier);
        return result;
      }
    }

    const challengeError = await this.validateChallenge(request.nonce, requestMs);
    if (challengeError) {
      const result = { verified: false, error: challengeError };
      this.emitVerificationEvent(request.claimType, result, startTime, clientIdentifier);
      return result;
    }

    // Replay protection
    if (this.config.nonceStore) {
      const nonceUsed = await this.config.nonceStore.has(request.nonce);
      if (nonceUsed) {
        const result = {
          verified: false,
          error: 'Nonce already used (replay attack detected)',
        };
        this.emitVerificationEvent(request.claimType, result, startTime, clientIdentifier);
        return result;
      }
    }

    const trustedBits = this.config.issuerPublicKeyBits?.[request.issuer];
    if (!trustedBits) {
      const result = { verified: false, error: 'Unknown or untrusted issuer' };
      this.emitVerificationEvent(request.claimType, result, startTime, clientIdentifier);
      return result;
    }

    // Bind nonce and timestamp to proof public signals
    const proofNonce = this.getSignedProofNonce(request.proof, request.claimType);
    if (proofNonce !== request.nonce) {
      const result = { verified: false, error: 'Proof nonce does not match request nonce' };
      this.emitVerificationEvent(request.claimType, result, startTime, clientIdentifier);
      return result;
    }
    const proofTimestamp = this.getSignedProofTimestamp(request.proof, request.claimType);
    if (proofTimestamp !== requestMs) {
      const result = {
        verified: false,
        error: 'Proof timestamp does not match request timestamp',
      };
      this.emitVerificationEvent(request.claimType, result, startTime, clientIdentifier);
      return result;
    }

    // Policy enforcement
    const requiredPolicy = this.config.requiredPolicy;
    if (request.claimType === 'age') {
      const requiredMinAge = requiredPolicy?.minAge ?? this.config.requiredMinAge;
      if (requiredMinAge !== undefined) {
        const proof = request.proof as AgeProofSigned;
        if (proof.publicSignals.minAge !== requiredMinAge) {
          const result = {
            verified: false,
            error: 'Proof does not satisfy required minimum age',
          };
          this.emitVerificationEvent(request.claimType, result, startTime, clientIdentifier);
          return result;
        }
      }
    }
    if (request.claimType === 'nationality') {
      const requiredNationality =
        requiredPolicy?.nationality ?? this.config.requiredNationality;
      if (requiredNationality !== undefined) {
        const proof = request.proof as NationalityProofSigned;
        if (proof.publicSignals.targetNationality !== requiredNationality) {
          const result = {
            verified: false,
            error: 'Proof does not satisfy required nationality',
          };
          this.emitVerificationEvent(request.claimType, result, startTime, clientIdentifier);
          return result;
        }
      }
    }

    // Revocation check using commitment in proof
    if (this.config.revocationStore) {
      const commitment = this.getSignedProofCommitment(request.proof, request.claimType);
      const isRevoked = await this.config.revocationStore.isRevoked(commitment);
      if (isRevoked) {
        const result = {
          verified: false,
          error: 'Credential has been revoked',
        };
        this.emitVerificationEvent(request.claimType, result, startTime, clientIdentifier);
        return result;
      }
    }

    let verified = false;
    try {
      if (request.claimType === 'age') {
        if (!this.signedVerificationKey) {
          return { verified: false, error: 'Signed age verification key not configured' };
        }
        verified = await verifyAgeProofSignedWithIssuer(
          request.proof as AgeProofSigned,
          this.signedVerificationKey,
          trustedBits
        );
      } else {
        if (!this.signedNationalityVerificationKey) {
          return { verified: false, error: 'Signed nationality verification key not configured' };
        }
        verified = await verifyNationalityProofSignedWithIssuer(
          request.proof as NationalityProofSigned,
          this.signedNationalityVerificationKey,
          trustedBits
        );
      }
    } catch (error) {
      return { verified: false, error: `Verification error: ${error}` };
    }

    if (verified && this.config.nonceStore) {
      await this.config.nonceStore.add(request.nonce);
    }

    const result = verified
      ? {
          verified: true,
          claimType: request.claimType,
          minAge:
            request.claimType === 'age'
              ? (request.proof as AgeProofSigned).publicSignals.minAge
              : undefined,
          targetNationality:
            request.claimType === 'nationality'
              ? (request.proof as NationalityProofSigned).publicSignals.targetNationality
              : undefined,
        }
      : { verified: false, error: 'Proof verification failed' };

    this.emitVerificationEvent(request.claimType, result, startTime, clientIdentifier);
    return result;
  }

  /**
   * Internal age proof verification
   */
  private async verifyAgeProofInternal(
    proofResponse: ProofResponse
  ): Promise<VerificationResult> {
    const proof = proofResponse.proof as AgeProof;

    // Validate proof constraints
    const constraintCheck = validateProofConstraints(proof);
    if (!constraintCheck.valid) {
      return {
        verified: false,
        error: `Invalid proof constraints: ${constraintCheck.errors.join(', ')}`,
      };
    }

    // Cryptographically verify the proof
    try {
      const isValid = await verifyAgeProof(proof, this.verificationKey);

      if (isValid) {
        // Mark nonce as used
        if (this.config.nonceStore) {
          await this.config.nonceStore.add(proofResponse.nonce);
        }

        return {
          verified: true,
          claimType: proofResponse.claimType,
          minAge: proof.publicSignals.minAge,
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
   * Internal nationality proof verification
   */
  private async verifyNationalityProofInternal(
    proofResponse: ProofResponse
  ): Promise<VerificationResult> {
    const proof = proofResponse.proof as NationalityProof;

    if (!this.nationalityVerificationKey) {
      return {
        verified: false,
        error: 'Nationality verification key not configured',
      };
    }

    // Validate proof constraints
    const constraintCheck = validateNationalityProofConstraints(proof);
    if (!constraintCheck.valid) {
      return {
        verified: false,
        error: `Invalid proof constraints: ${constraintCheck.errors.join(', ')}`,
      };
    }

    // Cryptographically verify the proof
    try {
      const isValid = await verifyNationalityProof(proof, this.nationalityVerificationKey);

      if (isValid) {
        // Mark nonce as used
        if (this.config.nonceStore) {
          await this.config.nonceStore.add(proofResponse.nonce);
        }

        return {
          verified: true,
          claimType: proofResponse.claimType,
          targetNationality: proof.publicSignals.targetNationality,
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
  private loadVerificationKey(path: string): VerificationKey {
    const data = readFileSync(path, 'utf8');
    return JSON.parse(data);
  }

  /**
   * Validate issuer signature and binding between proof and credential
   */
  private async validateSignedCredentialBinding(
    signedCredential: SignedCredential,
    proofResponse: ProofResponse
  ): Promise<{ valid: boolean; error?: string }> {
    const issuerRecord = await this.getIssuerRecord(signedCredential.issuer);
    const issuerKey = issuerRecord?.publicKey;
    if (!issuerKey) {
      return { valid: false, error: 'Unknown or untrusted issuer' };
    }
    if (issuerRecord?.status && issuerRecord.status !== 'active') {
      return { valid: false, error: 'Issuer is not active' };
    }
    if (issuerRecord?.validFrom || issuerRecord?.validTo) {
      const now = Date.now();
      if (issuerRecord.validFrom && Date.parse(issuerRecord.validFrom) > now) {
        return { valid: false, error: 'Issuer key not yet valid' };
      }
      if (issuerRecord.validTo && Date.parse(issuerRecord.validTo) < now) {
        return { valid: false, error: 'Issuer key expired' };
      }
    }

    const payload = credentialSignaturePayload(signedCredential.credential);
    const signature = Buffer.from(signedCredential.signature, 'base64');
    const signatureValid = cryptoVerify(null, Buffer.from(payload), issuerKey, signature);
    if (!signatureValid) {
      return { valid: false, error: 'Invalid credential signature' };
    }

    if (proofResponse.credentialId && proofResponse.credentialId !== signedCredential.credential.id) {
      return { valid: false, error: 'Credential ID mismatch' };
    }

    const proofCommitment = this.getCredentialCommitmentFromProof(proofResponse);
    if (proofCommitment !== signedCredential.credential.commitment) {
      return { valid: false, error: 'Credential commitment mismatch' };
    }

    return { valid: true };
  }

  private getCredentialCommitmentFromProof(proofResponse: ProofResponse): string {
    const proof = proofResponse.proof as AgeProof | NationalityProof;
    if (proofResponse.claimType === 'age') {
      return (proof as AgeProof).publicSignals.credentialHash;
    }
    if (proofResponse.claimType === 'nationality') {
      return (proof as NationalityProof).publicSignals.credentialHash;
    }
    return '';
  }

  private getProofNonce(proofResponse: ProofResponse): string {
    const proof = proofResponse.proof as AgeProof | NationalityProof;
    if (proofResponse.claimType === 'age') {
      return (proof as AgeProof).publicSignals.nonce;
    }
    if (proofResponse.claimType === 'nationality') {
      return (proof as NationalityProof).publicSignals.nonce;
    }
    return '';
  }

  private getProofTimestamp(proofResponse: ProofResponse): number {
    const proof = proofResponse.proof as AgeProof | NationalityProof;
    if (proofResponse.claimType === 'age') {
      return (proof as AgeProof).publicSignals.requestTimestamp;
    }
    if (proofResponse.claimType === 'nationality') {
      return (proof as NationalityProof).publicSignals.requestTimestamp;
    }
    return 0;
  }

  private async validateChallenge(nonce: string, requestTimestampMs: number): Promise<string | null> {
    if (!this.config.challengeStore) {
      return null;
    }

    const expectedTimestamp = await this.config.challengeStore.consume(nonce);
    if (expectedTimestamp === null) {
      return 'Unknown or expired challenge';
    }

    if (expectedTimestamp !== requestTimestampMs) {
      return 'Challenge timestamp mismatch';
    }

    return null;
  }

  private getSignedProofNonce(
    proof: AgeProofSigned | NationalityProofSigned,
    claimType: 'age' | 'nationality'
  ): string {
    if (claimType === 'age') {
      return (proof as AgeProofSigned).publicSignals.nonce;
    }
    return (proof as NationalityProofSigned).publicSignals.nonce;
  }

  private getSignedProofTimestamp(
    proof: AgeProofSigned | NationalityProofSigned,
    claimType: 'age' | 'nationality'
  ): number {
    if (claimType === 'age') {
      return (proof as AgeProofSigned).publicSignals.requestTimestamp;
    }
    return (proof as NationalityProofSigned).publicSignals.requestTimestamp;
  }

  private getSignedProofCommitment(
    proof: AgeProofSigned | NationalityProofSigned,
    claimType: 'age' | 'nationality'
  ): string {
    if (claimType === 'age') {
      return (proof as AgeProofSigned).publicSignals.credentialHash;
    }
    return (proof as NationalityProofSigned).publicSignals.credentialHash;
  }

  private async getIssuerRecord(issuer: string): Promise<IssuerRecord | null> {
    if (this.config.issuerRegistry) {
      return this.config.issuerRegistry.getIssuer(issuer);
    }
    const key = this.config.issuerPublicKeys?.[issuer];
    if (!key) {
      return null;
    }
    return { issuer, publicKey: key, status: 'active' };
  }

  /**
   * Emit a verification event for telemetry
   */
  private emitVerificationEvent(
    claimType: string,
    result: VerificationResult,
    startTime: number,
    clientIdentifier?: string
  ): void {
    const event: VerificationEvent = {
      timestamp: new Date().toISOString(),
      claimType,
      verified: result.verified,
      verificationTimeMs: Date.now() - startTime,
      clientIdentifier,
      error: result.error,
    };
    this.emit('verification', event);
  }

  /**
   * Register a callback for verification events
   *
   * @param callback - Function to call when a verification occurs
   */
  onVerification(callback: (event: VerificationEvent) => void): void {
    this.on('verification', callback);
  }
}

export interface VerificationResult {
  verified: boolean;
  claimType?: string;
  minAge?: number;
  targetNationality?: number;
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
 * Simple in-memory challenge store (for demo)
 */
export class InMemoryChallengeStore implements ChallengeStore {
  private challenges: Map<string, { requestTimestampMs: number; expiresAtMs: number }> = new Map();

  async issue(nonce: string, requestTimestampMs: number, ttlMs: number): Promise<void> {
    const expiresAtMs = Date.now() + ttlMs;
    this.challenges.set(nonce, { requestTimestampMs, expiresAtMs });
  }

  async consume(nonce: string): Promise<number | null> {
    const entry = this.challenges.get(nonce);
    if (!entry) {
      return null;
    }

    if (Date.now() > entry.expiresAtMs) {
      this.challenges.delete(nonce);
      return null;
    }

    this.challenges.delete(nonce);
    return entry.requestTimestampMs;
  }
}

export class StaticVerificationKeyProvider implements VerificationKeyProvider {
  private keys: VerificationKeySet;

  constructor(keys: VerificationKeySet) {
    this.keys = keys;
  }

  async getVerificationKeys(): Promise<VerificationKeySet> {
    return this.keys;
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
