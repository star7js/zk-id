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
  AgeProofRevocable,
  MultiClaimResponse,
  ClaimVerificationResult,
  MultiClaimVerificationResult,
  aggregateVerificationResults,
  VerificationKey,
  RevocationStore,
  ValidCredentialTree,
  SignedCredential,
  RevocationRootInfo,
  credentialSignaturePayload,
  AgeProofSigned,
  NationalityProofSigned,
  verifyAgeProofSignedWithIssuer,
  verifyNationalityProofSignedWithIssuer,
  verifyAgeProof,
  verifyNationalityProof,
  verifyAgeProofRevocable,
  validateProofConstraints,
  validateNationalityProofConstraints,
  validateAgeProofRevocableConstraints,
  PROTOCOL_VERSION,
  isProtocolCompatible,
  AuditLogger,
  ConsoleAuditLogger,
  constantTimeEqual,
  ZkIdConfigError,
} from '@zk-id/core';
import { readFileSync } from 'fs';
import { EventEmitter } from 'events';
import { KeyObject, randomBytes, verify as cryptoVerify } from 'crypto';

export type ProtocolVersionPolicy = 'strict' | 'warn' | 'off';

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
  /** Optional path to revocable age verification key file */
  revocableVerificationKeyPath?: string;
  /** Optional nonce storage for replay protection */
  nonceStore?: NonceStore;
  /** Optional rate limiter */
  rateLimiter?: RateLimiter;
  /** Optional revocation store for checking revoked credentials */
  revocationStore?: RevocationStore;
  /** Optional valid credential tree for revocable proofs */
  validCredentialTree?: ValidCredentialTree;
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
  /** Maximum age (in past) for request timestamps in ms. Prevents replay of stale proofs. */
  maxRequestAgeMs?: number;
  /** Maximum allowed future timestamp skew in ms (default: 60000 = 1 minute). Allows small clock differences. */
  maxFutureSkewMs?: number;
  /** Protocol version enforcement policy (default: warn) */
  protocolVersionPolicy?: ProtocolVersionPolicy;
  /** Revocation root TTL in seconds (default: 300). Used in getRevocationRootInfo(). */
  revocationRootTtlSeconds?: number;
  /** Source identifier for revocation root metadata (e.g., issuer name or registry URL) */
  revocationRootSource?: string;
  /** Maximum acceptable root age in ms. If set, verifyProof rejects revocable proofs when the root is stale. */
  maxRevocationRootAgeMs?: number;
  /** Enable strict payload validation before verification (default: true). Checks required fields and types. Set to false to disable validation. */
  validatePayloads?: boolean;
  /** Optional audit logger for verification and registry events. Defaults to ConsoleAuditLogger. */
  auditLogger?: AuditLogger;
  /** Return detailed error messages (default: false). When false, sanitizes errors to prevent information leakage. Use only in development/debugging. */
  verboseErrors?: boolean;
}

export interface VerificationKeySet {
  age: VerificationKey;
  nationality?: VerificationKey;
  signedAge?: VerificationKey;
  signedNationality?: VerificationKey;
  ageRevocable?: VerificationKey;
  nullifier?: VerificationKey;
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
  /** Issuer identifier (name or DID) */
  issuer: string;
  /** Ed25519 public verification key */
  publicKey: KeyObject;
  /** Issuer status: active, revoked, or suspended */
  status?: 'active' | 'revoked' | 'suspended';
  /** ISO 8601 timestamp — key is not valid before this time */
  validFrom?: string;
  /** ISO 8601 timestamp — key is not valid after this time */
  validTo?: string;
  /** Grace period in ms after validTo during which proofs are still accepted (for key rotation). Default: no grace period. */
  rotationGracePeriodMs?: number;
  /** Jurisdiction code (e.g., ISO 3166-1 alpha-2: "US", "DE", "GB") */
  jurisdiction?: string;
  /** URL to the issuer's attestation or issuance policy document */
  policyUrl?: string;
  /** URL to an external audit report or compliance reference */
  auditUrl?: string;
}

export interface IssuerRegistry {
  getIssuer(issuer: string): Promise<IssuerRecord | null>;
}

/**
 * Simple in-memory issuer registry (demo).
 *
 * Supports key rotation via multiple records per issuer (current + previous keys).
 * Records are stored as a list; `getIssuer()` returns the first active record whose
 * validity window covers the current time.
 */
export class InMemoryIssuerRegistry implements IssuerRegistry {
  private issuers: Map<string, IssuerRecord[]>;
  private auditLogger?: AuditLogger;

  constructor(records: IssuerRecord[] = [], auditLogger?: AuditLogger) {
    this.issuers = new Map();
    this.auditLogger = auditLogger;
    for (const r of records) {
      this.addRecord(r);
    }
  }

  /**
   * Return the best matching record for the given issuer:
   * - Prefers active records within their validity window.
   * - Supports rotation grace period: if no active key is found, checks for recently-expired keys within rotationGracePeriodMs.
   * - Falls back to the first record if none match (preserves existing behavior).
   */
  async getIssuer(issuer: string): Promise<IssuerRecord | null> {
    const records = this.issuers.get(issuer);
    if (!records || records.length === 0) {
      return null;
    }
    const now = Date.now();
    // Find first active record whose validity window covers now
    const active = records.find((r) => {
      if (r.status && r.status !== 'active') return false;
      if (r.validFrom && Date.parse(r.validFrom) > now) return false;
      if (r.validTo && Date.parse(r.validTo) < now) return false;
      return true;
    });

    if (active) {
      return active;
    }

    // Check for recently-expired keys within grace period
    // Note: grace period is also checked in validateSignedCredentialBinding()
    const gracePeriodMatch = records.find((r) => {
      if (r.status && r.status !== 'active') return false;
      if (!r.validTo || !r.rotationGracePeriodMs) return false;
      const validToMs = Date.parse(r.validTo);
      if (validToMs >= now) return false; // Not expired yet
      const expiryAge = now - validToMs;
      const withinGrace = expiryAge <= r.rotationGracePeriodMs;
      if (withinGrace && this.auditLogger) {
        this.auditLogger.log({
          timestamp: new Date().toISOString(),
          action: 'grace_period_accept',
          actor: 'registry',
          target: issuer,
          success: true,
          metadata: {
            validTo: r.validTo,
            expiryAgeMs: expiryAge,
            gracePeriodMs: r.rotationGracePeriodMs,
          },
        });
      }
      return withinGrace;
    });

    if (gracePeriodMatch) {
      return gracePeriodMatch;
    }

    // Fallback: return first record (caller handles status/validity checks)
    return records[0];
  }

  /**
   * List all records for an issuer (for rotation inspection).
   */
  async listRecords(issuer: string): Promise<IssuerRecord[]> {
    return this.issuers.get(issuer) ?? [];
  }

  /**
   * Add or replace an issuer record. When a record with the same validFrom
   * already exists for the issuer, it is replaced; otherwise the new record
   * is appended (supporting overlapping rotation windows).
   */
  upsert(record: IssuerRecord): void {
    const records = this.issuers.get(record.issuer);
    if (!records) {
      this.issuers.set(record.issuer, [record]);
      return;
    }
    const idx = records.findIndex(
      (r) => r.validFrom === record.validFrom && r.validTo === record.validTo,
    );
    if (idx >= 0) {
      records[idx] = record;
    } else {
      records.push(record);
    }
  }

  /**
   * Suspend all records for an issuer.
   */
  suspend(issuer: string): void {
    const records = this.issuers.get(issuer);
    if (records) {
      for (const r of records) {
        r.status = 'suspended';
      }
    }
    this.auditLogger?.log({
      timestamp: new Date().toISOString(),
      action: 'suspend',
      actor: 'registry',
      target: issuer,
      success: !!records,
    });
  }

  /**
   * Reactivate all records for an issuer.
   */
  reactivate(issuer: string): void {
    const records = this.issuers.get(issuer);
    if (records) {
      for (const r of records) {
        r.status = 'active';
      }
    }
    this.auditLogger?.log({
      timestamp: new Date().toISOString(),
      action: 'reactivate',
      actor: 'registry',
      target: issuer,
      success: !!records,
    });
  }

  /**
   * Deactivate (revoke) an issuer — marks all records as revoked.
   */
  deactivate(issuer: string): void {
    const records = this.issuers.get(issuer);
    if (records) {
      for (const r of records) {
        r.status = 'revoked';
      }
    }
    this.auditLogger?.log({
      timestamp: new Date().toISOString(),
      action: 'deactivate',
      actor: 'registry',
      target: issuer,
      success: !!records,
    });
  }

  private addRecord(record: IssuerRecord): void {
    const existing = this.issuers.get(record.issuer);
    if (existing) {
      existing.push(record);
    } else {
      this.issuers.set(record.issuer, [record]);
    }
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
const DEFAULT_REVOCATION_ROOT_TTL_SECONDS = 300;

/**
 * Server SDK for verifying zk-id proofs
 */
export class ZkIdServer extends EventEmitter {
  private config: ZkIdServerConfig;
  private verificationKey: VerificationKey;
  private nationalityVerificationKey?: VerificationKey;
  private signedVerificationKey?: VerificationKey;
  private signedNationalityVerificationKey?: VerificationKey;
  private revocableVerificationKey?: VerificationKey;
  private auditLogger: AuditLogger;

  /**
   * Get the protocol version implemented by this SDK
   */
  get protocolVersion(): string {
    return PROTOCOL_VERSION;
  }

  /**
   * Create a new ZkIdServer instance
   *
   * @param config - Server configuration including verification keys and security policies
   */
  constructor(config: ZkIdServerConfig) {
    super();
    this.config = config;
    this.auditLogger = config.auditLogger ?? new ConsoleAuditLogger();
    if (config.verificationKeys?.age) {
      this.verificationKey = config.verificationKeys.age;
    } else if (config.verificationKeyPath) {
      this.verificationKey = this.loadVerificationKey(config.verificationKeyPath);
    } else {
      throw new ZkIdConfigError('verificationKeyPath or verificationKeys.age is required');
    }

    if (config.verificationKeys?.nationality) {
      this.nationalityVerificationKey = config.verificationKeys.nationality;
    } else if (config.nationalityVerificationKeyPath) {
      this.nationalityVerificationKey = this.loadVerificationKey(
        config.nationalityVerificationKeyPath,
      );
    }

    if (config.verificationKeys?.signedAge) {
      this.signedVerificationKey = config.verificationKeys.signedAge;
    } else if (config.signedVerificationKeyPath) {
      this.signedVerificationKey = this.loadVerificationKey(config.signedVerificationKeyPath);
    }

    if (config.verificationKeys?.signedNationality) {
      this.signedNationalityVerificationKey = config.verificationKeys.signedNationality;
    } else if (config.signedNationalityVerificationKeyPath) {
      this.signedNationalityVerificationKey = this.loadVerificationKey(
        config.signedNationalityVerificationKeyPath,
      );
    }

    if (config.verificationKeys?.ageRevocable) {
      this.revocableVerificationKey = config.verificationKeys.ageRevocable;
    } else if (config.revocableVerificationKeyPath) {
      this.revocableVerificationKey = this.loadVerificationKey(config.revocableVerificationKeyPath);
    }
  }

  /**
   * Sanitize error messages to prevent information leakage.
   * Maps internal errors to generic categories unless verboseErrors is enabled.
   */
  private sanitizeError(internalError: string): string {
    if (this.config.verboseErrors) {
      return internalError;
    }

    // Categorize errors into generic responses
    const lowerError = internalError.toLowerCase();

    // Rate limiting
    if (lowerError.includes('rate limit')) {
      return 'Too many requests';
    }

    // Payload validation (check before timestamp/nonce to avoid false matches)
    if (lowerError.includes('payload') || lowerError.includes('invalid request')) {
      return 'Invalid request format';
    }

    // Timestamp/nonce errors
    if (
      lowerError.includes('timestamp') ||
      lowerError.includes('nonce') ||
      lowerError.includes('expired') ||
      lowerError.includes('stale') ||
      lowerError.includes('challenge') ||
      lowerError.includes('replay')
    ) {
      return 'Request expired or invalid';
    }

    // All signature/issuer/constraint/proof errors
    // (includes: signature, issuer, constraint, proof, verification, credential, revoked, policy, etc.)
    return 'Verification failed';
  }

  /**
   * Generate a server-issued nonce + timestamp challenge.
   *
   * @returns A ProofChallenge containing nonce and timestamp for the client to use
   */
  async createChallenge(): Promise<ProofChallenge> {
    const nonce = BigInt('0x' + randomBytes(31).toString('hex')).toString();
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
   *
   * @param config - Server configuration with verification key provider
   * @returns A configured ZkIdServer instance
   */
  static async createWithKeyProvider(
    config: Omit<ZkIdServerConfig, 'verificationKeys'> & {
      verificationKeyProvider: VerificationKeyProvider;
    },
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
    clientIdentifier?: string,
    clientProtocolVersion?: string,
  ): Promise<VerificationResult> {
    const startTime = Date.now();
    const requireSigned = this.config.requireSignedCredentials !== false;

    // Strict payload validation (enabled by default)
    if (this.config.validatePayloads !== false) {
      const payloadErrors = validateProofResponsePayload(proofResponse, requireSigned);
      if (payloadErrors.length > 0) {
        const msg = payloadErrors.map((e) => `${e.field}: ${e.message}`).join('; ');
        const internalError = `Invalid payload: ${msg}`;
        const result: VerificationResult = {
          verified: false,
          error: this.sanitizeError(internalError),
        };
        this.emitVerificationEvent(
          proofResponse?.claimType ?? 'unknown',
          result,
          startTime,
          clientIdentifier,
          internalError,
        );
        return result;
      }
    }

    // Rate limiting
    if (this.config.rateLimiter && clientIdentifier) {
      const allowed = await this.config.rateLimiter.allowRequest(clientIdentifier);
      if (!allowed) {
        const internalError = 'Rate limit exceeded';
        const result = {
          verified: false,
          error: this.sanitizeError(internalError),
        };
        this.emitVerificationEvent(
          proofResponse.claimType,
          result,
          startTime,
          clientIdentifier,
          internalError,
        );
        return result;
      }
    }

    // Protocol version enforcement
    const protocolResult = this.checkProtocolVersion(
      clientProtocolVersion,
      proofResponse.claimType,
      startTime,
      clientIdentifier,
    );
    if (protocolResult) {
      return protocolResult;
    }

    // Signed credential validation (issuer trust + binding)
    if (requireSigned) {
      const signedCredential = proofResponse.signedCredential;
      if (!signedCredential) {
        const internalError = 'Signed credential required';
        const result = { verified: false, error: this.sanitizeError(internalError) };
        this.emitVerificationEvent(
          proofResponse.claimType,
          result,
          startTime,
          clientIdentifier,
          internalError,
        );
        return result;
      }

      const bindingCheck = await this.validateSignedCredentialBinding(
        signedCredential,
        proofResponse,
      );
      if (!bindingCheck.valid) {
        const internalError = bindingCheck.error!;
        const result = { verified: false, error: this.sanitizeError(internalError) };
        this.emitVerificationEvent(
          proofResponse.claimType,
          result,
          startTime,
          clientIdentifier,
          internalError,
        );
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
          const internalError = 'Proof does not satisfy required minimum age';
          const result = {
            verified: false,
            error: this.sanitizeError(internalError),
          };
          this.emitVerificationEvent(
            proofResponse.claimType,
            result,
            startTime,
            clientIdentifier,
            internalError,
          );
          return result;
        }
      }
    }
    if (proofResponse.claimType === 'age-revocable') {
      const requiredMinAge = requiredPolicy?.minAge ?? this.config.requiredMinAge;
      if (requiredMinAge !== undefined) {
        const proof = proofResponse.proof as AgeProofRevocable;
        if (proof.publicSignals.minAge !== requiredMinAge) {
          const internalError = 'Proof does not satisfy required minimum age';
          const result = {
            verified: false,
            error: this.sanitizeError(internalError),
          };
          this.emitVerificationEvent(
            proofResponse.claimType,
            result,
            startTime,
            clientIdentifier,
            internalError,
          );
          return result;
        }
      }
    }
    if (proofResponse.claimType === 'nationality') {
      const requiredNationality = requiredPolicy?.nationality ?? this.config.requiredNationality;
      if (requiredNationality !== undefined) {
        const proof = proofResponse.proof as NationalityProof;
        if (proof.publicSignals.targetNationality !== requiredNationality) {
          const internalError = 'Proof does not satisfy required nationality';
          const result = {
            verified: false,
            error: this.sanitizeError(internalError),
          };
          this.emitVerificationEvent(
            proofResponse.claimType,
            result,
            startTime,
            clientIdentifier,
            internalError,
          );
          return result;
        }
      }
    }

    // Request timestamp freshness check (optional)
    const requestTimestamp = proofResponse.requestTimestamp;
    if (!requestTimestamp) {
      const internalError = 'Missing request timestamp';
      const result = {
        verified: false,
        error: this.sanitizeError(internalError),
      };
      this.emitVerificationEvent(
        proofResponse.claimType,
        result,
        startTime,
        clientIdentifier,
        internalError,
      );
      return result;
    }
    const requestMs = Date.parse(requestTimestamp);
    if (Number.isNaN(requestMs)) {
      const internalError = 'Invalid request timestamp';
      const result = {
        verified: false,
        error: this.sanitizeError(internalError),
      };
      this.emitVerificationEvent(
        proofResponse.claimType,
        result,
        startTime,
        clientIdentifier,
        internalError,
      );
      return result;
    }
    // Check for future timestamps (time-shifted proofs)
    const maxFutureSkew = this.config.maxFutureSkewMs ?? 60000; // Default: 1 minute clock skew
    const timeDiffMs = requestMs - Date.now();
    if (timeDiffMs > maxFutureSkew) {
      const internalError = 'Request timestamp is too far in the future';
      const result = {
        verified: false,
        error: this.sanitizeError(internalError),
      };
      this.emitVerificationEvent(
        proofResponse.claimType,
        result,
        startTime,
        clientIdentifier,
        internalError,
      );
      return result;
    }

    // Check for stale timestamps (replay protection)
    if (this.config.maxRequestAgeMs !== undefined) {
      const ageMs = Date.now() - requestMs;
      if (ageMs > this.config.maxRequestAgeMs) {
        const internalError = 'Request timestamp is too old';
        const result = {
          verified: false,
          error: this.sanitizeError(internalError),
        };
        this.emitVerificationEvent(
          proofResponse.claimType,
          result,
          startTime,
          clientIdentifier,
          internalError,
        );
        return result;
      }
    }

    const challengeError = await this.validateChallenge(proofResponse.nonce, requestMs);
    if (challengeError) {
      const result = { verified: false, error: this.sanitizeError(challengeError) };
      this.emitVerificationEvent(
        proofResponse.claimType,
        result,
        startTime,
        clientIdentifier,
        challengeError,
      );
      return result;
    }

    // Nonce binding: ensure proof public nonce matches the request nonce
    const proofNonce = this.getProofNonce(proofResponse);
    if (!constantTimeEqual(proofNonce, proofResponse.nonce)) {
      const internalError = 'Proof nonce does not match request nonce';
      const result = {
        verified: false,
        error: this.sanitizeError(internalError),
      };
      this.emitVerificationEvent(
        proofResponse.claimType,
        result,
        startTime,
        clientIdentifier,
        internalError,
      );
      return result;
    }

    // Timestamp binding: ensure proof public timestamp matches request timestamp
    {
      const proofTimestamp = this.getProofTimestamp(proofResponse);
      if (proofTimestamp !== requestMs) {
        const internalError = 'Proof timestamp does not match request timestamp';
        const result = {
          verified: false,
          error: this.sanitizeError(internalError),
        };
        this.emitVerificationEvent(
          proofResponse.claimType,
          result,
          startTime,
          clientIdentifier,
          internalError,
        );
        return result;
      }
    }

    // Replay protection
    if (this.config.nonceStore) {
      const nonceUsed = await this.config.nonceStore.has(proofResponse.nonce);
      if (nonceUsed) {
        const internalError = 'Nonce already used (replay attack detected)';
        const result = {
          verified: false,
          error: this.sanitizeError(internalError),
        };
        this.emitVerificationEvent(
          proofResponse.claimType,
          result,
          startTime,
          clientIdentifier,
          internalError,
        );
        return result;
      }
    }

    // Revocation check (use credential commitment)
    if (this.config.revocationStore) {
      const commitment = this.getCredentialCommitmentFromProof(proofResponse);
      const isRevoked = await this.config.revocationStore.isRevoked(commitment);
      if (isRevoked) {
        const internalError = 'Credential has been revoked';
        const result = {
          verified: false,
          error: this.sanitizeError(internalError),
        };
        this.emitVerificationEvent(
          proofResponse.claimType,
          result,
          startTime,
          clientIdentifier,
          internalError,
        );
        return result;
      }
    }

    // Dispatch based on claim type
    let result: VerificationResult;
    let internalError: string | undefined;
    if (proofResponse.claimType === 'age') {
      const verification = await this.verifyAgeProofInternal(proofResponse);
      result = verification.result;
      internalError = verification.internalError;
    } else if (proofResponse.claimType === 'nationality') {
      const verification = await this.verifyNationalityProofInternal(proofResponse);
      result = verification.result;
      internalError = verification.internalError;
    } else if (proofResponse.claimType === 'age-revocable') {
      const verification = await this.verifyAgeProofRevocableInternal(proofResponse);
      result = verification.result;
      internalError = verification.internalError;
    } else {
      internalError = 'Unknown claim type';
      result = {
        verified: false,
        error: this.sanitizeError(internalError),
      };
    }

    this.emitVerificationEvent(
      proofResponse.claimType,
      result,
      startTime,
      clientIdentifier,
      internalError,
    );
    return result;
  }

  /**
   * Verify a signed proof submission (issuer signature checked in-circuit)
   *
   * @param request - The signed proof request containing proof and issuer information
   * @param clientIdentifier - Optional client IP/session for rate limiting
   * @param clientProtocolVersion - Optional client protocol version for compatibility checking
   * @returns Verification result with outcome and details
   */
  async verifySignedProof(
    request: SignedProofRequest,
    clientIdentifier?: string,
    clientProtocolVersion?: string,
  ): Promise<VerificationResult> {
    const startTime = Date.now();

    // Strict payload validation (enabled by default)
    if (this.config.validatePayloads !== false) {
      const payloadErrors = validateSignedProofRequestPayload(request);
      if (payloadErrors.length > 0) {
        const msg = payloadErrors.map((e) => `${e.field}: ${e.message}`).join('; ');
        const internalError = `Invalid payload: ${msg}`;
        const result: VerificationResult = {
          verified: false,
          error: this.sanitizeError(internalError),
        };
        this.emitVerificationEvent(
          request?.claimType ?? 'unknown',
          result,
          startTime,
          clientIdentifier,
          internalError,
        );
        return result;
      }
    }

    // Rate limiting
    if (this.config.rateLimiter && clientIdentifier) {
      const allowed = await this.config.rateLimiter.allowRequest(clientIdentifier);
      if (!allowed) {
        const internalError = 'Rate limit exceeded';
        const result = { verified: false, error: this.sanitizeError(internalError) };
        this.emitVerificationEvent(
          request.claimType,
          result,
          startTime,
          clientIdentifier,
          internalError,
        );
        return result;
      }
    }

    // Protocol version enforcement
    const protocolResult = this.checkProtocolVersion(
      clientProtocolVersion,
      request.claimType,
      startTime,
      clientIdentifier,
    );
    if (protocolResult) {
      return protocolResult;
    }

    // Validate timestamp and nonce binding
    const requestMs = Date.parse(request.requestTimestamp);
    if (Number.isNaN(requestMs)) {
      const internalError = 'Invalid request timestamp';
      const result = { verified: false, error: this.sanitizeError(internalError) };
      this.emitVerificationEvent(
        request.claimType,
        result,
        startTime,
        clientIdentifier,
        internalError,
      );
      return result;
    }

    // Check for future timestamps (time-shifted proofs)
    const maxFutureSkew = this.config.maxFutureSkewMs ?? 60000; // Default: 1 minute clock skew
    const timeDiffMs = requestMs - Date.now();
    if (timeDiffMs > maxFutureSkew) {
      const internalError = 'Request timestamp is too far in the future';
      const result = { verified: false, error: this.sanitizeError(internalError) };
      this.emitVerificationEvent(
        request.claimType,
        result,
        startTime,
        clientIdentifier,
        internalError,
      );
      return result;
    }

    // Check for stale timestamps (replay protection)
    if (this.config.maxRequestAgeMs !== undefined) {
      const ageMs = Date.now() - requestMs;
      if (ageMs > this.config.maxRequestAgeMs) {
        const internalError = 'Request timestamp is too old';
        const result = { verified: false, error: this.sanitizeError(internalError) };
        this.emitVerificationEvent(
          request.claimType,
          result,
          startTime,
          clientIdentifier,
          internalError,
        );
        return result;
      }
    }

    const challengeError = await this.validateChallenge(request.nonce, requestMs);
    if (challengeError) {
      const result = { verified: false, error: this.sanitizeError(challengeError) };
      this.emitVerificationEvent(
        request.claimType,
        result,
        startTime,
        clientIdentifier,
        challengeError,
      );
      return result;
    }

    // Replay protection
    if (this.config.nonceStore) {
      const nonceUsed = await this.config.nonceStore.has(request.nonce);
      if (nonceUsed) {
        const internalError = 'Nonce already used (replay attack detected)';
        const result = {
          verified: false,
          error: this.sanitizeError(internalError),
        };
        this.emitVerificationEvent(
          request.claimType,
          result,
          startTime,
          clientIdentifier,
          internalError,
        );
        return result;
      }
    }

    const trustedBits = this.config.issuerPublicKeyBits?.[request.issuer];
    if (!trustedBits) {
      const internalError = 'Unknown or untrusted issuer';
      const result = { verified: false, error: this.sanitizeError(internalError) };
      this.emitVerificationEvent(
        request.claimType,
        result,
        startTime,
        clientIdentifier,
        internalError,
      );
      return result;
    }

    // Bind nonce and timestamp to proof public signals
    const proofNonce = this.getSignedProofNonce(request.proof, request.claimType);
    if (!constantTimeEqual(proofNonce, request.nonce)) {
      const internalError = 'Proof nonce does not match request nonce';
      const result = { verified: false, error: this.sanitizeError(internalError) };
      this.emitVerificationEvent(
        request.claimType,
        result,
        startTime,
        clientIdentifier,
        internalError,
      );
      return result;
    }
    const proofTimestamp = this.getSignedProofTimestamp(request.proof, request.claimType);
    if (proofTimestamp !== requestMs) {
      const internalError = 'Proof timestamp does not match request timestamp';
      const result = {
        verified: false,
        error: this.sanitizeError(internalError),
      };
      this.emitVerificationEvent(
        request.claimType,
        result,
        startTime,
        clientIdentifier,
        internalError,
      );
      return result;
    }

    // Policy enforcement
    const requiredPolicy = this.config.requiredPolicy;
    if (request.claimType === 'age') {
      const requiredMinAge = requiredPolicy?.minAge ?? this.config.requiredMinAge;
      if (requiredMinAge !== undefined) {
        const proof = request.proof as AgeProofSigned;
        if (proof.publicSignals.minAge !== requiredMinAge) {
          const internalError = 'Proof does not satisfy required minimum age';
          const result = {
            verified: false,
            error: this.sanitizeError(internalError),
          };
          this.emitVerificationEvent(
            request.claimType,
            result,
            startTime,
            clientIdentifier,
            internalError,
          );
          return result;
        }
      }
    }
    if (request.claimType === 'nationality') {
      const requiredNationality = requiredPolicy?.nationality ?? this.config.requiredNationality;
      if (requiredNationality !== undefined) {
        const proof = request.proof as NationalityProofSigned;
        if (proof.publicSignals.targetNationality !== requiredNationality) {
          const internalError = 'Proof does not satisfy required nationality';
          const result = {
            verified: false,
            error: this.sanitizeError(internalError),
          };
          this.emitVerificationEvent(
            request.claimType,
            result,
            startTime,
            clientIdentifier,
            internalError,
          );
          return result;
        }
      }
    }

    // Revocation check using commitment in proof
    if (this.config.revocationStore) {
      const commitment = this.getSignedProofCommitment(request.proof, request.claimType);
      const isRevoked = await this.config.revocationStore.isRevoked(commitment);
      if (isRevoked) {
        const internalError = 'Credential has been revoked';
        const result = {
          verified: false,
          error: this.sanitizeError(internalError),
        };
        this.emitVerificationEvent(
          request.claimType,
          result,
          startTime,
          clientIdentifier,
          internalError,
        );
        return result;
      }
    }

    let verified = false;
    let internalError: string | undefined;
    try {
      if (request.claimType === 'age') {
        if (!this.signedVerificationKey) {
          internalError = 'Signed age verification key not configured';
          const result = { verified: false, error: this.sanitizeError(internalError) };
          this.emitVerificationEvent(
            request.claimType,
            result,
            startTime,
            clientIdentifier,
            internalError,
          );
          return result;
        }
        verified = await verifyAgeProofSignedWithIssuer(
          request.proof as AgeProofSigned,
          this.signedVerificationKey,
          trustedBits,
        );
      } else {
        if (!this.signedNationalityVerificationKey) {
          internalError = 'Signed nationality verification key not configured';
          const result = { verified: false, error: this.sanitizeError(internalError) };
          this.emitVerificationEvent(
            request.claimType,
            result,
            startTime,
            clientIdentifier,
            internalError,
          );
          return result;
        }
        verified = await verifyNationalityProofSignedWithIssuer(
          request.proof as NationalityProofSigned,
          this.signedNationalityVerificationKey,
          trustedBits,
        );
      }
    } catch (error) {
      internalError = `Verification error: ${error}`;
      const result = { verified: false, error: this.sanitizeError(internalError) };
      this.emitVerificationEvent(
        request.claimType,
        result,
        startTime,
        clientIdentifier,
        internalError,
      );
      return result;
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
          protocolVersion: PROTOCOL_VERSION,
        }
      : ((internalError = 'Proof verification failed'),
        { verified: false, error: this.sanitizeError(internalError) });

    this.emitVerificationEvent(
      request.claimType,
      result,
      startTime,
      clientIdentifier,
      internalError,
    );
    return result;
  }

  /**
   * Verify a multi-claim proof bundle with a shared nonce + timestamp.
   *
   * @param response - Multi-claim proof response
   * @param clientIdentifier - Optional client IP/session for rate limiting
   * @param clientProtocolVersion - Optional client protocol version for compatibility checking
   * @returns Multi-claim verification result
   */
  async verifyMultiClaim(
    response: MultiClaimResponse,
    clientIdentifier?: string,
    clientProtocolVersion?: string,
  ): Promise<MultiClaimVerificationResult> {
    const startTime = Date.now();
    const requireSigned = this.config.requireSignedCredentials !== false;
    type LooseClaimProof = { label?: string; claimType?: string; proof?: unknown };
    const responseProofs = (response as { proofs?: unknown }).proofs;
    const safeProofs: LooseClaimProof[] = Array.isArray(responseProofs)
      ? (responseProofs as LooseClaimProof[])
      : [];

    const failAll = (internalError: string): MultiClaimVerificationResult => {
      const error = this.sanitizeError(internalError);
      const results: ClaimVerificationResult[] = safeProofs.map((proof) => {
        const claimType = typeof proof?.claimType === 'string' ? proof.claimType : 'unknown';
        const label = typeof proof?.label === 'string' ? proof.label : 'unknown';
        const result: VerificationResult = { verified: false, error };
        this.emitVerificationEvent(claimType, result, startTime, clientIdentifier, internalError);
        return { label, verified: false, error };
      });

      if (results.length === 0) {
        return { results: [], allVerified: false, verifiedCount: 0, totalCount: 0 };
      }

      return aggregateVerificationResults(results);
    };

    // Strict payload validation (enabled by default)
    if (this.config.validatePayloads !== false) {
      const payloadErrors = validateMultiClaimResponsePayload(response, requireSigned);
      if (payloadErrors.length > 0) {
        const msg = payloadErrors.map((e) => `${e.field}: ${e.message}`).join('; ');
        return failAll(`Invalid payload: ${msg}`);
      }
    }

    // Rate limiting
    if (this.config.rateLimiter && clientIdentifier) {
      const allowed = await this.config.rateLimiter.allowRequest(clientIdentifier);
      if (!allowed) {
        return failAll('Rate limit exceeded');
      }
    }

    // Protocol version enforcement (no per-proof event emission here)
    const protocolResult = this.checkProtocolVersion(
      clientProtocolVersion,
      'multi-claim',
      startTime,
      clientIdentifier,
      false,
    );
    if (protocolResult) {
      return failAll(protocolResult.error ?? 'Incompatible protocol version');
    }

    // Request timestamp validation
    const requestTimestamp = response.requestTimestamp;
    if (!requestTimestamp) {
      return failAll('Missing request timestamp');
    }
    const requestMs = Date.parse(requestTimestamp);
    if (Number.isNaN(requestMs)) {
      return failAll('Invalid request timestamp');
    }

    // Check for future timestamps (time-shifted proofs)
    const maxFutureSkew = this.config.maxFutureSkewMs ?? 60000;
    const timeDiffMs = requestMs - Date.now();
    if (timeDiffMs > maxFutureSkew) {
      return failAll('Request timestamp is too far in the future');
    }

    // Check for stale timestamps (replay protection)
    if (this.config.maxRequestAgeMs !== undefined) {
      const ageMs = Date.now() - requestMs;
      if (ageMs > this.config.maxRequestAgeMs) {
        return failAll('Request timestamp is too old');
      }
    }

    const challengeError = await this.validateChallenge(response.nonce, requestMs);
    if (challengeError) {
      return failAll(challengeError);
    }

    // Replay protection
    if (this.config.nonceStore) {
      const nonceUsed = await this.config.nonceStore.has(response.nonce);
      if (nonceUsed) {
        return failAll('Nonce already used (replay attack detected)');
      }
    }

    if (requireSigned && !response.signedCredential) {
      return failAll('Signed credential required');
    }

    if (safeProofs.length === 0) {
      return failAll('No proofs provided');
    }

    const results: ClaimVerificationResult[] = [];
    for (const claim of safeProofs) {
      const label = claim.label;
      let internalError: string | undefined;
      let result: VerificationResult | undefined;

      const proofResponse: ProofResponse = {
        credentialId: response.credentialId,
        claimType: claim.claimType,
        proof: claim.proof,
        signedCredential: response.signedCredential,
        nonce: response.nonce,
        requestTimestamp: response.requestTimestamp,
      };

      if (!['age', 'nationality', 'age-revocable'].includes(claim.claimType)) {
        internalError = 'Unknown claim type';
      } else {
        const proofType = (claim.proof as { proofType?: string } | undefined)?.proofType;
        if (proofType && proofType !== claim.claimType) {
          internalError = 'Proof type does not match claim type';
        }
      }

      // Policy enforcement
      if (!internalError) {
        const requiredPolicy = this.config.requiredPolicy;
        if (claim.claimType === 'age') {
          const requiredMinAge = requiredPolicy?.minAge ?? this.config.requiredMinAge;
          if (requiredMinAge !== undefined) {
            const proof = claim.proof as AgeProof;
            if (proof.publicSignals.minAge !== requiredMinAge) {
              internalError = 'Proof does not satisfy required minimum age';
            }
          }
        }
        if (claim.claimType === 'age-revocable') {
          const requiredMinAge = requiredPolicy?.minAge ?? this.config.requiredMinAge;
          if (requiredMinAge !== undefined) {
            const proof = claim.proof as AgeProofRevocable;
            if (proof.publicSignals.minAge !== requiredMinAge) {
              internalError = 'Proof does not satisfy required minimum age';
            }
          }
        }
        if (claim.claimType === 'nationality') {
          const requiredNationality =
            requiredPolicy?.nationality ?? this.config.requiredNationality;
          if (requiredNationality !== undefined) {
            const proof = claim.proof as NationalityProof;
            if (proof.publicSignals.targetNationality !== requiredNationality) {
              internalError = 'Proof does not satisfy required nationality';
            }
          }
        }
      }

      // Nonce binding: ensure proof public nonce matches the request nonce
      if (!internalError) {
        const proofNonce = this.getProofNonce(proofResponse);
        if (!constantTimeEqual(proofNonce, response.nonce)) {
          internalError = 'Proof nonce does not match request nonce';
        }
      }

      // Timestamp binding: ensure proof public timestamp matches request timestamp
      if (!internalError) {
        const proofTimestamp = this.getProofTimestamp(proofResponse);
        if (proofTimestamp !== requestMs) {
          internalError = 'Proof timestamp does not match request timestamp';
        }
      }

      // Signed credential validation (issuer trust + binding)
      if (!internalError && requireSigned) {
        const signedCredential = response.signedCredential!;
        const bindingCheck = await this.validateSignedCredentialBinding(
          signedCredential,
          proofResponse,
        );
        if (!bindingCheck.valid) {
          internalError = bindingCheck.error!;
        }
      }

      // Revocation check (use credential commitment)
      if (!internalError && this.config.revocationStore) {
        const commitment = this.getCredentialCommitmentFromProof(proofResponse);
        const isRevoked = await this.config.revocationStore.isRevoked(commitment);
        if (isRevoked) {
          internalError = 'Credential has been revoked';
        }
      }

      if (internalError) {
        result = {
          verified: false,
          error: this.sanitizeError(internalError),
        };
      } else if (claim.claimType === 'age') {
        const verification = await this.verifyAgeProofInternal(proofResponse, { markNonce: false });
        result = verification.result;
        internalError = verification.internalError;
      } else if (claim.claimType === 'nationality') {
        const verification = await this.verifyNationalityProofInternal(proofResponse, {
          markNonce: false,
        });
        result = verification.result;
        internalError = verification.internalError;
      } else if (claim.claimType === 'age-revocable') {
        const verification = await this.verifyAgeProofRevocableInternal(proofResponse, {
          markNonce: false,
        });
        result = verification.result;
        internalError = verification.internalError;
      } else {
        internalError = 'Unknown claim type';
        result = {
          verified: false,
          error: this.sanitizeError(internalError),
        };
      }

      this.emitVerificationEvent(
        claim.claimType,
        result,
        startTime,
        clientIdentifier,
        internalError,
      );

      results.push({
        label,
        verified: result.verified,
        error: result.error,
      });
    }

    if (results.length === 0) {
      return { results: [], allVerified: false, verifiedCount: 0, totalCount: 0 };
    }

    const aggregated = aggregateVerificationResults(results);
    if (aggregated.allVerified && this.config.nonceStore) {
      await this.config.nonceStore.add(response.nonce);
    }

    return aggregated;
  }

  /**
   * Internal age proof verification
   */
  private async verifyAgeProofInternal(
    proofResponse: ProofResponse,
    options: { markNonce?: boolean } = {},
  ): Promise<{ result: VerificationResult; internalError?: string }> {
    const proof = proofResponse.proof as AgeProof;

    // Validate proof constraints
    const constraintCheck = validateProofConstraints(proof);
    if (!constraintCheck.valid) {
      const internalError = `Invalid proof constraints: ${constraintCheck.errors.join(', ')}`;
      return {
        result: {
          verified: false,
          error: this.sanitizeError(internalError),
        },
        internalError,
      };
    }

    // Cryptographically verify the proof
    try {
      const isValid = await verifyAgeProof(proof, this.verificationKey);

      if (isValid) {
        if (options.markNonce !== false && this.config.nonceStore) {
          await this.config.nonceStore.add(proofResponse.nonce);
        }

        return {
          result: {
            verified: true,
            claimType: proofResponse.claimType,
            minAge: proof.publicSignals.minAge,
            protocolVersion: PROTOCOL_VERSION,
          },
        };
      } else {
        const internalError = 'Proof verification failed';
        return {
          result: {
            verified: false,
            error: this.sanitizeError(internalError),
          },
          internalError,
        };
      }
    } catch (error) {
      const internalError = `Verification error: ${error}`;
      return {
        result: {
          verified: false,
          error: this.sanitizeError(internalError),
        },
        internalError,
      };
    }
  }

  /**
   * Internal nationality proof verification
   */
  private async verifyNationalityProofInternal(
    proofResponse: ProofResponse,
    options: { markNonce?: boolean } = {},
  ): Promise<{ result: VerificationResult; internalError?: string }> {
    const proof = proofResponse.proof as NationalityProof;

    if (!this.nationalityVerificationKey) {
      const internalError = 'Nationality verification key not configured';
      return {
        result: {
          verified: false,
          error: this.sanitizeError(internalError),
        },
        internalError,
      };
    }

    // Validate proof constraints
    const constraintCheck = validateNationalityProofConstraints(proof);
    if (!constraintCheck.valid) {
      const internalError = `Invalid proof constraints: ${constraintCheck.errors.join(', ')}`;
      return {
        result: {
          verified: false,
          error: this.sanitizeError(internalError),
        },
        internalError,
      };
    }

    // Cryptographically verify the proof
    try {
      const isValid = await verifyNationalityProof(proof, this.nationalityVerificationKey);

      if (isValid) {
        if (options.markNonce !== false && this.config.nonceStore) {
          await this.config.nonceStore.add(proofResponse.nonce);
        }

        return {
          result: {
            verified: true,
            claimType: proofResponse.claimType,
            targetNationality: proof.publicSignals.targetNationality,
            protocolVersion: PROTOCOL_VERSION,
          },
        };
      } else {
        const internalError = 'Proof verification failed';
        return {
          result: {
            verified: false,
            error: this.sanitizeError(internalError),
          },
          internalError,
        };
      }
    } catch (error) {
      const internalError = `Verification error: ${error}`;
      return {
        result: {
          verified: false,
          error: this.sanitizeError(internalError),
        },
        internalError,
      };
    }
  }

  /**
   * Internal revocable age proof verification
   */
  private async verifyAgeProofRevocableInternal(
    proofResponse: ProofResponse,
    options: { markNonce?: boolean } = {},
  ): Promise<{ result: VerificationResult; internalError?: string }> {
    const proof = proofResponse.proof as AgeProofRevocable;

    if (!this.revocableVerificationKey) {
      const internalError = 'Revocable age verification key not configured';
      return {
        result: {
          verified: false,
          error: this.sanitizeError(internalError),
        },
        internalError,
      };
    }

    // Revocation root staleness check (before proof validation)
    if (
      this.config.maxRevocationRootAgeMs !== undefined &&
      this.config.validCredentialTree?.getRootInfo
    ) {
      const rootInfo = await this.config.validCredentialTree.getRootInfo();
      const rootAgeMs = Date.now() - Date.parse(rootInfo.updatedAt);
      if (rootAgeMs > this.config.maxRevocationRootAgeMs) {
        const internalError = 'Revocation root is stale';
        return {
          result: {
            verified: false,
            error: this.sanitizeError(internalError),
          },
          internalError,
        };
      }
    }

    // Validate proof constraints
    const constraintCheck = validateAgeProofRevocableConstraints(proof);
    if (!constraintCheck.valid) {
      const internalError = `Invalid proof constraints: ${constraintCheck.errors.join(', ')}`;
      return {
        result: {
          verified: false,
          error: this.sanitizeError(internalError),
        },
        internalError,
      };
    }

    // Optional Merkle root freshness check
    const expectedRoot = this.config.validCredentialTree
      ? await this.config.validCredentialTree.getRoot()
      : undefined;

    // Cryptographically verify the proof
    try {
      const isValid = await verifyAgeProofRevocable(
        proof,
        this.revocableVerificationKey,
        expectedRoot,
      );

      if (isValid) {
        if (options.markNonce !== false && this.config.nonceStore) {
          await this.config.nonceStore.add(proofResponse.nonce);
        }

        return {
          result: {
            verified: true,
            claimType: proofResponse.claimType,
            minAge: proof.publicSignals.minAge,
            protocolVersion: PROTOCOL_VERSION,
          },
        };
      } else {
        const internalError = 'Proof verification failed';
        return {
          result: {
            verified: false,
            error: this.sanitizeError(internalError),
          },
          internalError,
        };
      }
    } catch (error) {
      const internalError = `Verification error: ${error}`;
      return {
        result: {
          verified: false,
          error: this.sanitizeError(internalError),
        },
        internalError,
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
    proofResponse: ProofResponse,
  ): Promise<{ valid: boolean; error?: string }> {
    const issuerRecord = await this.getIssuerRecord(signedCredential.issuer);
    const issuerKey = issuerRecord?.publicKey;
    if (!issuerKey) {
      return { valid: false, error: this.sanitizeError('Unknown or untrusted issuer') };
    }
    if (issuerRecord?.status && issuerRecord.status !== 'active') {
      return { valid: false, error: this.sanitizeError('Issuer is not active') };
    }
    if (issuerRecord?.validFrom || issuerRecord?.validTo) {
      const now = Date.now();
      if (issuerRecord.validFrom && Date.parse(issuerRecord.validFrom) > now) {
        return { valid: false, error: this.sanitizeError('Issuer key not yet valid') };
      }
      if (issuerRecord.validTo) {
        const validToMs = Date.parse(issuerRecord.validTo);
        if (validToMs < now) {
          const graceMs = issuerRecord.rotationGracePeriodMs ?? 0;
          const withinGrace = graceMs > 0 && now - validToMs <= graceMs;
          if (!withinGrace) {
            return { valid: false, error: this.sanitizeError('Issuer key expired') };
          }
          // Grace period accepted - log for audit
          // Note: grace period is also checked in InMemoryIssuerRegistry.getIssuer()
          if (withinGrace) {
            try {
              this.auditLogger.log({
                timestamp: new Date().toISOString(),
                action: 'grace_period_accept',
                actor: issuerRecord.issuer,
                target: issuerRecord.issuer,
                success: true,
                metadata: {
                  validTo: issuerRecord.validTo,
                  graceMs,
                  expiredAgoMs: now - validToMs,
                },
              });
            } catch {
              // Avoid turning telemetry failures into verification failures.
            }
          }
        }
      }
    }

    const payload = credentialSignaturePayload(
      signedCredential.credential,
      signedCredential.issuer,
      signedCredential.issuedAt,
    );
    const signature = Buffer.from(signedCredential.signature, 'base64');
    const signatureValid = cryptoVerify(null, Buffer.from(payload), issuerKey, signature);
    if (!signatureValid) {
      return { valid: false, error: this.sanitizeError('Invalid credential signature') };
    }

    if (
      proofResponse.credentialId &&
      proofResponse.credentialId !== signedCredential.credential.id
    ) {
      return { valid: false, error: this.sanitizeError('Credential ID mismatch') };
    }

    const proofCommitment = this.getCredentialCommitmentFromProof(proofResponse);
    if (!constantTimeEqual(proofCommitment, signedCredential.credential.commitment)) {
      return { valid: false, error: this.sanitizeError('Credential commitment mismatch') };
    }

    return { valid: true };
  }

  private getCredentialCommitmentFromProof(proofResponse: ProofResponse): string {
    const proof = proofResponse.proof as AgeProof | NationalityProof | AgeProofRevocable;
    if (proofResponse.claimType === 'age') {
      return (proof as AgeProof).publicSignals.credentialHash;
    }
    if (proofResponse.claimType === 'nationality') {
      return (proof as NationalityProof).publicSignals.credentialHash;
    }
    if (proofResponse.claimType === 'age-revocable') {
      return (proof as AgeProofRevocable).publicSignals.credentialHash;
    }
    return '';
  }

  private getProofNonce(proofResponse: ProofResponse): string {
    const proof = proofResponse.proof as AgeProof | NationalityProof | AgeProofRevocable;
    if (proofResponse.claimType === 'age') {
      return (proof as AgeProof).publicSignals.nonce;
    }
    if (proofResponse.claimType === 'nationality') {
      return (proof as NationalityProof).publicSignals.nonce;
    }
    if (proofResponse.claimType === 'age-revocable') {
      return (proof as AgeProofRevocable).publicSignals.nonce;
    }
    return '';
  }

  private getProofTimestamp(proofResponse: ProofResponse): number {
    const proof = proofResponse.proof as AgeProof | NationalityProof | AgeProofRevocable;
    if (proofResponse.claimType === 'age') {
      return (proof as AgeProof).publicSignals.requestTimestamp;
    }
    if (proofResponse.claimType === 'nationality') {
      return (proof as NationalityProof).publicSignals.requestTimestamp;
    }
    if (proofResponse.claimType === 'age-revocable') {
      return (proof as AgeProofRevocable).publicSignals.requestTimestamp;
    }
    return 0;
  }

  private async validateChallenge(
    nonce: string,
    requestTimestampMs: number,
  ): Promise<string | null> {
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
    claimType: 'age' | 'nationality',
  ): string {
    if (claimType === 'age') {
      return (proof as AgeProofSigned).publicSignals.nonce;
    }
    return (proof as NationalityProofSigned).publicSignals.nonce;
  }

  private getSignedProofTimestamp(
    proof: AgeProofSigned | NationalityProofSigned,
    claimType: 'age' | 'nationality',
  ): number {
    if (claimType === 'age') {
      return (proof as AgeProofSigned).publicSignals.requestTimestamp;
    }
    return (proof as NationalityProofSigned).publicSignals.requestTimestamp;
  }

  private getSignedProofCommitment(
    proof: AgeProofSigned | NationalityProofSigned,
    claimType: 'age' | 'nationality',
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
    clientIdentifier?: string,
    internalError?: string,
  ): void {
    const timestamp = new Date().toISOString();
    const event: VerificationEvent = {
      timestamp,
      claimType,
      verified: result.verified,
      verificationTimeMs: Date.now() - startTime,
      clientIdentifier,
      error: result.error,
    };
    this.emit('verification', event);

    // Structured audit log entry (best-effort)
    try {
      this.auditLogger.log({
        timestamp,
        action: 'verify',
        actor: clientIdentifier ?? 'unknown',
        target: claimType,
        success: result.verified,
        metadata: {
          verificationTimeMs: event.verificationTimeMs,
          ...(internalError
            ? { error: internalError }
            : result.error
              ? { error: result.error }
              : {}),
        },
      });
    } catch {
      // Avoid turning telemetry failures into verification failures.
    }
  }

  /**
   * Register a callback for verification events
   *
   * @param callback - Function to call when a verification occurs
   */
  onVerification(callback: (event: VerificationEvent) => void): void {
    this.on('verification', callback);
  }

  /**
   * Get current revocation root info (if valid credential tree is configured).
   *
   * Populates `expiresAt`, `ttlSeconds`, and `source` from server config when available.
   *
   * @returns Revocation root metadata including version, TTL, and expiration time
   * @throws Error if valid credential tree is not configured
   */
  async getRevocationRootInfo(): Promise<RevocationRootInfo> {
    if (!this.config.validCredentialTree) {
      throw new Error('Valid credential tree not configured');
    }

    let info: RevocationRootInfo;
    if (this.config.validCredentialTree.getRootInfo) {
      info = await this.config.validCredentialTree.getRootInfo();
    } else {
      const root = await this.config.validCredentialTree.getRoot();
      info = {
        root,
        version: 0,
        updatedAt: new Date().toISOString(),
      };
    }

    const ttl = this.config.revocationRootTtlSeconds ?? DEFAULT_REVOCATION_ROOT_TTL_SECONDS;
    info.ttlSeconds = ttl;
    info.expiresAt = new Date(Date.parse(info.updatedAt) + ttl * 1000).toISOString();
    if (this.config.revocationRootSource) {
      info.source = this.config.revocationRootSource;
    }

    return info;
  }

  private checkProtocolVersion(
    clientProtocolVersion: string | undefined,
    claimType: string,
    startTime: number,
    clientIdentifier?: string,
    emitEvent: boolean = true,
  ): VerificationResult | null {
    const policy: ProtocolVersionPolicy = this.config.protocolVersionPolicy ?? 'warn';
    if (policy === 'off') {
      return null;
    }

    if (!clientProtocolVersion) {
      if (policy === 'strict') {
        const result: VerificationResult = {
          verified: false,
          error: this.sanitizeError('Missing protocol version'),
          protocolVersion: PROTOCOL_VERSION,
        };
        if (emitEvent) {
          this.emitVerificationEvent(claimType, result, startTime, clientIdentifier);
        }
        return result;
      }
      console.warn(
        `[zk-id] Protocol version header missing for claimType=${claimType}. ` +
          `Server=${PROTOCOL_VERSION}`,
      );
      return null;
    }

    if (!isProtocolCompatible(PROTOCOL_VERSION, clientProtocolVersion)) {
      if (policy === 'strict') {
        const result: VerificationResult = {
          verified: false,
          error: this.sanitizeError('Incompatible protocol version'),
          protocolVersion: PROTOCOL_VERSION,
        };
        if (emitEvent) {
          this.emitVerificationEvent(claimType, result, startTime, clientIdentifier);
        }
        return result;
      }
      console.warn(
        `[zk-id] Protocol version mismatch for claimType=${claimType}. ` +
          `Client=${clientProtocolVersion}, Server=${PROTOCOL_VERSION}`,
      );
    }

    return null;
  }
}

export interface VerificationResult {
  verified: boolean;
  claimType?: string;
  minAge?: number;
  targetNationality?: number;
  error?: string;
  protocolVersion?: string;
}

/**
 * Simple in-memory nonce store (for demo)
 * Production should use Redis or database
 */
export interface InMemoryNonceStoreOptions {
  /** TTL for nonce entries in ms (default: 5 minutes). */
  ttlMs?: number;
  /** Prune interval in ms. Set to 0 to disable background pruning. */
  pruneIntervalMs?: number;
}

export class InMemoryNonceStore implements NonceStore {
  private nonces: Map<string, number> = new Map();
  private ttlMs: number;
  private pruneIntervalMs: number;
  private pruneTimer?: NodeJS.Timeout;

  constructor(options: InMemoryNonceStoreOptions = {}) {
    this.ttlMs = options.ttlMs ?? 5 * 60 * 1000;
    this.pruneIntervalMs = options.pruneIntervalMs ?? 60 * 1000;
    if (this.pruneIntervalMs > 0) {
      this.pruneTimer = setInterval(() => this.prune(), this.pruneIntervalMs);
      this.pruneTimer.unref?.();
    }
  }

  async has(nonce: string): Promise<boolean> {
    const expiresAtMs = this.nonces.get(nonce);
    if (!expiresAtMs) {
      return false;
    }

    if (Date.now() > expiresAtMs) {
      this.nonces.delete(nonce);
      return false;
    }

    return true;
  }

  async add(nonce: string): Promise<void> {
    const expiresAtMs = Date.now() + this.ttlMs;
    this.nonces.set(nonce, expiresAtMs);
  }

  /**
   * Optional: Prune expired nonces
   * Call periodically if needed to prevent unbounded growth
   */
  prune(): void {
    const now = Date.now();
    for (const [nonce, expiresAtMs] of this.nonces.entries()) {
      if (now > expiresAtMs) {
        this.nonces.delete(nonce);
      }
    }
  }

  /**
   * Stop background pruning (if enabled).
   */
  stop(): void {
    if (this.pruneTimer) {
      clearInterval(this.pruneTimer);
      this.pruneTimer = undefined;
    }
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

/**
 * Static verification key provider for in-memory keys.
 * Useful for testing or when keys are loaded at startup.
 */
export class StaticVerificationKeyProvider implements VerificationKeyProvider {
  private keys: VerificationKeySet;

  constructor(keys: VerificationKeySet) {
    this.keys = keys;
  }

  /**
   * Get the verification keys
   *
   * @returns The configured verification key set
   */
  async getVerificationKeys(): Promise<VerificationKeySet> {
    return this.keys;
  }
}

/**
 * Simple in-memory rate limiter using a sliding window (for demo/development).
 *
 * **WARNING: NOT SUITABLE FOR PRODUCTION**
 *
 * This implementation is trivially bypassable in production environments:
 * - IP-based identification can be spoofed or rotated (proxies, VPNs, botnets)
 * - In-memory storage is lost on restart
 * - Does not synchronize across multiple server instances
 *
 * **Production recommendations:**
 * - Use a token bucket algorithm with authenticated session identifiers (not IPs)
 * - Implement rate limiting at the API gateway or reverse proxy layer (nginx, Cloudflare, AWS API Gateway)
 * - For custom implementations, use a distributed store (Redis with sliding window or token bucket)
 * - Consider per-user, per-endpoint, and global rate limits
 *
 * **For custom implementations**, implement the `RateLimiter` interface with your chosen strategy.
 *
 * @example
 * // Development only
 * const rateLimiter = new SimpleRateLimiter(10, 60000); // 10 requests per minute
 *
 * @example
 * // Production: Use external rate limiting
 * // Option 1: API Gateway (nginx limit_req_zone, Cloudflare rate limiting rules)
 * // Option 2: Redis-based token bucket
 * class RedisRateLimiter implements RateLimiter {
 *   async allowRequest(sessionId: string): Promise<boolean> {
 *     // Implement token bucket with Redis INCR + EXPIRE
 *   }
 * }
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
    const recentRequests = requests.filter((time) => now - time < this.windowMs);

    if (recentRequests.length >= this.limit) {
      return false;
    }

    recentRequests.push(now);
    this.requests.set(identifier, recentRequests);

    return true;
  }
}

// ---------------------------------------------------------------------------
// Payload validation helpers (T-007)
// ---------------------------------------------------------------------------

export interface PayloadValidationError {
  field: string;
  message: string;
}

/**
 * Validate a ProofResponse payload structure before cryptographic verification.
 * Returns an empty array when the payload is well-formed.
 */
export function validateProofResponsePayload(
  body: unknown,
  requireSignedCredential: boolean = true,
): PayloadValidationError[] {
  const errors: PayloadValidationError[] = [];
  if (!body || typeof body !== 'object') {
    return [{ field: '(root)', message: 'Body must be a non-null object' }];
  }
  const obj = body as Record<string, unknown>;

  if (
    typeof obj.claimType !== 'string' ||
    !['age', 'nationality', 'age-revocable'].includes(obj.claimType)
  ) {
    errors.push({
      field: 'claimType',
      message: "Must be 'age', 'nationality', or 'age-revocable'",
    });
  }
  if (typeof obj.nonce !== 'string' || obj.nonce.length === 0) {
    errors.push({ field: 'nonce', message: 'Must be a non-empty string' });
  }
  if (typeof obj.requestTimestamp !== 'string') {
    errors.push({ field: 'requestTimestamp', message: 'Must be a string (ISO 8601)' });
  }
  if (!obj.proof || typeof obj.proof !== 'object') {
    errors.push({ field: 'proof', message: 'Must be a non-null object' });
  } else {
    const proof = obj.proof as Record<string, unknown>;
    if (!proof.proof || typeof proof.proof !== 'object') {
      errors.push({ field: 'proof.proof', message: 'Must be a non-null object' });
    }
    if (!proof.publicSignals || typeof proof.publicSignals !== 'object') {
      errors.push({ field: 'proof.publicSignals', message: 'Must be a non-null object' });
    }
  }
  if (requireSignedCredential) {
    if (!obj.signedCredential || typeof obj.signedCredential !== 'object') {
      errors.push({ field: 'signedCredential', message: 'Must be a non-null object' });
    }
  }
  return errors;
}

/**
 * Validate a MultiClaimResponse payload structure.
 * Returns an empty array when the payload is well-formed.
 */
export function validateMultiClaimResponsePayload(
  body: unknown,
  requireSignedCredential: boolean = true,
): PayloadValidationError[] {
  const errors: PayloadValidationError[] = [];
  if (!body || typeof body !== 'object') {
    return [{ field: '(root)', message: 'Body must be a non-null object' }];
  }
  const obj = body as Record<string, unknown>;

  if (!Array.isArray(obj.proofs) || obj.proofs.length === 0) {
    errors.push({ field: 'proofs', message: 'Must be a non-empty array' });
  }
  if (typeof obj.nonce !== 'string' || obj.nonce.length === 0) {
    errors.push({ field: 'nonce', message: 'Must be a non-empty string' });
  }
  if (typeof obj.requestTimestamp !== 'string') {
    errors.push({ field: 'requestTimestamp', message: 'Must be a string (ISO 8601)' });
  }
  if (typeof obj.credentialId !== 'string' || obj.credentialId.length === 0) {
    errors.push({ field: 'credentialId', message: 'Must be a non-empty string' });
  }
  if (requireSignedCredential) {
    if (!obj.signedCredential || typeof obj.signedCredential !== 'object') {
      errors.push({ field: 'signedCredential', message: 'Must be a non-null object' });
    }
  }

  if (Array.isArray(obj.proofs)) {
    obj.proofs.forEach((proof, index) => {
      if (!proof || typeof proof !== 'object') {
        errors.push({ field: `proofs[${index}]`, message: 'Must be a non-null object' });
        return;
      }
      const claim = proof as Record<string, unknown>;
      if (typeof claim.label !== 'string' || claim.label.length === 0) {
        errors.push({ field: `proofs[${index}].label`, message: 'Must be a non-empty string' });
      }
      if (
        typeof claim.claimType !== 'string' ||
        !['age', 'nationality', 'age-revocable'].includes(claim.claimType)
      ) {
        errors.push({
          field: `proofs[${index}].claimType`,
          message: "Must be 'age', 'nationality', or 'age-revocable'",
        });
      }
      if (!claim.proof || typeof claim.proof !== 'object') {
        errors.push({ field: `proofs[${index}].proof`, message: 'Must be a non-null object' });
      } else {
        const proofObj = claim.proof as Record<string, unknown>;
        if (!proofObj.proof || typeof proofObj.proof !== 'object') {
          errors.push({
            field: `proofs[${index}].proof.proof`,
            message: 'Must be a non-null object',
          });
        }
        if (!proofObj.publicSignals || typeof proofObj.publicSignals !== 'object') {
          errors.push({
            field: `proofs[${index}].proof.publicSignals`,
            message: 'Must be a non-null object',
          });
        }
      }
    });
  }

  return errors;
}

/**
 * Validate a SignedProofRequest payload structure.
 * Returns an empty array when the payload is well-formed.
 */
export function validateSignedProofRequestPayload(body: unknown): PayloadValidationError[] {
  const errors: PayloadValidationError[] = [];
  if (!body || typeof body !== 'object') {
    return [{ field: '(root)', message: 'Body must be a non-null object' }];
  }
  const obj = body as Record<string, unknown>;

  if (typeof obj.claimType !== 'string' || !['age', 'nationality'].includes(obj.claimType)) {
    errors.push({ field: 'claimType', message: "Must be 'age' or 'nationality'" });
  }
  if (typeof obj.issuer !== 'string' || obj.issuer.length === 0) {
    errors.push({ field: 'issuer', message: 'Must be a non-empty string' });
  }
  if (typeof obj.nonce !== 'string' || obj.nonce.length === 0) {
    errors.push({ field: 'nonce', message: 'Must be a non-empty string' });
  }
  if (typeof obj.requestTimestamp !== 'string') {
    errors.push({ field: 'requestTimestamp', message: 'Must be a string (ISO 8601)' });
  }
  if (!obj.proof || typeof obj.proof !== 'object') {
    errors.push({ field: 'proof', message: 'Must be a non-null object' });
  } else {
    const proof = obj.proof as Record<string, unknown>;
    if (!proof.proof || typeof proof.proof !== 'object') {
      errors.push({ field: 'proof.proof', message: 'Must be a non-null object' });
    }
    if (!proof.publicSignals || typeof proof.publicSignals !== 'object') {
      errors.push({ field: 'proof.publicSignals', message: 'Must be a non-null object' });
    }
  }
  return errors;
}
