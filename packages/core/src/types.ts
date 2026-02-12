/**
 * Core type definitions for zk-id
 */

import type { SerializedBBSDisclosureProof } from './bbs';

/**
 * Credential represents a privacy-preserving identity commitment
 *
 * IMPORTANT: Commitment Binding Limitation
 * The Poseidon commitment binds exactly 3 fields: (birthYear, nationality, salt).
 * This structure is hardcoded in all circuits (age-verify.circom, nationality-verify.circom, etc.).
 * Extending the credential schema (e.g., adding dateOfBirth, name, or other attributes)
 * requires designing, auditing, and deploying new circuits with different Poseidon inputs.
 * Backwards compatibility is NOT automatic — new fields = new commitment = new circuits.
 */
export interface Credential {
  /** Unique identifier for this credential */
  id: string;
  /** Birth year of the credential holder */
  birthYear: number;
  /** Nationality of the credential holder (ISO 3166-1 numeric code) */
  nationality: number;
  /** Random salt for privacy (used in commitment) */
  salt: string;
  /** Poseidon hash commitment: H(birthYear, nationality, salt) — binds exactly 3 fields */
  commitment: string;
  /** ISO 8601 timestamp of credential creation */
  createdAt: string;
}

export interface SignedCredential {
  /** The signed credential */
  credential: Credential;
  /** Issuer name or identifier */
  issuer: string;
  /** Base64-encoded Ed25519 signature */
  signature: string;
  /** ISO 8601 timestamp of issuance */
  issuedAt: string;
  /** Optional ISO 8601 timestamp when credential expires */
  expiresAt?: string;
}

export interface AgeProof {
  /** Discriminator for TypeScript discriminated unions */
  proofType: 'age';
  /** The zero-knowledge proof data (Groth16 format) */
  proof: {
    pi_a: string[];
    pi_b: string[][];
    pi_c: string[];
    protocol: string;
    curve: string;
  };
  /** Public signals used in the proof */
  publicSignals: {
    currentYear: number;
    minAge: number;
    credentialHash: string;
    nonce: string;
    requestTimestamp: number;
  };
}

export interface NationalityProof {
  /** Discriminator for TypeScript discriminated unions */
  proofType: 'nationality';
  /** The zero-knowledge proof data (Groth16 format) */
  proof: {
    pi_a: string[];
    pi_b: string[][];
    pi_c: string[];
    protocol: string;
    curve: string;
  };
  /** Public signals used in the proof */
  publicSignals: {
    targetNationality: number;
    credentialHash: string;
    nonce: string;
    requestTimestamp: number;
  };
}

export interface AgeProofRevocable {
  /** Discriminator for TypeScript discriminated unions */
  proofType: 'age-revocable';
  /** The zero-knowledge proof data (Groth16 format) */
  proof: {
    pi_a: string[];
    pi_b: string[][];
    pi_c: string[];
    protocol: string;
    curve: string;
  };
  /** Public signals used in the proof */
  publicSignals: {
    currentYear: number;
    minAge: number;
    credentialHash: string;
    merkleRoot: string;
    nonce: string;
    requestTimestamp: number;
  };
}

export interface CircuitSignatureInputs {
  /** Issuer public key bits (packed point) */
  issuerPublicKey: string[];
  /** Signature R8 bits */
  signatureR8: string[];
  /** Signature S bits */
  signatureS: string[];
}

export interface AgeProofSigned {
  /** Discriminator for TypeScript discriminated unions */
  proofType: 'age-signed';
  proof: {
    pi_a: string[];
    pi_b: string[][];
    pi_c: string[];
    protocol: string;
    curve: string;
  };
  publicSignals: {
    currentYear: number;
    minAge: number;
    credentialHash: string;
    nonce: string;
    requestTimestamp: number;
    issuerPublicKey: string[];
  };
}

export interface NationalityProofSigned {
  /** Discriminator for TypeScript discriminated unions */
  proofType: 'nationality-signed';
  proof: {
    pi_a: string[];
    pi_b: string[][];
    pi_c: string[];
    protocol: string;
    curve: string;
  };
  publicSignals: {
    targetNationality: number;
    credentialHash: string;
    nonce: string;
    requestTimestamp: number;
    issuerPublicKey: string[];
  };
}

export interface NullifierProof {
  proofType: 'nullifier';
  proof: {
    pi_a: string[];
    pi_b: string[][];
    pi_c: string[];
  };
  publicSignals: {
    credentialHash: string;
    scopeHash: string;
    nullifier: string;
  };
}

export interface BBSSelectiveDisclosureProof {
  proofType: 'bbs-selective-disclosure';
  proof: SerializedBBSDisclosureProof;
  schemaId: string;
  revealedFields: Record<string, unknown>;
}

export interface RangeProof {
  proofType: 'range';
  proof: {
    pi_a: string[];
    pi_b: string[][];
    pi_c: string[];
    protocol: string;
    curve: string;
  };
  publicSignals: string[];
  fieldName: string;
}

/** Discriminated union of all ZK proof types */
export type ZkProof =
  | AgeProof
  | NationalityProof
  | AgeProofRevocable
  | AgeProofSigned
  | NationalityProofSigned
  | NullifierProof
  | BBSSelectiveDisclosureProof
  | RangeProof;

/** String literal type for all proof type discriminators */
export type ProofType = ZkProof['proofType'];

export interface VerificationKey {
  protocol: string;
  curve: string;
  nPublic: number;
  vk_alpha_1: string[];
  vk_beta_2: string[][];
  vk_gamma_2: string[][];
  vk_delta_2: string[][];
  vk_alphabeta_12: string[][][];
  IC: string[][];
}

export interface ProofRequest {
  /** Type of claim being proven */
  claimType: 'age' | 'nationality' | 'age-revocable';
  /** Minimum age required (for age claims) */
  minAge?: number;
  /** Target nationality to verify (for nationality claims) */
  targetNationality?: number;
  /** Nonce to prevent replay attacks */
  nonce: string;
  /** Timestamp of request */
  timestamp: string;
}

export interface ProofResponse {
  /** The credential ID being proven */
  credentialId: string;
  /** The type of claim */
  claimType: string;
  /** The zero-knowledge proof (use proof.proofType to discriminate) */
  proof: ZkProof;
  /** Signed credential (binds issuer and commitment). Optional when requireSignedCredentials is false. */
  signedCredential?: SignedCredential;
  /** Nonce from the request (for replay protection) */
  nonce: string;
  /** Request timestamp (ISO 8601) */
  requestTimestamp: string;
}

/**
 * Response for BBS+ selective disclosure proofs
 */
export interface BBSProofResponse {
  /** The credential ID being proven */
  credentialId: string;
  /** Schema identifier */
  schemaId: string;
  /** BBS+ selective disclosure proof (base format from bbs.ts) */
  proof: SerializedBBSDisclosureProof;
  /** Revealed field values */
  revealedFields: Record<string, unknown>;
  /** Nonce from the request (for replay protection) */
  nonce: string;
  /** Request timestamp (ISO 8601) */
  requestTimestamp: string;
}

export interface BatchVerificationResult {
  /** Per-proof verification results */
  results: { index: number; verified: boolean; error?: string }[];
  /** True if all proofs verified successfully */
  allVerified: boolean;
  /** Number of successfully verified proofs */
  verifiedCount: number;
  /** Total number of proofs checked */
  totalCount: number;
}

export interface RevocationStore {
  /** Check if a credential commitment has been revoked */
  isRevoked(commitment: string): Promise<boolean>;
  /** Revoke a credential commitment */
  revoke(commitment: string): Promise<void>;
  /** Get the count of revoked credentials */
  getRevokedCount(): Promise<number>;
}

/**
 * Append-only index of every credential commitment ever issued.
 *
 * This is NOT a revocation store — it only records that a commitment was
 * issued at some point. Combined with the ValidCredentialTree it allows
 * distinguishing "revoked" (was issued, no longer in tree) from "never
 * issued" (not in tree and never was).
 */
export interface IssuedCredentialIndex {
  /** Record that a commitment was issued. Idempotent. */
  record(commitment: string): Promise<void>;
  /** Check whether a commitment was ever issued. */
  wasIssued(commitment: string): Promise<boolean>;
  /** Total number of commitments ever issued. */
  issuedCount(): Promise<number>;
}

export interface RevocationWitness {
  /** Merkle root at the time of issuance */
  root: string;
  /** 0 = left, 1 = right per level */
  pathIndices: number[];
  /** Sibling hashes for each level */
  siblings: string[];
}

export interface RevocationRootInfo {
  /** Current Merkle root */
  root: string;
  /** Monotonic root version */
  version: number;
  /** ISO 8601 timestamp of last update */
  updatedAt: string;
  /** ISO 8601 timestamp when this root should be considered expired (optional) */
  expiresAt?: string;
  /** Recommended TTL in seconds for caching this root (optional) */
  ttlSeconds?: number;
  /** Identifier for the source/issuer of this root (optional) */
  source?: string;
}

// ---------------------------------------------------------------------------
// Audit Logging
// ---------------------------------------------------------------------------

/**
 * Structured audit log entry produced by issuers and verifiers.
 */
export interface AuditEntry {
  /** ISO 8601 timestamp */
  timestamp: string;
  /** Action that occurred */
  action:
    | 'issue'
    | 'revoke'
    | 'verify'
    | 'suspend'
    | 'reactivate'
    | 'deactivate'
    | 'grace_period_accept';
  /** Actor (issuer name, verifier identifier) */
  actor: string;
  /** Target identifier (credential ID, commitment, issuer name) */
  target?: string;
  /** Whether the action succeeded */
  success: boolean;
  /** Additional structured metadata */
  metadata?: Record<string, unknown>;
}

/**
 * Pluggable audit logger interface.
 *
 * Production implementations should write to tamper-evident storage
 * (append-only database, SIEM, cloud audit trail). The default
 * `ConsoleAuditLogger` writes JSON to stdout and is suitable only for
 * development and testing.
 */
export interface AuditLogger {
  /** Record an audit entry */
  log(entry: AuditEntry): void;
}

/**
 * Console-based audit logger (development/testing only).
 */
export class ConsoleAuditLogger implements AuditLogger {
  log(entry: AuditEntry): void {
    console.log('[AUDIT]', JSON.stringify(entry));
  }
}

/**
 * In-memory audit logger that stores entries for inspection (testing).
 */
export class InMemoryAuditLogger implements AuditLogger {
  readonly entries: AuditEntry[] = [];

  constructor() {
    if (typeof process !== 'undefined' && process.env.NODE_ENV === 'production') {
      console.warn(
        '[zk-id] InMemoryAuditLogger is not suitable for production. ' +
          'Audit entries will be lost on restart. Use a persistent audit logger (SIEM, database).',
      );
    }
  }

  log(entry: AuditEntry): void {
    this.entries.push(entry);
  }

  /** Return entries filtered by action */
  filter(action: AuditEntry['action']): AuditEntry[] {
    return this.entries.filter((e) => e.action === action);
  }

  clear(): void {
    this.entries.length = 0;
  }
}

export interface ValidCredentialTree {
  /** Add a valid credential commitment to the tree */
  add(commitment: string): Promise<void>;
  /** Remove a credential commitment from the tree (on revocation) */
  remove(commitment: string): Promise<void>;
  /** Check if a commitment is in the tree */
  contains(commitment: string): Promise<boolean>;
  /** Get the current Merkle root */
  getRoot(): Promise<string>;
  /** Get current Merkle root with version metadata (if supported) */
  getRootInfo?(): Promise<RevocationRootInfo>;
  /** Generate Merkle witness for a credential */
  getWitness(commitment: string): Promise<RevocationWitness | null>;
  /** Get the number of credentials in the tree */
  size(): Promise<number>;
}
