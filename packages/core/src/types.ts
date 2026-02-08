/**
 * Core type definitions for zk-id
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
  /** Poseidon hash commitment to (birthYear, nationality, salt) */
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
}

export interface AgeProof {
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
  /** The zero-knowledge proof */
  proof: AgeProof | NationalityProof | AgeProofRevocable;
  /** Signed credential (binds issuer and commitment) */
  signedCredential: SignedCredential;
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

export interface RevocationAccumulator {
  /** Current Merkle root */
  getRoot(): Promise<string>;
  /** Check if a credential commitment is revoked */
  isRevoked(commitment: string): Promise<boolean>;
  /** Add a revoked commitment */
  revoke(commitment: string): Promise<void>;
  /** Generate Merkle witness for a revoked commitment */
  getWitness(commitment: string): Promise<RevocationWitness | null>;
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
