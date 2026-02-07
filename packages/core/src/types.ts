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
  claimType: 'age' | 'nationality';
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
  proof: AgeProof | NationalityProof;
  /** Nonce from the request (for replay protection) */
  nonce: string;
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
  /** Check if a credential has been revoked */
  isRevoked(credentialId: string): Promise<boolean>;
  /** Revoke a credential */
  revoke(credentialId: string): Promise<void>;
  /** Get the count of revoked credentials */
  getRevokedCount(): Promise<number>;
}
