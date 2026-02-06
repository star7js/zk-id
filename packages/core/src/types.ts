/**
 * Core type definitions for zk-id
 */

export interface Credential {
  /** Unique identifier for this credential */
  id: string;
  /** Birth year of the credential holder */
  birthYear: number;
  /** Random salt for privacy (used in commitment) */
  salt: string;
  /** Poseidon hash commitment to (birthYear, salt) */
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
  claimType: 'age' | 'attribute';
  /** Minimum age required (for age claims) */
  minAge?: number;
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
  proof: AgeProof;
  /** Nonce from the request (for replay protection) */
  nonce: string;
}
