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
  /** Signed credential (binds issuer and commitment) */
  signedCredential: SignedCredential;
  /** Nonce from the request (for replay protection) */
  nonce: string;
  /** Request timestamp (ISO 8601) */
  requestTimestamp?: string;
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
