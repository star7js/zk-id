/**
 * Multi-claim proof types for composite verifications.
 *
 * Enables proving multiple claims (e.g., age AND nationality) in a single
 * verification request. While each underlying proof is still a separate
 * Groth16 proof, this module provides the types and helpers for bundling
 * them into a single request/response and verifying them atomically.
 */

import {
  AgeProof,
  NationalityProof,
  AgeProofRevocable,
  ProofRequest,
  SignedCredential,
} from './types';
import { validateNonce, validateMinAge, validateNationality } from './validation';
import { ZkIdValidationError } from './errors';

// ---------------------------------------------------------------------------
// Multi-Claim Types
// ---------------------------------------------------------------------------

/**
 * A single claim within a multi-claim proof request.
 */
export interface ClaimSpec {
  /** Unique label for this claim within the request */
  label: string;
  /** Type of claim */
  claimType: 'age' | 'nationality' | 'age-revocable';
  /** Minimum age (for age claims) */
  minAge?: number;
  /** Target nationality (for nationality claims) */
  targetNationality?: number;
}

/**
 * A multi-claim proof request that bundles multiple claims.
 */
export interface MultiClaimRequest {
  /** Ordered list of claims to prove */
  claims: ClaimSpec[];
  /** Shared nonce binding all claims to this request */
  nonce: string;
  /** ISO 8601 timestamp of the request */
  timestamp: string;
}

/**
 * A resolved proof for a single claim within a multi-claim response.
 */
export interface ClaimProof {
  /** Label matching the ClaimSpec */
  label: string;
  /** Type of claim */
  claimType: 'age' | 'nationality' | 'age-revocable';
  /** The zero-knowledge proof */
  proof: AgeProof | NationalityProof | AgeProofRevocable;
}

/**
 * A multi-claim proof response bundling proofs for all requested claims.
 */
export interface MultiClaimResponse {
  /** Proofs for each requested claim (same order as request) */
  proofs: ClaimProof[];
  /** Shared nonce from the request */
  nonce: string;
  /** ISO 8601 request timestamp */
  requestTimestamp: string;
  /** Credential ID used for all proofs */
  credentialId: string;
  /** Signed credential (optional when requireSignedCredentials is false). */
  signedCredential?: SignedCredential;
}

/**
 * Result of verifying a single claim within a multi-claim response.
 */
export interface ClaimVerificationResult {
  /** Claim label */
  label: string;
  /** Whether verification succeeded */
  verified: boolean;
  /** Error message if verification failed */
  error?: string;
}

/**
 * Result of verifying a multi-claim response.
 */
export interface MultiClaimVerificationResult {
  /** Per-claim verification results */
  results: ClaimVerificationResult[];
  /** True only if ALL claims verified successfully */
  allVerified: boolean;
  /** Number of verified claims */
  verifiedCount: number;
  /** Total number of claims */
  totalCount: number;
}

// ---------------------------------------------------------------------------
// Multi-Claim Helpers
// ---------------------------------------------------------------------------

/**
 * Create a multi-claim proof request.
 *
 * @param claims - Array of claim specifications
 * @param nonce - Shared nonce for replay protection
 * @returns Multi-claim request
 */
export function createMultiClaimRequest(claims: ClaimSpec[], nonce: string): MultiClaimRequest {
  if (claims.length === 0) {
    throw new ZkIdValidationError('Multi-claim request must contain at least one claim', 'claims');
  }

  validateNonce(nonce);

  // Validate no duplicate labels
  const labels = new Set<string>();
  for (const claim of claims) {
    if (!claim.label || claim.label.length === 0) {
      throw new ZkIdValidationError('Claim label must be a non-empty string', 'label');
    }
    if (labels.has(claim.label)) {
      throw new ZkIdValidationError(`Duplicate claim label: ${claim.label}`, 'label');
    }
    labels.add(claim.label);
  }

  // Validate claim parameters
  for (const claim of claims) {
    if (claim.claimType === 'age' || claim.claimType === 'age-revocable') {
      if (claim.minAge === undefined) {
        throw new ZkIdValidationError(
          `Claim '${claim.label}': minAge is required for ${claim.claimType} claims`,
          'minAge',
        );
      }
      validateMinAge(claim.minAge);
    }
    if (claim.claimType === 'nationality') {
      if (claim.targetNationality === undefined) {
        throw new ZkIdValidationError(
          `Claim '${claim.label}': targetNationality is required for nationality claims`,
          'targetNationality',
        );
      }
      validateNationality(claim.targetNationality);
    }
  }

  return {
    claims,
    nonce,
    timestamp: new Date().toISOString(),
  };
}

/**
 * Expand a multi-claim request into individual ProofRequest objects.
 *
 * Each claim is expanded into a standard ProofRequest that can be
 * passed to the existing proof generation functions. All share the
 * same nonce for binding.
 *
 * @param request - Multi-claim request to expand
 * @returns Array of (label, ProofRequest) tuples
 */
export function expandMultiClaimRequest(
  request: MultiClaimRequest,
): Array<{ label: string; proofRequest: ProofRequest }> {
  return request.claims.map((claim) => ({
    label: claim.label,
    proofRequest: {
      claimType: claim.claimType,
      minAge: claim.minAge,
      targetNationality: claim.targetNationality,
      nonce: request.nonce,
      timestamp: request.timestamp,
    },
  }));
}

/**
 * Aggregate individual claim verification results into a multi-claim result.
 *
 * @param results - Per-claim verification results
 * @returns Aggregated multi-claim verification result
 */
export function aggregateVerificationResults(
  results: ClaimVerificationResult[],
): MultiClaimVerificationResult {
  const verifiedCount = results.filter((r) => r.verified).length;

  return {
    results,
    allVerified: verifiedCount === results.length,
    verifiedCount,
    totalCount: results.length,
  };
}
