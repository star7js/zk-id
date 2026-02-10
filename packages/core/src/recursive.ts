/**
 * Recursive proof aggregation scaffolding.
 *
 * Recursive SNARKs allow multiple proofs to be combined into a single
 * proof that attests to the validity of all constituent proofs. This is
 * used for:
 *   - Batching multiple credential verifications into one on-chain tx
 *   - Aggregating proofs from different users (privacy-preserving batch)
 *   - Incremental computation (proving a chain of state transitions)
 *
 * Current state: type definitions and aggregation logic only.
 * Actual recursive circuits require either:
 *   - Halo2 (IPA-based, no trusted setup, native recursion)
 *   - Nova / SuperNova (IVC/folding-based)
 *   - snarkjs recursive verification circuits (Groth16-in-Groth16)
 *
 * This module provides the data model and orchestration layer so that
 * when recursive circuit implementations become available, they can be
 * plugged in without changing the API surface.
 */

import { SerializedProof, ProvingSystemType } from './proving-system';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/**
 * A single proof to be included in a recursive aggregation.
 */
export interface AggregateInput {
  /** Unique label for this proof within the aggregation */
  label: string;
  /** The serialized proof */
  proof: SerializedProof;
  /** The circuit identifier (e.g., 'age-verify', 'nationality-verify') */
  circuitId: string;
}

/**
 * An aggregated proof that attests to the validity of multiple sub-proofs.
 */
export interface AggregatedProof {
  /** The aggregate proof data (opaque to callers) */
  aggregateProof: SerializedProof | null;
  /** Labels of constituent proofs (in order) */
  constituentLabels: string[];
  /** Number of proofs aggregated */
  count: number;
  /** The proving system used for aggregation */
  aggregationSystem: ProvingSystemType | 'none';
  /** Whether the aggregation is a true recursive proof or a logical bundle */
  isRecursive: boolean;
  /** Per-proof public signals (preserved for verifier introspection) */
  publicSignalsByLabel: Record<string, string[]>;
}

/**
 * Result of verifying an aggregated proof.
 */
export interface AggregatedVerificationResult {
  /** Overall verification result */
  verified: boolean;
  /** Per-constituent results (if the system supports decomposition) */
  constituentResults: Array<{ label: string; verified: boolean; error?: string }>;
  /** Number of verified constituents */
  verifiedCount: number;
  /** Total number of constituents */
  totalCount: number;
}

/**
 * Interface for recursive proof aggregation backends.
 *
 * Implementations will wrap the actual recursive circuit/IVC system.
 */
export interface RecursiveAggregator {
  /** The proving system type used for aggregation */
  readonly aggregationSystem: ProvingSystemType;

  /**
   * Aggregate multiple proofs into a single recursive proof.
   */
  aggregate(inputs: AggregateInput[]): Promise<AggregatedProof>;

  /**
   * Verify an aggregated proof.
   */
  verify(aggregated: AggregatedProof): Promise<AggregatedVerificationResult>;
}

// ---------------------------------------------------------------------------
// Logical Aggregation (non-recursive)
// ---------------------------------------------------------------------------

/**
 * Logical proof aggregator (non-recursive).
 *
 * This is a pass-through aggregator that bundles proofs together without
 * actually creating a recursive proof. It is used as a placeholder until
 * recursive circuit support is available, and as a reference implementation
 * for the aggregator interface.
 *
 * Verification re-verifies each constituent proof individually.
 */
export class LogicalAggregator implements RecursiveAggregator {
  readonly aggregationSystem: ProvingSystemType = 'groth16';

  async aggregate(inputs: AggregateInput[]): Promise<AggregatedProof> {
    if (inputs.length === 0) {
      throw new Error('Cannot aggregate zero proofs');
    }

    const publicSignalsByLabel: Record<string, string[]> = {};
    for (const input of inputs) {
      publicSignalsByLabel[input.label] = input.proof.publicSignals;
    }

    return {
      aggregateProof: null, // No recursive proof — just a bundle
      constituentLabels: inputs.map((i) => i.label),
      count: inputs.length,
      aggregationSystem: 'none',
      isRecursive: false,
      publicSignalsByLabel,
    };
  }

  async verify(_aggregated: AggregatedProof): Promise<AggregatedVerificationResult> {
    // Logical aggregator cannot verify — it has no proof data.
    // Callers should verify each constituent proof individually.
    return {
      verified: false,
      constituentResults: _aggregated.constituentLabels.map((label) => ({
        label,
        verified: false,
        error: 'Logical aggregation — verify constituents individually',
      })),
      verifiedCount: 0,
      totalCount: _aggregated.count,
    };
  }
}

// ---------------------------------------------------------------------------
// Aggregation Helpers
// ---------------------------------------------------------------------------

/**
 * Create an aggregate input from a proof and metadata.
 */
export function createAggregateInput(
  label: string,
  proof: SerializedProof,
  circuitId: string,
): AggregateInput {
  return { label, proof, circuitId };
}

/**
 * Check if an aggregated proof is a true recursive proof vs a logical bundle.
 */
export function isRecursiveProof(aggregated: AggregatedProof): boolean {
  return aggregated.isRecursive && aggregated.aggregateProof !== null;
}

/**
 * Extract public signals for a specific constituent from an aggregated proof.
 */
export function getConstituentPublicSignals(
  aggregated: AggregatedProof,
  label: string,
): string[] | undefined {
  return aggregated.publicSignalsByLabel[label];
}

/**
 * Summary of recursive proof support status.
 *
 * This is intentionally honest about the current state — recursive proofs
 * require significant circuit development and should not be represented
 * as production-ready until they are actually implemented and audited.
 */
export const RECURSIVE_PROOF_STATUS = {
  groth16InGroth16: {
    status: 'scaffold' as const,
    description:
      'Verify a Groth16 proof inside a Groth16 circuit. Requires a BN128 pairing verifier circuit (~20M constraints). Not yet implemented.',
    estimatedConstraints: '~20,000,000',
    provingTime: '~60-120s',
  },
  nova: {
    status: 'planned' as const,
    description:
      'Incrementally Verifiable Computation (IVC) via Nova folding. Efficient for sequential proof aggregation. Requires Nova/SuperNova circuit library.',
    estimatedConstraints: 'N/A (folding-based)',
    provingTime: '~1-5s per fold step',
  },
  halo2: {
    status: 'planned' as const,
    description:
      'IPA-based recursion with no trusted setup. Requires migration from circom to halo2 circuits (Rust).',
    estimatedConstraints: 'Varies',
    provingTime: '~5-20s',
  },
} as const;
