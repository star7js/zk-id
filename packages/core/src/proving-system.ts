/**
 * Proving system abstraction layer.
 *
 * Decouples zk-id from any single ZK backend (Groth16, PLONK, Halo2, etc.)
 * so that the prover, verifier, and SDK can work with pluggable proving
 * systems without code changes beyond configuration.
 *
 * Current implementations:
 *   - Groth16ProvingSystem (snarkjs, BN128) — production default
 *
 * Planned:
 *   - PLONKProvingSystem  (snarkjs, universal SRS) — no per-circuit trusted setup
 */

// ---------------------------------------------------------------------------
// Core Abstractions
// ---------------------------------------------------------------------------

/**
 * Identifies the proving system in use.
 */
export type ProvingSystemType = 'groth16' | 'plonk' | 'fflonk';

/**
 * Opaque proof blob produced by a proving system.
 * Each backend stores its own structure here; callers should not inspect it
 * directly — pass it to the same ProvingSystem for verification.
 */
export interface SerializedProof {
  /** Which proving system produced this proof */
  system: ProvingSystemType;
  /** The proof data (format depends on system) */
  proof: {
    pi_a: string[];
    pi_b: string[][];
    pi_c: string[];
    protocol: string;
    curve: string;
  };
  /** Public signals array */
  publicSignals: string[];
}

/**
 * Artifacts needed by the prover to generate a proof for a specific circuit.
 */
export interface CircuitArtifacts {
  /** Path or bytes of the compiled circuit WASM */
  wasmPath: string;
  /** Path or bytes of the proving key (zkey for Groth16/PLONK) */
  provingKeyPath: string;
}

/**
 * Artifacts needed by the verifier.
 */
export interface VerifierArtifacts {
  /** The verification key object */
  verificationKey: Record<string, unknown>;
}

/**
 * Unified interface for any ZK proving system.
 *
 * Implementations wrap a specific library (snarkjs, rapidsnark, gnark, etc.)
 * and expose prove/verify through a common API.
 */
export interface ProvingSystem {
  /** The type identifier for this proving system */
  readonly type: ProvingSystemType;

  /**
   * Generate a proof.
   *
   * @param circuitInputs - Private + public inputs for the circuit
   * @param artifacts     - Circuit WASM and proving key paths
   * @returns The proof and public signals
   */
  prove(
    circuitInputs: Record<string, unknown>,
    artifacts: CircuitArtifacts,
  ): Promise<SerializedProof>;

  /**
   * Verify a proof.
   *
   * @param proof     - The serialized proof to verify
   * @param artifacts - Verification key
   * @returns true if the proof is valid
   */
  verify(proof: SerializedProof, artifacts: VerifierArtifacts): Promise<boolean>;
}

// ---------------------------------------------------------------------------
// Groth16 Implementation
// ---------------------------------------------------------------------------

/**
 * Groth16 proving system backed by snarkjs.
 *
 * This is the current default. Groth16 has the smallest proof size and
 * fastest verification, but requires a per-circuit trusted setup ceremony.
 */
export class Groth16ProvingSystem implements ProvingSystem {
  readonly type: ProvingSystemType = 'groth16';

  async prove(
    circuitInputs: Record<string, unknown>,
    artifacts: CircuitArtifacts,
  ): Promise<SerializedProof> {
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    const snarkjs = require('snarkjs');
    const { proof, publicSignals } = await snarkjs.groth16.fullProve(
      circuitInputs,
      artifacts.wasmPath,
      artifacts.provingKeyPath,
    );

    return {
      system: 'groth16',
      proof: {
        pi_a: proof.pi_a.slice(0, 2).map((x: unknown) => String(x)),
        pi_b: proof.pi_b.slice(0, 2).map((arr: unknown[]) => arr.map((x: unknown) => String(x))),
        pi_c: proof.pi_c.slice(0, 2).map((x: unknown) => String(x)),
        protocol: proof.protocol,
        curve: proof.curve,
      },
      publicSignals: publicSignals.map((s: unknown) => String(s)),
    };
  }

  async verify(proof: SerializedProof, artifacts: VerifierArtifacts): Promise<boolean> {
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    const snarkjs = require('snarkjs');
    return snarkjs.groth16.verify(artifacts.verificationKey, proof.publicSignals, proof.proof);
  }
}

// ---------------------------------------------------------------------------
// PLONK Implementation (Scaffold)
// ---------------------------------------------------------------------------

/**
 * PLONK proving system backed by snarkjs.
 *
 * PLONK uses a universal Structured Reference String (SRS) that is shared
 * across all circuits, eliminating per-circuit trusted setup ceremonies.
 * Trade-offs vs Groth16: larger proofs, slower verification, but no
 * circuit-specific ceremony required.
 *
 * Status: scaffold — requires a PLONK-compatible zkey (generated via
 * `snarkjs plonk setup`).
 */
export class PLONKProvingSystem implements ProvingSystem {
  readonly type: ProvingSystemType = 'plonk';

  async prove(
    circuitInputs: Record<string, unknown>,
    artifacts: CircuitArtifacts,
  ): Promise<SerializedProof> {
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    const snarkjs = require('snarkjs');
    const { proof, publicSignals } = await snarkjs.plonk.fullProve(
      circuitInputs,
      artifacts.wasmPath,
      artifacts.provingKeyPath,
    );

    return {
      system: 'plonk',
      proof: {
        pi_a: proof.A ? [proof.A[0].toString(), proof.A[1].toString()] : [],
        pi_b: proof.B ? [[proof.B[0].toString(), proof.B[1].toString()]] : [],
        pi_c: proof.C ? [proof.C[0].toString(), proof.C[1].toString()] : [],
        protocol: proof.protocol || 'plonk',
        curve: proof.curve || 'bn128',
      },
      publicSignals: publicSignals.map((s: unknown) => String(s)),
    };
  }

  async verify(proof: SerializedProof, artifacts: VerifierArtifacts): Promise<boolean> {
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    const snarkjs = require('snarkjs');
    return snarkjs.plonk.verify(artifacts.verificationKey, proof.publicSignals, proof.proof);
  }
}

// ---------------------------------------------------------------------------
// Registry
// ---------------------------------------------------------------------------

const PROVING_SYSTEMS: Map<ProvingSystemType, ProvingSystem> = new Map();

/**
 * Register a proving system implementation.
 */
export function registerProvingSystem(system: ProvingSystem): void {
  PROVING_SYSTEMS.set(system.type, system);
}

/**
 * Get a registered proving system by type.
 */
export function getProvingSystem(type: ProvingSystemType): ProvingSystem {
  const system = PROVING_SYSTEMS.get(type);
  if (!system) {
    throw new Error(
      `Proving system '${type}' not registered. ` +
        `Available: ${[...PROVING_SYSTEMS.keys()].join(', ') || 'none'}`,
    );
  }
  return system;
}

/**
 * List all registered proving system types.
 */
export function listProvingSystems(): ProvingSystemType[] {
  return [...PROVING_SYSTEMS.keys()];
}

// Register defaults
registerProvingSystem(new Groth16ProvingSystem());
registerProvingSystem(new PLONKProvingSystem());

// ---------------------------------------------------------------------------
// Comparison helpers (for documentation and selection)
// ---------------------------------------------------------------------------

export interface ProvingSystemTradeoffs {
  system: ProvingSystemType;
  trustedSetup: 'per-circuit' | 'universal' | 'none';
  proofSize: 'small' | 'medium' | 'large';
  verificationTime: 'fast' | 'medium' | 'slow';
  provingTime: 'medium' | 'slow';
  maturity: 'production' | 'beta' | 'experimental';
}

export const PROVING_SYSTEM_COMPARISON: ProvingSystemTradeoffs[] = [
  {
    system: 'groth16',
    trustedSetup: 'per-circuit',
    proofSize: 'small',
    verificationTime: 'fast',
    provingTime: 'medium',
    maturity: 'production',
  },
  {
    system: 'plonk',
    trustedSetup: 'universal',
    proofSize: 'medium',
    verificationTime: 'medium',
    provingTime: 'slow',
    maturity: 'beta',
  },
  {
    system: 'fflonk',
    trustedSetup: 'universal',
    proofSize: 'small',
    verificationTime: 'fast',
    provingTime: 'slow',
    maturity: 'experimental',
  },
];
