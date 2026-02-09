/**
 * Benchmark utilities for measuring zk-id operation performance.
 *
 * Provides a lightweight benchmark runner for Poseidon hashing,
 * credential creation, Merkle tree operations, and constraint
 * validation. Proof generation/verification benchmarks require
 * compiled circuit artifacts and are documented separately.
 */

export interface BenchmarkResult {
  /** Name of the benchmark */
  name: string;
  /** Number of iterations executed */
  iterations: number;
  /** Total elapsed time in milliseconds */
  totalMs: number;
  /** Average time per iteration in milliseconds */
  avgMs: number;
  /** Median time per iteration in milliseconds */
  medianMs: number;
  /** 95th percentile time in milliseconds */
  p95Ms: number;
  /** Minimum time in milliseconds */
  minMs: number;
  /** Maximum time in milliseconds */
  maxMs: number;
  /** Operations per second */
  opsPerSecond: number;
}

export interface BenchmarkTarget {
  /** Name of the operation */
  name: string;
  /** Maximum acceptable average time in milliseconds */
  maxAvgMs: number;
  /** Maximum acceptable p95 time in milliseconds */
  maxP95Ms: number;
}

/**
 * Known performance targets for zk-id operations.
 *
 * These targets represent acceptable performance on a typical server
 * (4-core x86_64, 8 GB RAM, Node.js 20+). Proof generation targets
 * assume compiled WASM circuits; verification targets assume in-memory
 * verification keys.
 */
export const PERFORMANCE_TARGETS: BenchmarkTarget[] = [
  // Cryptographic primitives
  { name: 'poseidon-hash-2', maxAvgMs: 5, maxP95Ms: 10 },
  { name: 'poseidon-hash-3', maxAvgMs: 5, maxP95Ms: 10 },
  { name: 'credential-creation', maxAvgMs: 10, maxP95Ms: 20 },

  // Merkle tree operations (depth 10)
  { name: 'merkle-add', maxAvgMs: 15, maxP95Ms: 30 },
  { name: 'merkle-remove', maxAvgMs: 15, maxP95Ms: 30 },
  { name: 'merkle-get-root', maxAvgMs: 1, maxP95Ms: 2 },
  { name: 'merkle-get-witness', maxAvgMs: 1, maxP95Ms: 2 },
  { name: 'merkle-contains', maxAvgMs: 1, maxP95Ms: 2 },

  // Constraint validation (no crypto)
  { name: 'constraint-validation-age', maxAvgMs: 1, maxP95Ms: 2 },
  { name: 'constraint-validation-nationality', maxAvgMs: 1, maxP95Ms: 2 },

  // Proof generation (requires circuit artifacts)
  { name: 'proof-generation-age', maxAvgMs: 3000, maxP95Ms: 5000 },
  { name: 'proof-generation-nationality', maxAvgMs: 3000, maxP95Ms: 5000 },
  { name: 'proof-generation-age-revocable', maxAvgMs: 5000, maxP95Ms: 8000 },

  // Proof verification (requires verification keys)
  { name: 'proof-verification-age', maxAvgMs: 100, maxP95Ms: 200 },
  { name: 'proof-verification-nationality', maxAvgMs: 100, maxP95Ms: 200 },
  { name: 'proof-verification-age-revocable', maxAvgMs: 100, maxP95Ms: 200 },
  { name: 'proof-verification-batch-10', maxAvgMs: 500, maxP95Ms: 800 },
];

/**
 * Runs a benchmark by executing the given function multiple times
 * and collecting timing statistics.
 *
 * @param name - Benchmark name
 * @param fn - Async function to benchmark
 * @param iterations - Number of iterations (default: 100)
 * @param warmup - Number of warmup iterations to discard (default: 5)
 * @returns Benchmark result with timing statistics
 */
export async function runBenchmark(
  name: string,
  fn: () => Promise<void>,
  iterations: number = 100,
  warmup: number = 5
): Promise<BenchmarkResult> {
  // Warmup runs (not measured)
  for (let i = 0; i < warmup; i++) {
    await fn();
  }

  // Measured runs
  const times: number[] = [];
  const totalStart = Date.now();

  for (let i = 0; i < iterations; i++) {
    const start = Date.now();
    await fn();
    times.push(Date.now() - start);
  }

  const totalMs = Date.now() - totalStart;
  const sorted = [...times].sort((a, b) => a - b);

  const avgMs = totalMs / iterations;
  const medianMs = sorted[Math.floor(sorted.length / 2)];
  const p95Ms = sorted[Math.floor(sorted.length * 0.95)];
  const minMs = sorted[0];
  const maxMs = sorted[sorted.length - 1];
  const opsPerSecond = iterations / (totalMs / 1000);

  return {
    name,
    iterations,
    totalMs,
    avgMs,
    medianMs,
    p95Ms,
    minMs,
    maxMs,
    opsPerSecond,
  };
}

/**
 * Checks a benchmark result against its performance target.
 *
 * @returns null if no target exists for this benchmark name,
 *          otherwise an object with pass/fail and details.
 */
export function checkTarget(
  result: BenchmarkResult
): { passed: boolean; target: BenchmarkTarget; violations: string[] } | null {
  const target = PERFORMANCE_TARGETS.find((t) => t.name === result.name);
  if (!target) return null;

  const violations: string[] = [];
  if (result.avgMs > target.maxAvgMs) {
    violations.push(
      `avg ${result.avgMs.toFixed(2)}ms exceeds target ${target.maxAvgMs}ms`
    );
  }
  if (result.p95Ms > target.maxP95Ms) {
    violations.push(
      `p95 ${result.p95Ms.toFixed(2)}ms exceeds target ${target.maxP95Ms}ms`
    );
  }

  return {
    passed: violations.length === 0,
    target,
    violations,
  };
}

/**
 * Formats a benchmark result as a human-readable string.
 */
export function formatResult(result: BenchmarkResult): string {
  const check = checkTarget(result);
  const status = check ? (check.passed ? 'PASS' : 'FAIL') : '----';

  return [
    `[${status}] ${result.name}`,
    `  avg: ${result.avgMs.toFixed(2)}ms | median: ${result.medianMs.toFixed(2)}ms | p95: ${result.p95Ms.toFixed(2)}ms`,
    `  min: ${result.minMs.toFixed(2)}ms | max: ${result.maxMs.toFixed(2)}ms | ops/s: ${result.opsPerSecond.toFixed(0)}`,
  ].join('\n');
}
