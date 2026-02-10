# Performance Benchmarks

This document defines performance targets for zk-id operations and describes how to run benchmarks.

## Targets

All targets assume a typical server environment: 4-core x86_64, 8 GB RAM, Node.js 20+. Browser targets may differ due to WebAssembly overhead and device variability.

### Cryptographic Primitives

| Operation                | Avg (ms) | p95 (ms) | Notes                                           |
| ------------------------ | -------- | -------- | ----------------------------------------------- |
| Poseidon hash (2 inputs) | ≤ 5      | ≤ 10     | After Poseidon instance warmup                  |
| Poseidon hash (3 inputs) | ≤ 5      | ≤ 10     | Credential commitment computation               |
| Credential creation      | ≤ 10     | ≤ 20     | Includes random salt generation + Poseidon hash |

### Merkle Tree Operations (depth 10)

| Operation      | Avg (ms) | p95 (ms) | Notes                                        |
| -------------- | -------- | -------- | -------------------------------------------- |
| `add()`        | ≤ 15     | ≤ 30     | O(depth) Poseidon hashes along affected path |
| `remove()`     | ≤ 15     | ≤ 30     | O(depth) Poseidon hashes along affected path |
| `getRoot()`    | ≤ 1      | ≤ 2      | O(1) cached read                             |
| `getWitness()` | ≤ 1      | ≤ 2      | O(1) array lookups from cached layers        |
| `contains()`   | ≤ 1      | ≤ 2      | O(1) Map lookup                              |

### Constraint Validation (non-cryptographic)

| Operation                     | Avg (ms) | p95 (ms) | Notes                        |
| ----------------------------- | -------- | -------- | ---------------------------- |
| Age proof constraints         | ≤ 1      | ≤ 2      | Field checks only, no crypto |
| Nationality proof constraints | ≤ 1      | ≤ 2      | Field checks only, no crypto |

### Proof Generation (requires circuit artifacts)

| Operation                     | Avg (ms) | p95 (ms) | Notes                                |
| ----------------------------- | -------- | -------- | ------------------------------------ |
| Age proof (Groth16)           | ≤ 3000   | ≤ 5000   | WASM witness + snarkjs prover        |
| Nationality proof (Groth16)   | ≤ 3000   | ≤ 5000   | WASM witness + snarkjs prover        |
| Age proof revocable (Groth16) | ≤ 5000   | ≤ 8000   | Larger circuit with Merkle inclusion |

### Proof Verification

| Operation                      | Avg (ms) | p95 (ms) | Notes                                     |
| ------------------------------ | -------- | -------- | ----------------------------------------- |
| Age proof verification         | ≤ 100    | ≤ 200    | Groth16 pairing check                     |
| Nationality proof verification | ≤ 100    | ≤ 200    | Groth16 pairing check                     |
| Revocable proof verification   | ≤ 100    | ≤ 200    | Groth16 pairing check (same verifier)     |
| Batch verification (10 proofs) | ≤ 500    | ≤ 800    | Parallel verification via `verifyBatch()` |

## Running Benchmarks

### Core Operation Benchmarks

```bash
cd packages/core
npm test -- --grep "Performance Benchmarks"
```

This runs benchmarks for all operations that do not require compiled circuits: Poseidon hashing, credential creation, Merkle tree operations, and constraint validation. Results are checked against the targets defined in `PERFORMANCE_TARGETS` (see `packages/core/src/benchmark.ts`).

### Full Proof Benchmarks (with circuits)

Full proof generation and verification benchmarks require compiled circuit artifacts. First, build the circuits:

```bash
cd packages/circuits
npm run build
```

Then run the integration tests which exercise proof generation and verification:

```bash
cd packages/core
npm test -- --grep "integration"
```

## Programmatic Usage

```typescript
import { runBenchmark, checkTarget, formatResult } from '@zk-id/core';
import { poseidonHash } from '@zk-id/core';

const result = await runBenchmark(
  'poseidon-hash-2',
  async () => {
    await poseidonHash([1990, 840]);
  },
  100, // iterations
  5, // warmup
);

console.log(formatResult(result));
// [PASS] poseidon-hash-2
//   avg: 0.45ms | median: 0.42ms | p95: 0.80ms
//   min: 0.35ms | max: 1.20ms | ops/s: 2222

const check = checkTarget(result);
if (check && !check.passed) {
  console.error('Performance regression:', check.violations);
}
```

## Benchmark Methodology

- **Warmup**: 5 iterations are executed before measurement to allow JIT compilation and lazy initialization (e.g., Poseidon instance).
- **Measurement**: Each iteration is individually timed with `performance.now()`.
- **Statistics**: Results include average, median, p95, min, max, and operations per second.
- **Target checking**: `checkTarget()` compares results against `PERFORMANCE_TARGETS` and reports pass/fail with specific violations.

## Browser Considerations

Proof generation in the browser uses the same snarkjs WASM backend but performance varies by device. Typical expectations:

- **Modern desktop browser**: 1.5-3x slower than Node.js for proof generation
- **Mobile browser**: 3-10x slower depending on device
- **Verification**: Roughly equivalent to Node.js (pairing math is CPU-bound)

The `@zk-id/sdk` browser wallet performs proof generation client-side. The progress callback provided by `BrowserWallet.generateProof()` can be used to show a spinner during the longer browser proving times.

---

Last updated: 2026-02-09
