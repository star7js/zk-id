import { strict as assert } from 'assert';
import {
  runBenchmark,
  checkTarget,
  formatResult,
  PERFORMANCE_TARGETS,
  BenchmarkResult,
} from '../src/benchmark';
import { poseidonHash } from '../src/poseidon';
import { createCredential, validateCredential } from '../src/credential';
import { InMemoryValidCredentialTree } from '../src/valid-credential-tree';
import { validateProofConstraints, validateNationalityProofConstraints } from '../src/verifier';
import { AgeProof, NationalityProof } from '../src/types';

describe('Performance Benchmarks', function () {
  // Benchmarks may take longer than default timeout
  this.timeout(60000);

  describe('Poseidon Hashing', () => {
    it('should meet target for 2-input hash', async () => {
      const result = await runBenchmark(
        'poseidon-hash-2',
        async () => { await poseidonHash([1990, 840]); },
        50, 5
      );

      const check = checkTarget(result);
      assert.ok(check, 'Target should exist for poseidon-hash-2');
      assert.ok(check.passed, `Benchmark failed: ${check.violations.join(', ')}`);
    });

    it('should meet target for 3-input hash', async () => {
      const result = await runBenchmark(
        'poseidon-hash-3',
        async () => { await poseidonHash([1990, 840, 123456789n]); },
        50, 5
      );

      const check = checkTarget(result);
      assert.ok(check, 'Target should exist for poseidon-hash-3');
      assert.ok(check.passed, `Benchmark failed: ${check.violations.join(', ')}`);
    });
  });

  describe('Credential Creation', () => {
    it('should meet target for credential creation', async () => {
      const result = await runBenchmark(
        'credential-creation',
        async () => { await createCredential(1990, 840); },
        50, 5
      );

      const check = checkTarget(result);
      assert.ok(check, 'Target should exist for credential-creation');
      assert.ok(check.passed, `Benchmark failed: ${check.violations.join(', ')}`);
    });
  });

  describe('Merkle Tree Operations', () => {
    let tree: InMemoryValidCredentialTree;
    let commitments: string[];

    before(async () => {
      // Create commitments for benchmarking
      commitments = [];
      for (let i = 0; i < 100; i++) {
        const cred = await createCredential(1950 + (i % 50), 1 + (i % 200));
        commitments.push(cred.commitment);
      }
    });

    beforeEach(async () => {
      tree = new InMemoryValidCredentialTree(10);
    });

    it('should meet target for add operations', async () => {
      let idx = 0;
      const result = await runBenchmark(
        'merkle-add',
        async () => { await tree.add(commitments[idx++ % commitments.length]); },
        50, 0
      );

      const check = checkTarget(result);
      assert.ok(check, 'Target should exist for merkle-add');
      assert.ok(check.passed, `Benchmark failed: ${check.violations.join(', ')}`);
    });

    it('should meet target for getRoot (cached read)', async () => {
      // Populate tree first
      for (let i = 0; i < 10; i++) {
        await tree.add(commitments[i]);
      }

      const result = await runBenchmark(
        'merkle-get-root',
        async () => { await tree.getRoot(); },
        50, 5
      );

      const check = checkTarget(result);
      assert.ok(check, 'Target should exist for merkle-get-root');
      assert.ok(check.passed, `Benchmark failed: ${check.violations.join(', ')}`);
    });

    it('should meet target for getWitness (cached read)', async () => {
      // Populate tree first
      for (let i = 0; i < 10; i++) {
        await tree.add(commitments[i]);
      }

      const result = await runBenchmark(
        'merkle-get-witness',
        async () => { await tree.getWitness(commitments[0]); },
        50, 5
      );

      const check = checkTarget(result);
      assert.ok(check, 'Target should exist for merkle-get-witness');
      assert.ok(check.passed, `Benchmark failed: ${check.violations.join(', ')}`);
    });

    it('should meet target for contains check', async () => {
      for (let i = 0; i < 10; i++) {
        await tree.add(commitments[i]);
      }

      const result = await runBenchmark(
        'merkle-contains',
        async () => { await tree.contains(commitments[0]); },
        50, 5
      );

      const check = checkTarget(result);
      assert.ok(check, 'Target should exist for merkle-contains');
      assert.ok(check.passed, `Benchmark failed: ${check.violations.join(', ')}`);
    });

    it('should meet target for remove operations', async () => {
      // Add all commitments first
      for (const c of commitments) {
        await tree.add(c);
      }

      let idx = 0;
      const result = await runBenchmark(
        'merkle-remove',
        async () => { await tree.remove(commitments[idx++ % commitments.length]); },
        50, 0
      );

      const check = checkTarget(result);
      assert.ok(check, 'Target should exist for merkle-remove');
      assert.ok(check.passed, `Benchmark failed: ${check.violations.join(', ')}`);
    });
  });

  describe('Constraint Validation', () => {
    const mockAgeProof: AgeProof = {
      proof: {
        pi_a: ['1', '2'],
        pi_b: [['3', '4'], ['5', '6']],
        pi_c: ['7', '8'],
        protocol: 'groth16',
        curve: 'bn128',
      },
      publicSignals: {
        currentYear: new Date().getFullYear(),
        minAge: 18,
        credentialHash: '12345678901234567890',
        nonce: 'nonce-bench-1',
        requestTimestamp: Date.now(),
      },
    };

    const mockNationalityProof: NationalityProof = {
      proof: {
        pi_a: ['1', '2'],
        pi_b: [['3', '4'], ['5', '6']],
        pi_c: ['7', '8'],
        protocol: 'groth16',
        curve: 'bn128',
      },
      publicSignals: {
        targetNationality: 840,
        credentialHash: '12345678901234567890',
        nonce: 'nonce-bench-2',
        requestTimestamp: Date.now(),
      },
    };

    it('should meet target for age constraint validation', async () => {
      const result = await runBenchmark(
        'constraint-validation-age',
        async () => { validateProofConstraints(mockAgeProof); },
        200, 10
      );

      const check = checkTarget(result);
      assert.ok(check, 'Target should exist for constraint-validation-age');
      assert.ok(check.passed, `Benchmark failed: ${check.violations.join(', ')}`);
    });

    it('should meet target for nationality constraint validation', async () => {
      const result = await runBenchmark(
        'constraint-validation-nationality',
        async () => { validateNationalityProofConstraints(mockNationalityProof); },
        200, 10
      );

      const check = checkTarget(result);
      assert.ok(check, 'Target should exist for constraint-validation-nationality');
      assert.ok(check.passed, `Benchmark failed: ${check.violations.join(', ')}`);
    });
  });

  describe('Benchmark Utilities', () => {
    it('should produce valid statistics', async () => {
      const result = await runBenchmark(
        'test-op',
        async () => { /* noop */ },
        20, 2
      );

      assert.strictEqual(result.name, 'test-op');
      assert.strictEqual(result.iterations, 20);
      assert.ok(result.totalMs >= 0);
      assert.ok(result.avgMs >= 0);
      assert.ok(result.medianMs >= 0);
      assert.ok(result.p95Ms >= 0);
      assert.ok(result.minMs >= 0);
      assert.ok(result.maxMs >= result.minMs);
      assert.ok(result.opsPerSecond > 0);
    });

    it('should check targets correctly', () => {
      const passing: BenchmarkResult = {
        name: 'poseidon-hash-2',
        iterations: 100,
        totalMs: 100,
        avgMs: 1,
        medianMs: 0.9,
        p95Ms: 2,
        minMs: 0.5,
        maxMs: 5,
        opsPerSecond: 1000,
      };

      const check = checkTarget(passing);
      assert.ok(check);
      assert.ok(check.passed);
      assert.strictEqual(check.violations.length, 0);
    });

    it('should detect target violations', () => {
      const failing: BenchmarkResult = {
        name: 'poseidon-hash-2',
        iterations: 100,
        totalMs: 10000,
        avgMs: 100,
        medianMs: 90,
        p95Ms: 200,
        minMs: 50,
        maxMs: 500,
        opsPerSecond: 10,
      };

      const check = checkTarget(failing);
      assert.ok(check);
      assert.ok(!check.passed);
      assert.ok(check.violations.length > 0);
    });

    it('should return null for unknown benchmark names', () => {
      const result: BenchmarkResult = {
        name: 'unknown-op',
        iterations: 10,
        totalMs: 10,
        avgMs: 1,
        medianMs: 1,
        p95Ms: 1,
        minMs: 1,
        maxMs: 1,
        opsPerSecond: 1000,
      };

      assert.strictEqual(checkTarget(result), null);
    });

    it('should format results as readable strings', () => {
      const result: BenchmarkResult = {
        name: 'poseidon-hash-2',
        iterations: 100,
        totalMs: 200,
        avgMs: 2,
        medianMs: 1.8,
        p95Ms: 4,
        minMs: 1,
        maxMs: 10,
        opsPerSecond: 500,
      };

      const formatted = formatResult(result);
      assert.ok(formatted.includes('poseidon-hash-2'));
      assert.ok(formatted.includes('PASS'));
      assert.ok(formatted.includes('avg:'));
      assert.ok(formatted.includes('p95:'));
    });

    it('should define targets for all critical operations', () => {
      const criticalOps = [
        'poseidon-hash-2',
        'credential-creation',
        'merkle-add',
        'merkle-get-root',
        'proof-generation-age',
        'proof-verification-age',
      ];

      for (const op of criticalOps) {
        const target = PERFORMANCE_TARGETS.find((t) => t.name === op);
        assert.ok(target, `Missing performance target for ${op}`);
        assert.ok(target.maxAvgMs > 0);
        assert.ok(target.maxP95Ms >= target.maxAvgMs);
      }
    });
  });
});
