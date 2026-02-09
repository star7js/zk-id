import { strict as assert } from 'assert';
import {
  createMultiClaimRequest,
  expandMultiClaimRequest,
  aggregateVerificationResults,
  ClaimSpec,
  ClaimVerificationResult,
} from '../src/multi-claim';

describe('Multi-Claim Proofs', () => {
  describe('createMultiClaimRequest', () => {
    it('should create a valid multi-claim request', () => {
      const claims: ClaimSpec[] = [
        { label: 'age', claimType: 'age', minAge: 18 },
        { label: 'nationality', claimType: 'nationality', targetNationality: 840 },
      ];

      const request = createMultiClaimRequest(claims, 'nonce-123');

      assert.strictEqual(request.claims.length, 2);
      assert.strictEqual(request.nonce, 'nonce-123');
      assert.ok(request.timestamp);
    });

    it('should reject empty claims array', () => {
      assert.throws(
        () => createMultiClaimRequest([], 'nonce'),
        /at least one claim/
      );
    });

    it('should reject duplicate claim labels', () => {
      const claims: ClaimSpec[] = [
        { label: 'age', claimType: 'age', minAge: 18 },
        { label: 'age', claimType: 'age', minAge: 21 },
      ];

      assert.throws(
        () => createMultiClaimRequest(claims, 'nonce'),
        /Duplicate claim label/
      );
    });

    it('should reject age claim without minAge', () => {
      const claims: ClaimSpec[] = [
        { label: 'age', claimType: 'age' },
      ];

      assert.throws(
        () => createMultiClaimRequest(claims, 'nonce'),
        /minAge is required/
      );
    });

    it('should reject nationality claim without targetNationality', () => {
      const claims: ClaimSpec[] = [
        { label: 'nat', claimType: 'nationality' },
      ];

      assert.throws(
        () => createMultiClaimRequest(claims, 'nonce'),
        /targetNationality is required/
      );
    });

    it('should reject nationality claim with invalid code', () => {
      const claims: ClaimSpec[] = [
        { label: 'nat', claimType: 'nationality', targetNationality: 0 },
      ];

      assert.throws(
        () => createMultiClaimRequest(claims, 'nonce'),
        /valid targetNationality/
      );
    });

    it('should accept age-revocable claim', () => {
      const claims: ClaimSpec[] = [
        { label: 'age-rev', claimType: 'age-revocable', minAge: 21 },
      ];

      const request = createMultiClaimRequest(claims, 'nonce');
      assert.strictEqual(request.claims[0].claimType, 'age-revocable');
    });

    it('should support three claims simultaneously', () => {
      const claims: ClaimSpec[] = [
        { label: 'drinking-age', claimType: 'age', minAge: 21 },
        { label: 'voting-age', claimType: 'age', minAge: 18 },
        { label: 'citizen', claimType: 'nationality', targetNationality: 840 },
      ];

      const request = createMultiClaimRequest(claims, 'nonce');
      assert.strictEqual(request.claims.length, 3);
    });
  });

  describe('expandMultiClaimRequest', () => {
    it('should expand to individual ProofRequests', () => {
      const claims: ClaimSpec[] = [
        { label: 'age', claimType: 'age', minAge: 18 },
        { label: 'nat', claimType: 'nationality', targetNationality: 826 },
      ];

      const request = createMultiClaimRequest(claims, 'nonce-456');
      const expanded = expandMultiClaimRequest(request);

      assert.strictEqual(expanded.length, 2);

      assert.strictEqual(expanded[0].label, 'age');
      assert.strictEqual(expanded[0].proofRequest.claimType, 'age');
      assert.strictEqual(expanded[0].proofRequest.minAge, 18);
      assert.strictEqual(expanded[0].proofRequest.nonce, 'nonce-456');

      assert.strictEqual(expanded[1].label, 'nat');
      assert.strictEqual(expanded[1].proofRequest.claimType, 'nationality');
      assert.strictEqual(expanded[1].proofRequest.targetNationality, 826);
      assert.strictEqual(expanded[1].proofRequest.nonce, 'nonce-456');
    });

    it('should share the same nonce across all expanded requests', () => {
      const claims: ClaimSpec[] = [
        { label: 'a', claimType: 'age', minAge: 18 },
        { label: 'b', claimType: 'age', minAge: 21 },
        { label: 'c', claimType: 'nationality', targetNationality: 840 },
      ];

      const request = createMultiClaimRequest(claims, 'shared-nonce');
      const expanded = expandMultiClaimRequest(request);

      for (const item of expanded) {
        assert.strictEqual(item.proofRequest.nonce, 'shared-nonce');
        assert.strictEqual(item.proofRequest.timestamp, request.timestamp);
      }
    });
  });

  describe('aggregateVerificationResults', () => {
    it('should report all verified when all pass', () => {
      const results: ClaimVerificationResult[] = [
        { label: 'age', verified: true },
        { label: 'nat', verified: true },
      ];

      const aggregate = aggregateVerificationResults(results);

      assert.strictEqual(aggregate.allVerified, true);
      assert.strictEqual(aggregate.verifiedCount, 2);
      assert.strictEqual(aggregate.totalCount, 2);
    });

    it('should report not all verified when one fails', () => {
      const results: ClaimVerificationResult[] = [
        { label: 'age', verified: true },
        { label: 'nat', verified: false, error: 'Wrong nationality' },
      ];

      const aggregate = aggregateVerificationResults(results);

      assert.strictEqual(aggregate.allVerified, false);
      assert.strictEqual(aggregate.verifiedCount, 1);
      assert.strictEqual(aggregate.totalCount, 2);
    });

    it('should report not all verified when all fail', () => {
      const results: ClaimVerificationResult[] = [
        { label: 'age', verified: false, error: 'Proof invalid' },
        { label: 'nat', verified: false, error: 'Proof invalid' },
      ];

      const aggregate = aggregateVerificationResults(results);

      assert.strictEqual(aggregate.allVerified, false);
      assert.strictEqual(aggregate.verifiedCount, 0);
      assert.strictEqual(aggregate.totalCount, 2);
    });

    it('should handle single-claim results', () => {
      const results: ClaimVerificationResult[] = [
        { label: 'only', verified: true },
      ];

      const aggregate = aggregateVerificationResults(results);

      assert.strictEqual(aggregate.allVerified, true);
      assert.strictEqual(aggregate.verifiedCount, 1);
      assert.strictEqual(aggregate.totalCount, 1);
    });

    it('should preserve per-claim error messages', () => {
      const results: ClaimVerificationResult[] = [
        { label: 'age', verified: false, error: 'Invalid proof structure' },
        { label: 'nat', verified: true },
      ];

      const aggregate = aggregateVerificationResults(results);
      const failed = aggregate.results.find((r) => !r.verified);

      assert.ok(failed);
      assert.strictEqual(failed.error, 'Invalid proof structure');
    });
  });
});
