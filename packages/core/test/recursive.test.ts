import { expect } from 'chai';
import {
  LogicalAggregator,
  createAggregateInput,
  isRecursiveProof,
  getConstituentPublicSignals,
  RECURSIVE_PROOF_STATUS,
  AggregateInput,
  AggregatedProof,
  SerializedProof,
} from '../src';

describe('Recursive Proof Aggregation', () => {
  function mockProof(label: string): SerializedProof {
    return {
      system: 'groth16',
      proof: {
        pi_a: ['1', '2'],
        pi_b: [['3', '4'], ['5', '6']],
        pi_c: ['7', '8'],
        protocol: 'groth16',
        curve: 'bn128',
      },
      publicSignals: [`${label}-signal-1`, `${label}-signal-2`],
    };
  }

  describe('createAggregateInput', () => {
    it('should create an aggregate input from proof and metadata', () => {
      const proof = mockProof('age');
      const input = createAggregateInput('age-check', proof, 'age-verify');
      expect(input.label).to.equal('age-check');
      expect(input.circuitId).to.equal('age-verify');
      expect(input.proof).to.equal(proof);
    });
  });

  describe('LogicalAggregator', () => {
    let aggregator: LogicalAggregator;

    before(() => {
      aggregator = new LogicalAggregator();
    });

    it('should have groth16 as aggregation system type', () => {
      expect(aggregator.aggregationSystem).to.equal('groth16');
    });

    it('should aggregate multiple proofs into a bundle', async () => {
      const inputs: AggregateInput[] = [
        createAggregateInput('age', mockProof('age'), 'age-verify'),
        createAggregateInput('nationality', mockProof('nat'), 'nationality-verify'),
      ];

      const result = await aggregator.aggregate(inputs);

      expect(result.count).to.equal(2);
      expect(result.constituentLabels).to.deep.equal(['age', 'nationality']);
      expect(result.isRecursive).to.be.false;
      expect(result.aggregateProof).to.be.null;
      expect(result.aggregationSystem).to.equal('none');
    });

    it('should preserve public signals per label', async () => {
      const inputs: AggregateInput[] = [
        createAggregateInput('claim-1', mockProof('c1'), 'circuit-a'),
        createAggregateInput('claim-2', mockProof('c2'), 'circuit-b'),
      ];

      const result = await aggregator.aggregate(inputs);

      expect(result.publicSignalsByLabel['claim-1']).to.deep.equal([
        'c1-signal-1',
        'c1-signal-2',
      ]);
      expect(result.publicSignalsByLabel['claim-2']).to.deep.equal([
        'c2-signal-1',
        'c2-signal-2',
      ]);
    });

    it('should reject empty input array', async () => {
      try {
        await aggregator.aggregate([]);
        expect.fail('Should have thrown');
      } catch (e: any) {
        expect(e.message).to.match(/zero/);
      }
    });

    it('verify should return false for logical aggregation', async () => {
      const inputs: AggregateInput[] = [
        createAggregateInput('test', mockProof('t'), 'test-circuit'),
      ];
      const aggregated = await aggregator.aggregate(inputs);
      const verifyResult = await aggregator.verify(aggregated);

      expect(verifyResult.verified).to.be.false;
      expect(verifyResult.totalCount).to.equal(1);
      expect(verifyResult.constituentResults[0].error).to.match(/individually/);
    });
  });

  describe('isRecursiveProof', () => {
    it('should return false for logical bundles', () => {
      const bundle: AggregatedProof = {
        aggregateProof: null,
        constituentLabels: ['a'],
        count: 1,
        aggregationSystem: 'none',
        isRecursive: false,
        publicSignalsByLabel: { a: ['1'] },
      };
      expect(isRecursiveProof(bundle)).to.be.false;
    });

    it('should return true for recursive proofs', () => {
      const recursive: AggregatedProof = {
        aggregateProof: mockProof('agg'),
        constituentLabels: ['a', 'b'],
        count: 2,
        aggregationSystem: 'groth16',
        isRecursive: true,
        publicSignalsByLabel: { a: ['1'], b: ['2'] },
      };
      expect(isRecursiveProof(recursive)).to.be.true;
    });
  });

  describe('getConstituentPublicSignals', () => {
    it('should return public signals for a known label', () => {
      const aggregated: AggregatedProof = {
        aggregateProof: null,
        constituentLabels: ['age'],
        count: 1,
        aggregationSystem: 'none',
        isRecursive: false,
        publicSignalsByLabel: { age: ['2026', '18', '123456'] },
      };
      const signals = getConstituentPublicSignals(aggregated, 'age');
      expect(signals).to.deep.equal(['2026', '18', '123456']);
    });

    it('should return undefined for unknown label', () => {
      const aggregated: AggregatedProof = {
        aggregateProof: null,
        constituentLabels: [],
        count: 0,
        aggregationSystem: 'none',
        isRecursive: false,
        publicSignalsByLabel: {},
      };
      expect(getConstituentPublicSignals(aggregated, 'missing')).to.be.undefined;
    });
  });

  describe('RECURSIVE_PROOF_STATUS', () => {
    it('should document groth16-in-groth16 as scaffold', () => {
      expect(RECURSIVE_PROOF_STATUS.groth16InGroth16.status).to.equal('scaffold');
    });

    it('should document nova as planned', () => {
      expect(RECURSIVE_PROOF_STATUS.nova.status).to.equal('planned');
    });

    it('should document halo2 as planned', () => {
      expect(RECURSIVE_PROOF_STATUS.halo2.status).to.equal('planned');
    });
  });
});
