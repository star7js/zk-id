import { expect } from 'chai';
import {
  Groth16ProvingSystem,
  PLONKProvingSystem,
  registerProvingSystem,
  getProvingSystem,
  listProvingSystems,
  PROVING_SYSTEM_COMPARISON,
  ProvingSystem,
  ProvingSystemType,
  SerializedProof,
  CircuitArtifacts,
  VerifierArtifacts,
} from '../src/proving-system';

describe('Proving System Abstraction', () => {
  describe('Groth16ProvingSystem', () => {
    it('should have type groth16', () => {
      const system = new Groth16ProvingSystem();
      expect(system.type).to.equal('groth16');
    });

    it('should implement ProvingSystem interface', () => {
      const system = new Groth16ProvingSystem();
      expect(system).to.have.property('prove');
      expect(system).to.have.property('verify');
      expect(system.prove).to.be.a('function');
      expect(system.verify).to.be.a('function');
    });
  });

  describe('PLONKProvingSystem', () => {
    it('should have type plonk', () => {
      const system = new PLONKProvingSystem();
      expect(system.type).to.equal('plonk');
    });

    it('should implement ProvingSystem interface', () => {
      const system = new PLONKProvingSystem();
      expect(system).to.have.property('prove');
      expect(system).to.have.property('verify');
    });
  });

  describe('Registry', () => {
    it('should have groth16 and plonk registered by default', () => {
      const systems = listProvingSystems();
      expect(systems).to.include('groth16');
      expect(systems).to.include('plonk');
    });

    it('should retrieve groth16 proving system', () => {
      const system = getProvingSystem('groth16');
      expect(system.type).to.equal('groth16');
    });

    it('should retrieve plonk proving system', () => {
      const system = getProvingSystem('plonk');
      expect(system.type).to.equal('plonk');
    });

    it('should throw for unregistered proving system', () => {
      expect(() => getProvingSystem('unknown' as ProvingSystemType)).to.throw(/not registered/);
    });

    it('should allow registering custom proving system', () => {
      const custom: ProvingSystem = {
        type: 'fflonk' as ProvingSystemType,
        async prove() {
          return {
            system: 'fflonk' as ProvingSystemType,
            proof: { pi_a: [], pi_b: [], pi_c: [], protocol: 'fflonk', curve: 'bn128' },
            publicSignals: [],
          };
        },
        async verify() {
          return true;
        },
      };
      registerProvingSystem(custom);
      const retrieved = getProvingSystem('fflonk');
      expect(retrieved.type).to.equal('fflonk');
    });
  });

  describe('SerializedProof structure', () => {
    it('should have required fields', () => {
      const proof: SerializedProof = {
        system: 'groth16',
        proof: {
          pi_a: ['1', '2'],
          pi_b: [
            ['3', '4'],
            ['5', '6'],
          ],
          pi_c: ['7', '8'],
          protocol: 'groth16',
          curve: 'bn128',
        },
        publicSignals: ['100', '18', '12345'],
      };

      expect(proof.system).to.equal('groth16');
      expect(proof.proof.pi_a).to.have.length(2);
      expect(proof.publicSignals).to.have.length(3);
    });
  });

  describe('CircuitArtifacts', () => {
    it('should hold wasm and proving key paths', () => {
      const artifacts: CircuitArtifacts = {
        wasmPath: '/path/to/circuit.wasm',
        provingKeyPath: '/path/to/circuit.zkey',
      };
      expect(artifacts.wasmPath).to.be.a('string');
      expect(artifacts.provingKeyPath).to.be.a('string');
    });
  });

  describe('VerifierArtifacts', () => {
    it('should hold a verification key object', () => {
      const artifacts: VerifierArtifacts = {
        verificationKey: { protocol: 'groth16', curve: 'bn128' },
      };
      expect(artifacts.verificationKey).to.be.an('object');
    });
  });

  describe('PROVING_SYSTEM_COMPARISON', () => {
    it('should contain tradeoff info for groth16, plonk, and fflonk', () => {
      expect(PROVING_SYSTEM_COMPARISON).to.have.length(3);
      const types = PROVING_SYSTEM_COMPARISON.map((c) => c.system);
      expect(types).to.include('groth16');
      expect(types).to.include('plonk');
      expect(types).to.include('fflonk');
    });

    it('groth16 should require per-circuit trusted setup', () => {
      const groth16 = PROVING_SYSTEM_COMPARISON.find((c) => c.system === 'groth16');
      expect(groth16!.trustedSetup).to.equal('per-circuit');
      expect(groth16!.maturity).to.equal('production');
    });

    it('plonk should use universal setup', () => {
      const plonk = PROVING_SYSTEM_COMPARISON.find((c) => c.system === 'plonk');
      expect(plonk!.trustedSetup).to.equal('universal');
    });
  });
});
