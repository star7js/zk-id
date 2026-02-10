declare module 'snarkjs' {
  export namespace groth16 {
    export function fullProve(
      input: any,
      wasmFile: string,
      zkeyFileName: string,
    ): Promise<{
      proof: any;
      publicSignals: string[];
    }>;

    export function verify(vk: any, publicSignals: string[], proof: any): Promise<boolean>;

    export function exportSolidityCallData(proof: any, publicSignals: string[]): Promise<string>;
  }

  export namespace plonk {
    export function fullProve(
      input: any,
      wasmFile: string,
      zkeyFileName: string,
    ): Promise<{
      proof: any;
      publicSignals: string[];
    }>;

    export function verify(vk: any, publicSignals: string[], proof: any): Promise<boolean>;
  }

  export namespace powersOfTau {
    export function newAccumulator(
      curve: any,
      power: number,
      fileName: string,
      logger: any,
    ): Promise<void>;
  }

  export namespace zKey {
    export function newZKey(
      r1csFileName: string,
      ptauFileName: string,
      zkeyFileName: string,
      logger?: any,
    ): Promise<void>;

    export function contribute(
      zkeyFileNameOld: string,
      zkeyFileNameNew: string,
      name: string,
      entropy: string,
      logger?: any,
    ): Promise<any>;

    export function exportVerificationKey(zkeyFileName: string): Promise<any>;
  }
}
