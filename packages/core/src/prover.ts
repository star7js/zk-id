import * as snarkjs from 'snarkjs';
import { Credential, AgeProof, NationalityProof } from './types';
import { poseidonHash } from './poseidon';

/**
 * Generates a zero-knowledge proof that the credential holder is at least minAge years old
 *
 * @param credential - The user's credential (private)
 * @param minAge - The minimum age requirement (public)
 * @param wasmPath - Path to the compiled circuit WASM file
 * @param zkeyPath - Path to the proving key
 * @returns An AgeProof that can be verified without revealing the birth year
 */
export async function generateAgeProof(
  credential: Credential,
  minAge: number,
  wasmPath: string,
  zkeyPath: string
): Promise<AgeProof> {
  const currentYear = new Date().getFullYear();

  // Recompute the credential hash to use as a public signal
  const credentialHash = await poseidonHash([
    credential.birthYear,
    credential.nationality,
    BigInt('0x' + credential.salt),
  ]);

  // Prepare circuit inputs
  const input = {
    birthYear: credential.birthYear,
    nationality: credential.nationality,
    salt: BigInt('0x' + credential.salt).toString(),
    currentYear: currentYear,
    minAge: minAge,
    credentialHash: credentialHash.toString(),
  };

  // Generate the proof using snarkjs
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(
    input,
    wasmPath,
    zkeyPath
  );

  // Format the proof
  const formattedProof: AgeProof = {
    proof: {
      pi_a: proof.pi_a.slice(0, 2).map((x: any) => x.toString()),
      pi_b: proof.pi_b.slice(0, 2).map((arr: any) =>
        arr.map((x: any) => x.toString())
      ),
      pi_c: proof.pi_c.slice(0, 2).map((x: any) => x.toString()),
      protocol: proof.protocol,
      curve: proof.curve,
    },
    publicSignals: {
      currentYear: parseInt(publicSignals[0]),
      minAge: parseInt(publicSignals[1]),
      credentialHash: publicSignals[2],
    },
  };

  return formattedProof;
}

/**
 * Generates proof with automatic path resolution
 * (assumes standard build directory structure)
 */
export async function generateAgeProofAuto(
  credential: Credential,
  minAge: number
): Promise<AgeProof> {
  // These paths would be resolved relative to the circuits package
  const wasmPath = require.resolve('@zk-id/circuits/build/age-verify_js/age-verify.wasm');
  const zkeyPath = require.resolve('@zk-id/circuits/build/age-verify.zkey');

  return generateAgeProof(credential, minAge, wasmPath, zkeyPath);
}

/**
 * Generates a zero-knowledge proof that the credential holder has the target nationality
 *
 * @param credential - The user's credential (private)
 * @param targetNationality - The nationality to verify (public)
 * @param wasmPath - Path to the compiled circuit WASM file
 * @param zkeyPath - Path to the proving key
 * @returns A NationalityProof that can be verified without revealing the birth year
 */
export async function generateNationalityProof(
  credential: Credential,
  targetNationality: number,
  wasmPath: string,
  zkeyPath: string
): Promise<NationalityProof> {
  // Recompute the credential hash to use as a public signal
  const credentialHash = await poseidonHash([
    credential.birthYear,
    credential.nationality,
    BigInt('0x' + credential.salt),
  ]);

  // Prepare circuit inputs
  const input = {
    birthYear: credential.birthYear,
    nationality: credential.nationality,
    salt: BigInt('0x' + credential.salt).toString(),
    targetNationality: targetNationality,
    credentialHash: credentialHash.toString(),
  };

  // Generate the proof using snarkjs
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(
    input,
    wasmPath,
    zkeyPath
  );

  // Format the proof
  const formattedProof: NationalityProof = {
    proof: {
      pi_a: proof.pi_a.slice(0, 2).map((x: any) => x.toString()),
      pi_b: proof.pi_b.slice(0, 2).map((arr: any) =>
        arr.map((x: any) => x.toString())
      ),
      pi_c: proof.pi_c.slice(0, 2).map((x: any) => x.toString()),
      protocol: proof.protocol,
      curve: proof.curve,
    },
    publicSignals: {
      targetNationality: parseInt(publicSignals[0]),
      credentialHash: publicSignals[1],
    },
  };

  return formattedProof;
}

/**
 * Generates nationality proof with automatic path resolution
 * (assumes standard build directory structure)
 */
export async function generateNationalityProofAuto(
  credential: Credential,
  targetNationality: number
): Promise<NationalityProof> {
  // These paths would be resolved relative to the circuits package
  const wasmPath = require.resolve('@zk-id/circuits/build/nationality-verify_js/nationality-verify.wasm');
  const zkeyPath = require.resolve('@zk-id/circuits/build/nationality-verify.zkey');

  return generateNationalityProof(credential, targetNationality, wasmPath, zkeyPath);
}
