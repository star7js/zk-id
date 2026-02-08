import * as snarkjs from 'snarkjs';
import {
  Credential,
  AgeProof,
  NationalityProof,
  AgeProofSigned,
  NationalityProofSigned,
  AgeProofRevocable,
  CircuitSignatureInputs,
  RevocationWitness,
} from './types';
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
  nonce: string,
  requestTimestampMs: number,
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
    nonce: nonce,
    requestTimestamp: requestTimestampMs,
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
      nonce: publicSignals[3],
      requestTimestamp: parseInt(publicSignals[4]),
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
  minAge: number,
  nonce: string,
  requestTimestampMs: number
): Promise<AgeProof> {
  // These paths would be resolved relative to the circuits package
  const wasmPath = require.resolve('@zk-id/circuits/build/age-verify_js/age-verify.wasm');
  const zkeyPath = require.resolve('@zk-id/circuits/build/age-verify.zkey');

  return generateAgeProof(credential, minAge, nonce, requestTimestampMs, wasmPath, zkeyPath);
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
  nonce: string,
  requestTimestampMs: number,
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
    nonce: nonce,
    requestTimestamp: requestTimestampMs,
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
      nonce: publicSignals[2],
      requestTimestamp: parseInt(publicSignals[3]),
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
  targetNationality: number,
  nonce: string,
  requestTimestampMs: number
): Promise<NationalityProof> {
  // These paths would be resolved relative to the circuits package
  const wasmPath = require.resolve('@zk-id/circuits/build/nationality-verify_js/nationality-verify.wasm');
  const zkeyPath = require.resolve('@zk-id/circuits/build/nationality-verify.zkey');

  return generateNationalityProof(
    credential,
    targetNationality,
    nonce,
    requestTimestampMs,
    wasmPath,
    zkeyPath
  );
}

/**
 * Generates a zero-knowledge proof that includes on-circuit issuer signature verification
 */
export async function generateAgeProofSigned(
  credential: Credential,
  minAge: number,
  nonce: string,
  requestTimestampMs: number,
  signatureInputs: CircuitSignatureInputs,
  wasmPath: string,
  zkeyPath: string
): Promise<AgeProofSigned> {
  const currentYear = new Date().getFullYear();

  const credentialHash = await poseidonHash([
    credential.birthYear,
    credential.nationality,
    BigInt('0x' + credential.salt),
  ]);

  const input = {
    birthYear: credential.birthYear,
    nationality: credential.nationality,
    salt: BigInt('0x' + credential.salt).toString(),
    currentYear: currentYear,
    minAge: minAge,
    credentialHash: credentialHash.toString(),
    nonce: nonce,
    requestTimestamp: requestTimestampMs,
    issuerPublicKey: signatureInputs.issuerPublicKey,
    signatureR8: signatureInputs.signatureR8,
    signatureS: signatureInputs.signatureS,
  };

  const { proof, publicSignals } = await snarkjs.groth16.fullProve(
    input,
    wasmPath,
    zkeyPath
  );

  const issuerPublicKey = publicSignals.slice(5, 5 + 256);

  const formattedProof: AgeProofSigned = {
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
      nonce: publicSignals[3],
      requestTimestamp: parseInt(publicSignals[4]),
      issuerPublicKey: issuerPublicKey,
    },
  };

  return formattedProof;
}

/**
 * Generates age proof with signature verification using default circuit paths
 */
export async function generateAgeProofSignedAuto(
  credential: Credential,
  minAge: number,
  nonce: string,
  requestTimestampMs: number,
  signatureInputs: CircuitSignatureInputs
): Promise<AgeProofSigned> {
  const wasmPath = require.resolve(
    '@zk-id/circuits/build/age-verify-signed_js/age-verify-signed.wasm'
  );
  const zkeyPath = require.resolve('@zk-id/circuits/build/age-verify-signed.zkey');

  return generateAgeProofSigned(
    credential,
    minAge,
    nonce,
    requestTimestampMs,
    signatureInputs,
    wasmPath,
    zkeyPath
  );
}

/**
 * Generates nationality proof with on-circuit issuer signature verification
 */
export async function generateNationalityProofSigned(
  credential: Credential,
  targetNationality: number,
  nonce: string,
  requestTimestampMs: number,
  signatureInputs: CircuitSignatureInputs,
  wasmPath: string,
  zkeyPath: string
): Promise<NationalityProofSigned> {
  const credentialHash = await poseidonHash([
    credential.birthYear,
    credential.nationality,
    BigInt('0x' + credential.salt),
  ]);

  const input = {
    birthYear: credential.birthYear,
    nationality: credential.nationality,
    salt: BigInt('0x' + credential.salt).toString(),
    targetNationality: targetNationality,
    credentialHash: credentialHash.toString(),
    nonce: nonce,
    requestTimestamp: requestTimestampMs,
    issuerPublicKey: signatureInputs.issuerPublicKey,
    signatureR8: signatureInputs.signatureR8,
    signatureS: signatureInputs.signatureS,
  };

  const { proof, publicSignals } = await snarkjs.groth16.fullProve(
    input,
    wasmPath,
    zkeyPath
  );

  const issuerPublicKey = publicSignals.slice(4, 4 + 256);

  const formattedProof: NationalityProofSigned = {
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
      nonce: publicSignals[2],
      requestTimestamp: parseInt(publicSignals[3]),
      issuerPublicKey: issuerPublicKey,
    },
  };

  return formattedProof;
}

/**
 * Generates nationality proof with signature verification using default circuit paths
 */
export async function generateNationalityProofSignedAuto(
  credential: Credential,
  targetNationality: number,
  nonce: string,
  requestTimestampMs: number,
  signatureInputs: CircuitSignatureInputs
): Promise<NationalityProofSigned> {
  const wasmPath = require.resolve(
    '@zk-id/circuits/build/nationality-verify-signed_js/nationality-verify-signed.wasm'
  );
  const zkeyPath = require.resolve('@zk-id/circuits/build/nationality-verify-signed.zkey');

  return generateNationalityProofSigned(
    credential,
    targetNationality,
    nonce,
    requestTimestampMs,
    signatureInputs,
    wasmPath,
    zkeyPath
  );
}

/**
 * Generates a zero-knowledge proof that the credential holder is at least minAge years old
 * AND that the credential is in the valid credential Merkle tree (not revoked)
 *
 * @param credential - The user's credential (private)
 * @param minAge - The minimum age requirement (public)
 * @param nonce - Nonce for replay protection (public)
 * @param requestTimestampMs - Request timestamp in milliseconds (public)
 * @param merkleWitness - Merkle witness from the valid credential tree
 * @param wasmPath - Path to the compiled circuit WASM file
 * @param zkeyPath - Path to the proving key
 * @returns An AgeProofRevocable that can be verified without revealing the birth year
 */
export async function generateAgeProofRevocable(
  credential: Credential,
  minAge: number,
  nonce: string,
  requestTimestampMs: number,
  merkleWitness: RevocationWitness,
  wasmPath: string,
  zkeyPath: string
): Promise<AgeProofRevocable> {
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
    merkleRoot: merkleWitness.root,
    pathIndices: merkleWitness.pathIndices,
    siblings: merkleWitness.siblings,
    nonce: nonce,
    requestTimestamp: requestTimestampMs,
  };

  // Generate the proof using snarkjs
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(
    input,
    wasmPath,
    zkeyPath
  );

  // Format the proof
  // Public signal index mapping: [0]=currentYear, [1]=minAge, [2]=credentialHash, [3]=merkleRoot, [4]=nonce, [5]=requestTimestamp
  const formattedProof: AgeProofRevocable = {
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
      merkleRoot: publicSignals[3],
      nonce: publicSignals[4],
      requestTimestamp: parseInt(publicSignals[5]),
    },
  };

  return formattedProof;
}

/**
 * Generates revocable age proof with automatic path resolution
 * (assumes standard build directory structure)
 */
export async function generateAgeProofRevocableAuto(
  credential: Credential,
  minAge: number,
  nonce: string,
  requestTimestampMs: number,
  merkleWitness: RevocationWitness
): Promise<AgeProofRevocable> {
  const wasmPath = require.resolve('@zk-id/circuits/build/age-verify-revocable_js/age-verify-revocable.wasm');
  const zkeyPath = require.resolve('@zk-id/circuits/build/age-verify-revocable.zkey');

  return generateAgeProofRevocable(
    credential,
    minAge,
    nonce,
    requestTimestampMs,
    merkleWitness,
    wasmPath,
    zkeyPath
  );
}
