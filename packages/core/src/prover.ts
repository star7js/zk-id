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
  NullifierProof,
} from './types';
import { poseidonHash } from './poseidon';
import {
  validateMinAge,
  validateNonce,
  validateRequestTimestamp,
  validateNationality,
  validateHexString,
  validateBigIntString,
  validateFieldElement,
} from './validation';

/**
 * Generates a zero-knowledge proof that the credential holder is at least minAge years old
 *
 * @param credential - The user's credential (private)
 * @param minAge - The minimum age requirement (public)
 * @param nonce - Nonce for replay protection (public)
 * @param requestTimestampMs - Request timestamp in milliseconds (public)
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
  zkeyPath: string,
): Promise<AgeProof> {
  validateMinAge(minAge);
  validateNonce(nonce);
  validateRequestTimestamp(requestTimestampMs);
  validateHexString(credential.salt, 'credential.salt');

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
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(input, wasmPath, zkeyPath);

  // Format the proof
  const formattedProof: AgeProof = {
    proofType: 'age',
    proof: {
      pi_a: proof.pi_a.slice(0, 2).map((x: unknown) => String(x)),
      pi_b: proof.pi_b.slice(0, 2).map((arr: unknown[]) => arr.map((x: unknown) => String(x))),
      pi_c: proof.pi_c.slice(0, 2).map((x: unknown) => String(x)),
      protocol: proof.protocol,
      curve: proof.curve,
    },
    publicSignals: {
      currentYear: parseInt(publicSignals[0], 10),
      minAge: parseInt(publicSignals[1], 10),
      credentialHash: publicSignals[2],
      nonce: publicSignals[3],
      requestTimestamp: parseInt(publicSignals[4], 10),
    },
  };

  return formattedProof;
}

/**
 * Generates proof with automatic path resolution
 * (assumes standard build directory structure)
 *
 * @param credential - The user's credential (private)
 * @param minAge - The minimum age requirement (public)
 * @param nonce - Nonce for replay protection (public)
 * @param requestTimestampMs - Request timestamp in milliseconds (public)
 * @returns An AgeProof that can be verified without revealing the birth year
 */
export async function generateAgeProofAuto(
  credential: Credential,
  minAge: number,
  nonce: string,
  requestTimestampMs: number,
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
 * @param nonce - Nonce for replay protection (public)
 * @param requestTimestampMs - Request timestamp in milliseconds (public)
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
  zkeyPath: string,
): Promise<NationalityProof> {
  validateNationality(targetNationality);
  validateNonce(nonce);
  validateRequestTimestamp(requestTimestampMs);
  validateHexString(credential.salt, 'credential.salt');

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
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(input, wasmPath, zkeyPath);

  // Format the proof
  const formattedProof: NationalityProof = {
    proofType: 'nationality',
    proof: {
      pi_a: proof.pi_a.slice(0, 2).map((x: unknown) => String(x)),
      pi_b: proof.pi_b.slice(0, 2).map((arr: unknown[]) => arr.map((x: unknown) => String(x))),
      pi_c: proof.pi_c.slice(0, 2).map((x: unknown) => String(x)),
      protocol: proof.protocol,
      curve: proof.curve,
    },
    publicSignals: {
      targetNationality: parseInt(publicSignals[0], 10),
      credentialHash: publicSignals[1],
      nonce: publicSignals[2],
      requestTimestamp: parseInt(publicSignals[3], 10),
    },
  };

  return formattedProof;
}

/**
 * Generates nationality proof with automatic path resolution
 * (assumes standard build directory structure)
 *
 * @param credential - The user's credential (private)
 * @param targetNationality - The nationality to verify (public)
 * @param nonce - Nonce for replay protection (public)
 * @param requestTimestampMs - Request timestamp in milliseconds (public)
 * @returns A NationalityProof that can be verified without revealing the birth year
 */
export async function generateNationalityProofAuto(
  credential: Credential,
  targetNationality: number,
  nonce: string,
  requestTimestampMs: number,
): Promise<NationalityProof> {
  // These paths would be resolved relative to the circuits package
  const wasmPath =
    require.resolve('@zk-id/circuits/build/nationality-verify_js/nationality-verify.wasm');
  const zkeyPath = require.resolve('@zk-id/circuits/build/nationality-verify.zkey');

  return generateNationalityProof(
    credential,
    targetNationality,
    nonce,
    requestTimestampMs,
    wasmPath,
    zkeyPath,
  );
}

/**
 * Generates a zero-knowledge proof that includes on-circuit issuer signature verification
 *
 * @param credential - The user's credential (private)
 * @param minAge - The minimum age requirement (public)
 * @param nonce - Nonce for replay protection (public)
 * @param requestTimestampMs - Request timestamp in milliseconds (public)
 * @param signatureInputs - Issuer signature components for circuit verification
 * @param wasmPath - Path to the compiled circuit WASM file
 * @param zkeyPath - Path to the proving key
 * @returns A signed AgeProof with embedded issuer public key bits
 */
export async function generateAgeProofSigned(
  credential: Credential,
  minAge: number,
  nonce: string,
  requestTimestampMs: number,
  signatureInputs: CircuitSignatureInputs,
  wasmPath: string,
  zkeyPath: string,
): Promise<AgeProofSigned> {
  validateMinAge(minAge);
  validateNonce(nonce);
  validateRequestTimestamp(requestTimestampMs);
  validateHexString(credential.salt, 'credential.salt');

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

  const { proof, publicSignals } = await snarkjs.groth16.fullProve(input, wasmPath, zkeyPath);

  const issuerPublicKey = publicSignals.slice(5, 5 + 256);

  const formattedProof: AgeProofSigned = {
    proofType: 'age-signed',
    proof: {
      pi_a: proof.pi_a.slice(0, 2).map((x: unknown) => String(x)),
      pi_b: proof.pi_b.slice(0, 2).map((arr: unknown[]) => arr.map((x: unknown) => String(x))),
      pi_c: proof.pi_c.slice(0, 2).map((x: unknown) => String(x)),
      protocol: proof.protocol,
      curve: proof.curve,
    },
    publicSignals: {
      currentYear: parseInt(publicSignals[0], 10),
      minAge: parseInt(publicSignals[1], 10),
      credentialHash: publicSignals[2],
      nonce: publicSignals[3],
      requestTimestamp: parseInt(publicSignals[4], 10),
      issuerPublicKey: issuerPublicKey,
    },
  };

  return formattedProof;
}

/**
 * Generates age proof with signature verification using default circuit paths
 *
 * @param credential - The user's credential (private)
 * @param minAge - The minimum age requirement (public)
 * @param nonce - Nonce for replay protection (public)
 * @param requestTimestampMs - Request timestamp in milliseconds (public)
 * @param signatureInputs - Issuer signature components for circuit verification
 * @returns A signed AgeProof with embedded issuer public key bits
 */
export async function generateAgeProofSignedAuto(
  credential: Credential,
  minAge: number,
  nonce: string,
  requestTimestampMs: number,
  signatureInputs: CircuitSignatureInputs,
): Promise<AgeProofSigned> {
  const wasmPath =
    require.resolve('@zk-id/circuits/build/age-verify-signed_js/age-verify-signed.wasm');
  const zkeyPath = require.resolve('@zk-id/circuits/build/age-verify-signed.zkey');

  return generateAgeProofSigned(
    credential,
    minAge,
    nonce,
    requestTimestampMs,
    signatureInputs,
    wasmPath,
    zkeyPath,
  );
}

/**
 * Generates nationality proof with on-circuit issuer signature verification
 *
 * @param credential - The user's credential (private)
 * @param targetNationality - The nationality to verify (public)
 * @param nonce - Nonce for replay protection (public)
 * @param requestTimestampMs - Request timestamp in milliseconds (public)
 * @param signatureInputs - Issuer signature components for circuit verification
 * @param wasmPath - Path to the compiled circuit WASM file
 * @param zkeyPath - Path to the proving key
 * @returns A signed NationalityProof with embedded issuer public key bits
 */
export async function generateNationalityProofSigned(
  credential: Credential,
  targetNationality: number,
  nonce: string,
  requestTimestampMs: number,
  signatureInputs: CircuitSignatureInputs,
  wasmPath: string,
  zkeyPath: string,
): Promise<NationalityProofSigned> {
  validateNationality(targetNationality);
  validateNonce(nonce);
  validateRequestTimestamp(requestTimestampMs);
  validateHexString(credential.salt, 'credential.salt');

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

  const { proof, publicSignals } = await snarkjs.groth16.fullProve(input, wasmPath, zkeyPath);

  const issuerPublicKey = publicSignals.slice(4, 4 + 256);

  const formattedProof: NationalityProofSigned = {
    proofType: 'nationality-signed',
    proof: {
      pi_a: proof.pi_a.slice(0, 2).map((x: unknown) => String(x)),
      pi_b: proof.pi_b.slice(0, 2).map((arr: unknown[]) => arr.map((x: unknown) => String(x))),
      pi_c: proof.pi_c.slice(0, 2).map((x: unknown) => String(x)),
      protocol: proof.protocol,
      curve: proof.curve,
    },
    publicSignals: {
      targetNationality: parseInt(publicSignals[0], 10),
      credentialHash: publicSignals[1],
      nonce: publicSignals[2],
      requestTimestamp: parseInt(publicSignals[3], 10),
      issuerPublicKey: issuerPublicKey,
    },
  };

  return formattedProof;
}

/**
 * Generates nationality proof with signature verification using default circuit paths
 *
 * @param credential - The user's credential (private)
 * @param targetNationality - The nationality to verify (public)
 * @param nonce - Nonce for replay protection (public)
 * @param requestTimestampMs - Request timestamp in milliseconds (public)
 * @param signatureInputs - Issuer signature components for circuit verification
 * @returns A signed NationalityProof with embedded issuer public key bits
 */
export async function generateNationalityProofSignedAuto(
  credential: Credential,
  targetNationality: number,
  nonce: string,
  requestTimestampMs: number,
  signatureInputs: CircuitSignatureInputs,
): Promise<NationalityProofSigned> {
  const wasmPath =
    require.resolve('@zk-id/circuits/build/nationality-verify-signed_js/nationality-verify-signed.wasm');
  const zkeyPath = require.resolve('@zk-id/circuits/build/nationality-verify-signed.zkey');

  return generateNationalityProofSigned(
    credential,
    targetNationality,
    nonce,
    requestTimestampMs,
    signatureInputs,
    wasmPath,
    zkeyPath,
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
  zkeyPath: string,
): Promise<AgeProofRevocable> {
  validateMinAge(minAge);
  validateNonce(nonce);
  validateRequestTimestamp(requestTimestampMs);
  validateHexString(credential.salt, 'credential.salt');

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
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(input, wasmPath, zkeyPath);

  // Format the proof
  // Public signal index mapping: [0]=currentYear, [1]=minAge, [2]=credentialHash, [3]=merkleRoot, [4]=nonce, [5]=requestTimestamp
  const formattedProof: AgeProofRevocable = {
    proofType: 'age-revocable',
    proof: {
      pi_a: proof.pi_a.slice(0, 2).map((x: unknown) => String(x)),
      pi_b: proof.pi_b.slice(0, 2).map((arr: unknown[]) => arr.map((x: unknown) => String(x))),
      pi_c: proof.pi_c.slice(0, 2).map((x: unknown) => String(x)),
      protocol: proof.protocol,
      curve: proof.curve,
    },
    publicSignals: {
      currentYear: parseInt(publicSignals[0], 10),
      minAge: parseInt(publicSignals[1], 10),
      credentialHash: publicSignals[2],
      merkleRoot: publicSignals[3],
      nonce: publicSignals[4],
      requestTimestamp: parseInt(publicSignals[5], 10),
    },
  };

  return formattedProof;
}

/**
 * Generates revocable age proof with automatic path resolution
 * (assumes standard build directory structure)
 *
 * @param credential - The user's credential (private)
 * @param minAge - The minimum age requirement (public)
 * @param nonce - Nonce for replay protection (public)
 * @param requestTimestampMs - Request timestamp in milliseconds (public)
 * @param revocationWitness - Merkle witness proving credential is in the valid credential tree
 * @returns An AgeProofRevocable that includes Merkle root verification
 */
export async function generateAgeProofRevocableAuto(
  credential: Credential,
  minAge: number,
  nonce: string,
  requestTimestampMs: number,
  merkleWitness: RevocationWitness,
): Promise<AgeProofRevocable> {
  const wasmPath =
    require.resolve('@zk-id/circuits/build/age-verify-revocable_js/age-verify-revocable.wasm');
  const zkeyPath = require.resolve('@zk-id/circuits/build/age-verify-revocable.zkey');

  return generateAgeProofRevocable(
    credential,
    minAge,
    nonce,
    requestTimestampMs,
    merkleWitness,
    wasmPath,
    zkeyPath,
  );
}

/**
 * Generates a zero-knowledge nullifier proof for sybil resistance
 *
 * @param credential - The user's credential (private)
 * @param scopeHash - The scope hash (public, determines the nullifier context)
 * @param wasmPath - Path to the compiled circuit WASM file
 * @param zkeyPath - Path to the proving key
 * @returns A NullifierProof that proves knowledge of the credential and computes the nullifier
 */
export async function generateNullifierProof(
  credential: Credential,
  scopeHash: string,
  wasmPath: string,
  zkeyPath: string,
): Promise<NullifierProof> {
  validateHexString(credential.salt, 'credential.salt');
  validateBigIntString(scopeHash, 'scopeHash');
  const scopeHashBigInt = BigInt(scopeHash);
  validateFieldElement(scopeHashBigInt, 'scopeHash');

  // Compute the credential hash (commitment)
  const credentialHash = await poseidonHash([
    credential.birthYear,
    credential.nationality,
    BigInt('0x' + credential.salt),
  ]);

  // Compute the nullifier = Poseidon(credentialHash, scopeHash)
  const nullifier = await poseidonHash([credentialHash, scopeHashBigInt]);

  // Prepare circuit inputs
  const input = {
    birthYear: credential.birthYear,
    nationality: credential.nationality,
    salt: BigInt('0x' + credential.salt).toString(),
    credentialHash: credentialHash.toString(),
    scopeHash: scopeHashBigInt.toString(),
    nullifier: nullifier.toString(),
  };

  // Generate the proof using snarkjs
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(input, wasmPath, zkeyPath);

  // Format the proof
  const formattedProof: NullifierProof = {
    proofType: 'nullifier',
    proof: {
      pi_a: proof.pi_a.slice(0, 2).map((x: unknown) => String(x)),
      pi_b: proof.pi_b.slice(0, 2).map((arr: unknown[]) => arr.map((x: unknown) => String(x))),
      pi_c: proof.pi_c.slice(0, 2).map((x: unknown) => String(x)),
    },
    publicSignals: {
      credentialHash: publicSignals[0],
      scopeHash: publicSignals[1],
      nullifier: publicSignals[2],
    },
  };

  return formattedProof;
}

/**
 * Generates nullifier proof with automatic path resolution
 * (assumes standard build directory structure)
 *
 * @param credential - The user's credential (private)
 * @param scope - The nullifier scope defining the context
 * @param nonce - Nonce for replay protection (public)
 * @param requestTimestampMs - Request timestamp in milliseconds (public)
 * @returns A NullifierProof proving credential ownership without revealing identity
 */
export async function generateNullifierProofAuto(
  credential: Credential,
  scopeHash: string,
): Promise<NullifierProof> {
  const wasmPath = require.resolve('@zk-id/circuits/build/nullifier_js/nullifier.wasm');
  const zkeyPath = require.resolve('@zk-id/circuits/build/nullifier.zkey');

  return generateNullifierProof(credential, scopeHash, wasmPath, zkeyPath);
}

/**
 * Generates a range proof that a value lies within [minValue, maxValue]
 * without revealing the actual value.
 *
 * @param value - The actual value (private)
 * @param salt - Random salt for commitment uniqueness (private)
 * @param minValue - Lower bound of the range (public)
 * @param maxValue - Upper bound of the range (public)
 * @param wasmPath - Path to the compiled circuit WASM file
 * @param zkeyPath - Path to the proving key
 * @returns A RangeProof that can be verified without revealing the value
 */
export async function generateRangeProof(
  value: number,
  salt: bigint,
  minValue: number,
  maxValue: number,
  wasmPath: string,
  zkeyPath: string,
): Promise<{
  proofType: 'range';
  proof: { pi_a: string[]; pi_b: string[][]; pi_c: string[]; protocol: string; curve: string };
  publicSignals: string[];
  fieldName: string;
}> {
  // Validate inputs
  if (value < 0) {
    throw new Error('Value must be non-negative');
  }
  if (minValue < 0 || maxValue < 0) {
    throw new Error('Range bounds must be non-negative');
  }
  if (minValue > maxValue) {
    throw new Error('minValue must be less than or equal to maxValue');
  }

  // Compute commitment
  const commitment = await poseidonHash([BigInt(value), salt]);

  // Prepare circuit inputs
  const input = {
    value: value,
    salt: salt.toString(),
    minValue: minValue,
    maxValue: maxValue,
    commitment: commitment.toString(),
  };

  // Generate the proof using snarkjs
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(input, wasmPath, zkeyPath);

  // Format the proof
  return {
    proofType: 'range',
    proof: {
      pi_a: proof.pi_a.slice(0, 2).map((x: unknown) => String(x)),
      pi_b: proof.pi_b.slice(0, 2).map((arr: unknown[]) => arr.map((x: unknown) => String(x))),
      pi_c: proof.pi_c.slice(0, 2).map((x: unknown) => String(x)),
      protocol: proof.protocol,
      curve: proof.curve,
    },
    publicSignals: publicSignals.map((x: unknown) => String(x)),
    fieldName: 'value', // Default field name
  };
}
