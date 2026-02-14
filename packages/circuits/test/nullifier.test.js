const path = require('path');
const _snarkjs = require('snarkjs');
const wasm_tester = require('circom_tester').wasm;
const { buildPoseidon } = require('circomlibjs');

describe('Nullifier Circuit Tests', function () {
  let circuit;
  let poseidon;

  before(async function () {
    circuit = await wasm_tester(path.join(__dirname, '../src/nullifier.circom'), {
      include: path.join(__dirname, '../../../node_modules'),
    });
    poseidon = await buildPoseidon();
  });

  // Helper function to compute credential hash (with domain separation)
  // Domain tag 0 = DOMAIN_CREDENTIAL (must match circuit and poseidon.ts)
  function computeCredentialHash(birthYear, nationality, salt) {
    const hash = poseidon([0, birthYear, nationality, salt]);
    return poseidon.F.toString(hash);
  }

  // Helper function to compute nullifier (with domain separation)
  // Domain tag 1 = DOMAIN_NULLIFIER (must match circuit and poseidon.ts)
  function computeNullifier(credentialHash, scopeHash) {
    const hash = poseidon([1, BigInt(credentialHash), BigInt(scopeHash)]);
    return poseidon.F.toString(hash);
  }

  it('should compute valid nullifier', async function () {
    const birthYear = 2000;
    const nationality = 840;
    const salt = 12345n;
    const scopeHash = '123456789';

    const credentialHash = computeCredentialHash(birthYear, nationality, salt);
    const nullifier = computeNullifier(credentialHash, scopeHash);

    const input = {
      birthYear: birthYear,
      nationality: nationality,
      salt: salt.toString(),
      credentialHash: credentialHash,
      scopeHash: scopeHash,
      nullifier: nullifier,
    };

    const witness = await circuit.calculateWitness(input);
    await circuit.checkConstraints(witness);
  });

  it('should produce deterministic nullifier for same credential and scope', async function () {
    const birthYear = 1995;
    const nationality = 826;
    const salt = 99999n;
    const scopeHash = '987654321';

    const credentialHash = computeCredentialHash(birthYear, nationality, salt);
    const nullifier = computeNullifier(credentialHash, scopeHash);

    const input1 = {
      birthYear: birthYear,
      nationality: nationality,
      salt: salt.toString(),
      credentialHash: credentialHash,
      scopeHash: scopeHash,
      nullifier: nullifier,
    };

    const input2 = {
      birthYear: birthYear,
      nationality: nationality,
      salt: salt.toString(),
      credentialHash: credentialHash,
      scopeHash: scopeHash,
      nullifier: nullifier,
    };

    const witness1 = await circuit.calculateWitness(input1);
    const witness2 = await circuit.calculateWitness(input2);

    await circuit.checkConstraints(witness1);
    await circuit.checkConstraints(witness2);

    // Both witnesses should be identical (determinism)
    // Nullifier should be the same for same credential + scope
  });

  it('should produce different nullifiers for different scopes', async function () {
    const birthYear = 2000;
    const nationality = 840;
    const salt = 12345n;
    const scopeHash1 = '111111111';
    const scopeHash2 = '222222222';

    const credentialHash = computeCredentialHash(birthYear, nationality, salt);
    const nullifier1 = computeNullifier(credentialHash, scopeHash1);
    const nullifier2 = computeNullifier(credentialHash, scopeHash2);

    const input1 = {
      birthYear: birthYear,
      nationality: nationality,
      salt: salt.toString(),
      credentialHash: credentialHash,
      scopeHash: scopeHash1,
      nullifier: nullifier1,
    };

    const input2 = {
      birthYear: birthYear,
      nationality: nationality,
      salt: salt.toString(),
      credentialHash: credentialHash,
      scopeHash: scopeHash2,
      nullifier: nullifier2,
    };

    const witness1 = await circuit.calculateWitness(input1);
    const witness2 = await circuit.calculateWitness(input2);

    await circuit.checkConstraints(witness1);
    await circuit.checkConstraints(witness2);

    // Nullifiers should be different for different scopes
    if (nullifier1 === nullifier2) {
      throw new Error('Nullifiers should be different for different scopes');
    }
  });

  it('should fail when credential preimage does not match credentialHash', async function () {
    const birthYear = 2000;
    const nationality = 840;
    const salt = 12345n;
    const wrongBirthYear = 1995;
    const scopeHash = '123456789';

    // Compute credential hash with correct values
    const credentialHash = computeCredentialHash(birthYear, nationality, salt);
    const nullifier = computeNullifier(credentialHash, scopeHash);

    // But provide wrong birthYear as private input
    const input = {
      birthYear: wrongBirthYear,
      nationality: nationality,
      salt: salt.toString(),
      credentialHash: credentialHash,
      scopeHash: scopeHash,
      nullifier: nullifier,
    };

    try {
      await circuit.calculateWitness(input);
      throw new Error('Expected constraint failure but proof succeeded');
    } catch (error) {
      if (error.message.includes('Expected constraint failure')) {
        throw error;
      }
      // Success - constraint properly failed due to credential hash mismatch
    }
  });

  it('should fail when nullifier does not match computed value', async function () {
    const birthYear = 2000;
    const nationality = 840;
    const salt = 12345n;
    const scopeHash = '123456789';

    const credentialHash = computeCredentialHash(birthYear, nationality, salt);
    const _correctNullifier = computeNullifier(credentialHash, scopeHash);
    const wrongNullifier = '999999999999999999';

    const input = {
      birthYear: birthYear,
      nationality: nationality,
      salt: salt.toString(),
      credentialHash: credentialHash,
      scopeHash: scopeHash,
      nullifier: wrongNullifier,
    };

    try {
      await circuit.calculateWitness(input);
      throw new Error('Expected constraint failure but proof succeeded');
    } catch (error) {
      if (error.message.includes('Expected constraint failure')) {
        throw error;
      }
      // Success - constraint properly failed due to nullifier mismatch
    }
  });

  it('should produce different nullifiers for different credentials in same scope', async function () {
    const birthYear1 = 2000;
    const birthYear2 = 1995;
    const nationality = 840;
    const salt1 = 12345n;
    const salt2 = 67890n;
    const scopeHash = '123456789';

    const credentialHash1 = computeCredentialHash(birthYear1, nationality, salt1);
    const credentialHash2 = computeCredentialHash(birthYear2, nationality, salt2);
    const nullifier1 = computeNullifier(credentialHash1, scopeHash);
    const nullifier2 = computeNullifier(credentialHash2, scopeHash);

    const input1 = {
      birthYear: birthYear1,
      nationality: nationality,
      salt: salt1.toString(),
      credentialHash: credentialHash1,
      scopeHash: scopeHash,
      nullifier: nullifier1,
    };

    const input2 = {
      birthYear: birthYear2,
      nationality: nationality,
      salt: salt2.toString(),
      credentialHash: credentialHash2,
      scopeHash: scopeHash,
      nullifier: nullifier2,
    };

    const witness1 = await circuit.calculateWitness(input1);
    const witness2 = await circuit.calculateWitness(input2);

    await circuit.checkConstraints(witness1);
    await circuit.checkConstraints(witness2);

    // Different credentials should produce different nullifiers
    if (nullifier1 === nullifier2) {
      throw new Error('Different credentials should produce different nullifiers');
    }
  });
});
