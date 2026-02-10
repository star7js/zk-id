const path = require('path');
const _snarkjs = require('snarkjs');
const wasm_tester = require('circom_tester').wasm;

describe('CredentialHash Circuit Tests', function () {
  let circuit;

  before(async function () {
    circuit = await wasm_tester(path.join(__dirname, '../src/credential-hash.circom'), {
      include: path.join(__dirname, '../../../node_modules'),
    });
  });

  it('should compute hash for valid inputs', async function () {
    const input = {
      birthYear: 1990,
      nationality: 840, // USA
      salt: 123456789,
    };

    const witness = await circuit.calculateWitness(input);
    await circuit.checkConstraints(witness);

    // Check that output exists and is non-zero
    const output = witness[1]; // First signal after public inputs
    if (output === 0n) {
      throw new Error('Hash output should not be zero');
    }
  });

  it('should produce different hashes for different birth years', async function () {
    const input1 = {
      birthYear: 1990,
      nationality: 840,
      salt: 123456789,
    };

    const input2 = {
      birthYear: 1991,
      nationality: 840,
      salt: 123456789,
    };

    const witness1 = await circuit.calculateWitness(input1);
    const witness2 = await circuit.calculateWitness(input2);

    await circuit.checkConstraints(witness1);
    await circuit.checkConstraints(witness2);

    const hash1 = witness1[1];
    const hash2 = witness2[1];

    if (hash1 === hash2) {
      throw new Error('Different birth years should produce different hashes');
    }
  });

  it('should produce different hashes for different salts', async function () {
    const input1 = {
      birthYear: 1990,
      nationality: 840,
      salt: 111111111,
    };

    const input2 = {
      birthYear: 1990,
      nationality: 840,
      salt: 222222222,
    };

    const witness1 = await circuit.calculateWitness(input1);
    const witness2 = await circuit.calculateWitness(input2);

    await circuit.checkConstraints(witness1);
    await circuit.checkConstraints(witness2);

    const hash1 = witness1[1];
    const hash2 = witness2[1];

    if (hash1 === hash2) {
      throw new Error('Different salts should produce different hashes');
    }
  });

  it('should produce same hash for same inputs (deterministic)', async function () {
    const input = {
      birthYear: 1995,
      nationality: 840,
      salt: 987654321,
    };

    const witness1 = await circuit.calculateWitness(input);
    const witness2 = await circuit.calculateWitness(input);

    await circuit.checkConstraints(witness1);
    await circuit.checkConstraints(witness2);

    const hash1 = witness1[1];
    const hash2 = witness2[1];

    if (hash1 !== hash2) {
      throw new Error('Same inputs should produce same hash');
    }
  });

  it('should produce different hashes for different nationalities', async function () {
    const input1 = {
      birthYear: 1990,
      nationality: 840, // USA
      salt: 123456789,
    };

    const input2 = {
      birthYear: 1990,
      nationality: 826, // UK
      salt: 123456789,
    };

    const witness1 = await circuit.calculateWitness(input1);
    const witness2 = await circuit.calculateWitness(input2);

    await circuit.checkConstraints(witness1);
    await circuit.checkConstraints(witness2);

    const hash1 = witness1[1];
    const hash2 = witness2[1];

    if (hash1 === hash2) {
      throw new Error('Different nationalities should produce different hashes');
    }
  });

  it('should handle edge case birth years', async function () {
    const inputs = [
      { birthYear: 1900, nationality: 840, salt: 111 },
      { birthYear: 2023, nationality: 826, salt: 222 },
      { birthYear: 2000, nationality: 124, salt: 333 },
    ];

    for (const input of inputs) {
      const witness = await circuit.calculateWitness(input);
      await circuit.checkConstraints(witness);

      const hash = witness[1];
      if (hash === 0n) {
        throw new Error(`Hash should not be zero for birthYear ${input.birthYear}`);
      }
    }
  });

  it('should handle large salt values', async function () {
    const input = {
      birthYear: 1990,
      nationality: 840,
      salt: 999999999999,
    };

    const witness = await circuit.calculateWitness(input);
    await circuit.checkConstraints(witness);
  });
});
