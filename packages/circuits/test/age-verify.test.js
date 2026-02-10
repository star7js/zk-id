const path = require('path');
const _snarkjs = require('snarkjs');
const wasm_tester = require('circom_tester').wasm;
const { buildPoseidon } = require('circomlibjs');

describe('AgeVerify Circuit Tests', function () {
  let circuit;
  let poseidon;

  before(async function () {
    circuit = await wasm_tester(path.join(__dirname, '../src/age-verify.circom'), {
      include: path.join(__dirname, '../../../node_modules'),
    });
    poseidon = await buildPoseidon();
  });

  // Helper function to compute credential hash
  function computeHash(birthYear, nationality, salt) {
    const hash = poseidon([birthYear, nationality, salt]);
    return poseidon.F.toString(hash);
  }

  it('should verify age >= minAge (exactly equal)', async function () {
    const birthYear = 2005;
    const nationality = 840;
    const salt = 12345n;
    const input = {
      birthYear: birthYear,
      nationality: nationality,
      salt: salt.toString(),
      currentYear: 2023,
      minAge: 18,
      credentialHash: computeHash(birthYear, nationality, salt),
      nonce: '1',
      requestTimestamp: 1700000000000,
    };

    const witness = await circuit.calculateWitness(input);
    await circuit.checkConstraints(witness);
  });

  it('should verify age > minAge', async function () {
    const birthYear = 2000;
    const nationality = 840;
    const salt = 12345n;
    const input = {
      birthYear: birthYear,
      nationality: nationality,
      salt: salt.toString(),
      currentYear: 2023,
      minAge: 18,
      credentialHash: computeHash(birthYear, nationality, salt),
      nonce: '1',
      requestTimestamp: 1700000000000,
    };

    const witness = await circuit.calculateWitness(input);
    await circuit.checkConstraints(witness);
  });

  it('should fail when age < minAge', async function () {
    const birthYear = 2010;
    const nationality = 840;
    const salt = 12345n;
    const input = {
      birthYear: birthYear,
      nationality: nationality,
      salt: salt.toString(),
      currentYear: 2023,
      minAge: 18,
      credentialHash: computeHash(birthYear, nationality, salt),
      nonce: '1',
      requestTimestamp: 1700000000000,
    };

    try {
      await circuit.calculateWitness(input);
      throw new Error('Expected constraint failure but proof succeeded');
    } catch (error) {
      // Expected to fail - age constraint not satisfied
      if (error.message.includes('Expected constraint failure')) {
        throw error;
      }
      // Success - constraint properly failed
    }
  });

  it('should verify age 21+ requirement', async function () {
    const birthYear = 2000;
    const nationality = 840;
    const salt = 12345n;
    const input = {
      birthYear: birthYear,
      nationality: nationality,
      salt: salt.toString(),
      currentYear: 2023,
      minAge: 21,
      credentialHash: computeHash(birthYear, nationality, salt),
      nonce: '1',
      requestTimestamp: 1700000000000,
    };

    const witness = await circuit.calculateWitness(input);
    await circuit.checkConstraints(witness);
  });

  it('should fail when birthYear > currentYear', async function () {
    const birthYear = 2025;
    const nationality = 840;
    const salt = 12345n;
    const input = {
      birthYear: birthYear,
      nationality: nationality,
      salt: salt.toString(),
      currentYear: 2023,
      minAge: 18,
      credentialHash: computeHash(birthYear, nationality, salt),
      nonce: '1',
      requestTimestamp: 1700000000000,
    };

    try {
      await circuit.calculateWitness(input);
      throw new Error('Expected constraint failure but proof succeeded');
    } catch (error) {
      if (error.message.includes('Expected constraint failure')) {
        throw error;
      }
      // Success - constraint properly failed
    }
  });

  it('should handle different credential hashes', async function () {
    const birthYear = 2000;
    const nationality = 840;
    const salt1 = 11111n;
    const salt2 = 99999n;

    const input1 = {
      birthYear: birthYear,
      nationality: nationality,
      salt: salt1.toString(),
      currentYear: 2023,
      minAge: 18,
      credentialHash: computeHash(birthYear, nationality, salt1),
      nonce: '1',
      requestTimestamp: 1700000000000,
    };

    const input2 = {
      birthYear: birthYear,
      nationality: nationality,
      salt: salt2.toString(),
      currentYear: 2023,
      minAge: 18,
      credentialHash: computeHash(birthYear, nationality, salt2),
      nonce: '1',
      requestTimestamp: 1700000000000,
    };

    const witness1 = await circuit.calculateWitness(input1);
    const witness2 = await circuit.calculateWitness(input2);

    await circuit.checkConstraints(witness1);
    await circuit.checkConstraints(witness2);

    // Both should pass but with different witnesses
    // This ensures credential binding works
  });

  it('should verify senior age requirement (65+)', async function () {
    const birthYear = 1950;
    const nationality = 840;
    const salt = 12345n;
    const input = {
      birthYear: birthYear,
      nationality: nationality,
      salt: salt.toString(),
      currentYear: 2023,
      minAge: 65,
      credentialHash: computeHash(birthYear, nationality, salt),
      nonce: '1',
      requestTimestamp: 1700000000000,
    };

    const witness = await circuit.calculateWitness(input);
    await circuit.checkConstraints(witness);
  });

  it('should verify age regardless of nationality value', async function () {
    const birthYear = 2000;
    const nationality1 = 840; // USA
    const nationality2 = 826; // UK
    const salt = 12345n;

    const input1 = {
      birthYear: birthYear,
      nationality: nationality1,
      salt: salt.toString(),
      currentYear: 2023,
      minAge: 18,
      credentialHash: computeHash(birthYear, nationality1, salt),
      nonce: '1',
      requestTimestamp: 1700000000000,
    };

    const input2 = {
      birthYear: birthYear,
      nationality: nationality2,
      salt: salt.toString(),
      currentYear: 2023,
      minAge: 18,
      credentialHash: computeHash(birthYear, nationality2, salt),
      nonce: '1',
      requestTimestamp: 1700000000000,
    };

    const witness1 = await circuit.calculateWitness(input1);
    const witness2 = await circuit.calculateWitness(input2);

    await circuit.checkConstraints(witness1);
    await circuit.checkConstraints(witness2);

    // Both should pass - nationality is not constrained in age verification
  });

  // Security test: verify that mismatched credentialHash/birthYear/salt causes failure
  it('should fail when credentialHash does not match birthYear and salt', async function () {
    const birthYear = 2000;
    const nationality = 840;
    const salt = 12345n;
    const wrongBirthYear = 1995;

    const input = {
      birthYear: birthYear,
      nationality: nationality,
      salt: salt.toString(),
      currentYear: 2023,
      minAge: 18,
      // Using hash of wrong birth year - this should fail
      credentialHash: computeHash(wrongBirthYear, nationality, salt),
      nonce: '1',
      requestTimestamp: 1700000000000,
    };

    try {
      await circuit.calculateWitness(input);
      throw new Error('Expected constraint failure but proof succeeded');
    } catch (error) {
      if (error.message.includes('Expected constraint failure')) {
        throw error;
      }
      // Success - constraint properly failed due to hash mismatch
    }
  });

  // Security test: verify that wrong salt with correct birthYear also fails
  it('should fail when salt does not match the credentialHash', async function () {
    const birthYear = 2000;
    const nationality = 840;
    const correctSalt = 12345n;
    const wrongSalt = 99999n;

    const input = {
      birthYear: birthYear,
      nationality: nationality,
      salt: wrongSalt.toString(),
      currentYear: 2023,
      minAge: 18,
      // Using hash with correct salt, but providing wrong salt as input
      credentialHash: computeHash(birthYear, nationality, correctSalt),
      nonce: '1',
      requestTimestamp: 1700000000000,
    };

    try {
      await circuit.calculateWitness(input);
      throw new Error('Expected constraint failure but proof succeeded');
    } catch (error) {
      if (error.message.includes('Expected constraint failure')) {
        throw error;
      }
      // Success - constraint properly failed due to salt mismatch
    }
  });
});
