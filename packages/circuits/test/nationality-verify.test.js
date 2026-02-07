const path = require("path");
const snarkjs = require("snarkjs");
const wasm_tester = require("circom_tester").wasm;
const { buildPoseidon } = require("circomlibjs");

describe("NationalityVerify Circuit Tests", function () {
  let circuit;
  let poseidon;

  before(async function () {
    circuit = await wasm_tester(
      path.join(__dirname, "../src/nationality-verify.circom"),
      {
        include: path.join(__dirname, "../../../node_modules"),
      }
    );
    poseidon = await buildPoseidon();
  });

  // Helper function to compute credential hash
  function computeHash(birthYear, nationality, salt) {
    const hash = poseidon([birthYear, nationality, salt]);
    return poseidon.F.toString(hash);
  }

  it("should verify matching nationality", async function () {
    const birthYear = 1990;
    const nationality = 840; // USA
    const salt = 12345n;
    const input = {
      birthYear: birthYear,
      nationality: nationality,
      salt: salt.toString(),
      targetNationality: 840,
      credentialHash: computeHash(birthYear, nationality, salt),
    };

    const witness = await circuit.calculateWitness(input);
    await circuit.checkConstraints(witness);
  });

  it("should fail when nationality does not match target", async function () {
    const birthYear = 1990;
    const nationality = 840; // USA
    const salt = 12345n;
    const input = {
      birthYear: birthYear,
      nationality: nationality,
      salt: salt.toString(),
      targetNationality: 826, // UK (different from actual)
      credentialHash: computeHash(birthYear, nationality, salt),
    };

    try {
      await circuit.calculateWitness(input);
      throw new Error("Expected constraint failure but proof succeeded");
    } catch (error) {
      // Expected to fail - nationality constraint not satisfied
      if (error.message.includes("Expected constraint failure")) {
        throw error;
      }
      // Success - constraint properly failed
    }
  });

  it("should fail when credentialHash does not match", async function () {
    const birthYear = 1990;
    const nationality = 840;
    const salt = 12345n;
    const wrongNationality = 826;
    const input = {
      birthYear: birthYear,
      nationality: nationality,
      salt: salt.toString(),
      targetNationality: 840,
      // Using hash with wrong nationality - this should fail
      credentialHash: computeHash(birthYear, wrongNationality, salt),
    };

    try {
      await circuit.calculateWitness(input);
      throw new Error("Expected constraint failure but proof succeeded");
    } catch (error) {
      if (error.message.includes("Expected constraint failure")) {
        throw error;
      }
      // Success - constraint properly failed due to hash mismatch
    }
  });

  it("should verify various nationality codes", async function () {
    const birthYear = 1990;
    const salt = 12345n;
    const nationalities = [
      840, // USA
      826, // UK
      124, // Canada
      276, // Germany
      392, // Japan
    ];

    for (const nationality of nationalities) {
      const input = {
        birthYear: birthYear,
        nationality: nationality,
        salt: salt.toString(),
        targetNationality: nationality,
        credentialHash: computeHash(birthYear, nationality, salt),
      };

      const witness = await circuit.calculateWitness(input);
      await circuit.checkConstraints(witness);
    }
  });

  it("should verify nationality regardless of birth year value", async function () {
    const nationality = 840;
    const salt = 12345n;
    const birthYear1 = 1990;
    const birthYear2 = 2000;

    const input1 = {
      birthYear: birthYear1,
      nationality: nationality,
      salt: salt.toString(),
      targetNationality: nationality,
      credentialHash: computeHash(birthYear1, nationality, salt),
    };

    const input2 = {
      birthYear: birthYear2,
      nationality: nationality,
      salt: salt.toString(),
      targetNationality: nationality,
      credentialHash: computeHash(birthYear2, nationality, salt),
    };

    const witness1 = await circuit.calculateWitness(input1);
    const witness2 = await circuit.calculateWitness(input2);

    await circuit.checkConstraints(witness1);
    await circuit.checkConstraints(witness2);

    // Both should pass - birth year is not constrained in nationality verification
  });

  it("should handle different salts", async function () {
    const birthYear = 1990;
    const nationality = 840;
    const salt1 = 11111n;
    const salt2 = 99999n;

    const input1 = {
      birthYear: birthYear,
      nationality: nationality,
      salt: salt1.toString(),
      targetNationality: nationality,
      credentialHash: computeHash(birthYear, nationality, salt1),
    };

    const input2 = {
      birthYear: birthYear,
      nationality: nationality,
      salt: salt2.toString(),
      targetNationality: nationality,
      credentialHash: computeHash(birthYear, nationality, salt2),
    };

    const witness1 = await circuit.calculateWitness(input1);
    const witness2 = await circuit.calculateWitness(input2);

    await circuit.checkConstraints(witness1);
    await circuit.checkConstraints(witness2);

    // Both should pass with different salts
  });

  it("should fail when salt does not match the credentialHash", async function () {
    const birthYear = 1990;
    const nationality = 840;
    const correctSalt = 12345n;
    const wrongSalt = 99999n;

    const input = {
      birthYear: birthYear,
      nationality: nationality,
      salt: wrongSalt.toString(),
      targetNationality: nationality,
      // Using hash with correct salt, but providing wrong salt as input
      credentialHash: computeHash(birthYear, nationality, correctSalt),
    };

    try {
      await circuit.calculateWitness(input);
      throw new Error("Expected constraint failure but proof succeeded");
    } catch (error) {
      if (error.message.includes("Expected constraint failure")) {
        throw error;
      }
      // Success - constraint properly failed due to salt mismatch
    }
  });
});
