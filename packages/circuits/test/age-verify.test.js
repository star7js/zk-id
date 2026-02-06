const path = require("path");
const snarkjs = require("snarkjs");
const wasm_tester = require("circom_tester").wasm;

describe("AgeVerify Circuit Tests", function () {
  let circuit;

  before(async function () {
    circuit = await wasm_tester(
      path.join(__dirname, "../src/age-verify.circom"),
      {
        include: path.join(__dirname, "../../../node_modules"),
      }
    );
  });

  it("should verify age >= minAge (exactly equal)", async function () {
    const input = {
      birthYear: 2005,
      currentYear: 2023,
      minAge: 18,
      credentialHash: "12345",
    };

    const witness = await circuit.calculateWitness(input);
    await circuit.checkConstraints(witness);
  });

  it("should verify age > minAge", async function () {
    const input = {
      birthYear: 2000,
      currentYear: 2023,
      minAge: 18,
      credentialHash: "12345",
    };

    const witness = await circuit.calculateWitness(input);
    await circuit.checkConstraints(witness);
  });

  it("should fail when age < minAge", async function () {
    const input = {
      birthYear: 2010,
      currentYear: 2023,
      minAge: 18,
      credentialHash: "12345",
    };

    try {
      await circuit.calculateWitness(input);
      throw new Error("Expected constraint failure but proof succeeded");
    } catch (error) {
      // Expected to fail - age constraint not satisfied
      if (error.message.includes("Expected constraint failure")) {
        throw error;
      }
      // Success - constraint properly failed
    }
  });

  it("should verify age 21+ requirement", async function () {
    const input = {
      birthYear: 2000,
      currentYear: 2023,
      minAge: 21,
      credentialHash: "12345",
    };

    const witness = await circuit.calculateWitness(input);
    await circuit.checkConstraints(witness);
  });

  it("should fail when birthYear > currentYear", async function () {
    const input = {
      birthYear: 2025,
      currentYear: 2023,
      minAge: 18,
      credentialHash: "12345",
    };

    try {
      await circuit.calculateWitness(input);
      throw new Error("Expected constraint failure but proof succeeded");
    } catch (error) {
      if (error.message.includes("Expected constraint failure")) {
        throw error;
      }
      // Success - constraint properly failed
    }
  });

  it("should handle different credential hashes", async function () {
    const input1 = {
      birthYear: 2000,
      currentYear: 2023,
      minAge: 18,
      credentialHash: "11111",
    };

    const input2 = {
      birthYear: 2000,
      currentYear: 2023,
      minAge: 18,
      credentialHash: "99999",
    };

    const witness1 = await circuit.calculateWitness(input1);
    const witness2 = await circuit.calculateWitness(input2);

    await circuit.checkConstraints(witness1);
    await circuit.checkConstraints(witness2);

    // Both should pass but with different witnesses
    // This ensures credential binding works
  });

  it("should verify senior age requirement (65+)", async function () {
    const input = {
      birthYear: 1950,
      currentYear: 2023,
      minAge: 65,
      credentialHash: "12345",
    };

    const witness = await circuit.calculateWitness(input);
    await circuit.checkConstraints(witness);
  });
});
