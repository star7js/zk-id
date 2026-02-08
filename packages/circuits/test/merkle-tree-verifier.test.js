const path = require("path");
const snarkjs = require("snarkjs");
const wasm_tester = require("circom_tester").wasm;
const { buildPoseidon } = require("circomlibjs");

describe("MerkleTreeVerifier (via AgeVerifyRevocable) Circuit Tests", function () {
  let circuit;
  let poseidon;

  before(async function () {
    circuit = await wasm_tester(
      path.join(__dirname, "../src/age-verify-revocable.circom"),
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

  // Helper function to build a Merkle tree (matches revocation-accumulator.ts logic)
  function buildMerkleTree(leaves, depth) {
    const totalLeaves = 1 << depth;
    const baseLayer = [...leaves];

    // Pad with zeros to fill the tree
    while (baseLayer.length < totalLeaves) {
      baseLayer.push(BigInt(0));
    }

    const layers = [baseLayer];
    for (let level = 0; level < depth; level++) {
      const prev = layers[level];
      const next = [];
      for (let i = 0; i < prev.length; i += 2) {
        const left = prev[i];
        const right = prev[i + 1];
        const hash = poseidon([left, right]);
        next.push(poseidon.F.toString(hash));
      }
      layers.push(next);
    }

    return layers;
  }

  // Helper function to get witness (authentication path) for a leaf
  function getWitness(layers, index, depth) {
    const siblings = [];
    const pathIndices = [];
    let cursor = index;

    for (let level = 0; level < depth; level++) {
      const siblingIndex = cursor ^ 1;
      siblings.push(layers[level][siblingIndex].toString());
      pathIndices.push(cursor % 2);
      cursor = Math.floor(cursor / 2);
    }

    const root = layers[layers.length - 1][0].toString();
    return { root, pathIndices, siblings };
  }

  it("should verify valid age with valid Merkle proof (credential at index 0)", async function () {
    const birthYear = 2000;
    const nationality = 840;
    const salt = 12345n;
    const credentialHash = computeHash(birthYear, nationality, salt);

    // Build tree with this credential at index 0
    const leaves = [BigInt(credentialHash)];
    const depth = 10;
    const layers = buildMerkleTree(leaves, depth);
    const witness = getWitness(layers, 0, depth);

    const input = {
      birthYear: birthYear,
      nationality: nationality,
      salt: salt.toString(),
      pathIndices: witness.pathIndices,
      siblings: witness.siblings,
      currentYear: 2023,
      minAge: 18,
      credentialHash: credentialHash,
      merkleRoot: witness.root,
      nonce: "1",
      requestTimestamp: 1700000000000,
    };

    const witnessCalc = await circuit.calculateWitness(input);
    await circuit.checkConstraints(witnessCalc);
  });

  it("should verify credential at different tree positions", async function () {
    const depth = 10;

    // Create multiple credentials
    const credentials = [
      { birthYear: 2000, nationality: 840, salt: 11111n },
      { birthYear: 1995, nationality: 826, salt: 22222n },
      { birthYear: 1990, nationality: 124, salt: 33333n },
      { birthYear: 1985, nationality: 276, salt: 44444n },
    ];

    const credentialHashes = credentials.map(c =>
      BigInt(computeHash(c.birthYear, c.nationality, c.salt))
    );

    const layers = buildMerkleTree(credentialHashes, depth);

    // Test credential at index 0
    const witness0 = getWitness(layers, 0, depth);
    const input0 = {
      birthYear: credentials[0].birthYear,
      nationality: credentials[0].nationality,
      salt: credentials[0].salt.toString(),
      pathIndices: witness0.pathIndices,
      siblings: witness0.siblings,
      currentYear: 2023,
      minAge: 18,
      credentialHash: credentialHashes[0].toString(),
      merkleRoot: witness0.root,
      nonce: "1",
      requestTimestamp: 1700000000000,
    };
    const witnessCalc0 = await circuit.calculateWitness(input0);
    await circuit.checkConstraints(witnessCalc0);

    // Test credential at index 2
    const witness2 = getWitness(layers, 2, depth);
    const input2 = {
      birthYear: credentials[2].birthYear,
      nationality: credentials[2].nationality,
      salt: credentials[2].salt.toString(),
      pathIndices: witness2.pathIndices,
      siblings: witness2.siblings,
      currentYear: 2023,
      minAge: 18,
      credentialHash: credentialHashes[2].toString(),
      merkleRoot: witness2.root,
      nonce: "2",
      requestTimestamp: 1700000000001,
    };
    const witnessCalc2 = await circuit.calculateWitness(input2);
    await circuit.checkConstraints(witnessCalc2);
  });

  it("should fail when merkleRoot does not match", async function () {
    const birthYear = 2000;
    const nationality = 840;
    const salt = 12345n;
    const credentialHash = computeHash(birthYear, nationality, salt);

    const leaves = [BigInt(credentialHash)];
    const depth = 10;
    const layers = buildMerkleTree(leaves, depth);
    const witness = getWitness(layers, 0, depth);

    // Use wrong root
    const wrongRoot = "123456789012345678901234567890";

    const input = {
      birthYear: birthYear,
      nationality: nationality,
      salt: salt.toString(),
      pathIndices: witness.pathIndices,
      siblings: witness.siblings,
      currentYear: 2023,
      minAge: 18,
      credentialHash: credentialHash,
      merkleRoot: wrongRoot,
      nonce: "1",
      requestTimestamp: 1700000000000,
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

  it("should fail when credential is not in tree", async function () {
    const depth = 10;

    // Build tree with one credential
    const inTreeCred = { birthYear: 2000, nationality: 840, salt: 11111n };
    const inTreeHash = BigInt(computeHash(inTreeCred.birthYear, inTreeCred.nationality, inTreeCred.salt));

    const layers = buildMerkleTree([inTreeHash], depth);
    const witness = getWitness(layers, 0, depth);

    // Try to prove a different credential is in the tree
    const notInTreeCred = { birthYear: 1995, nationality: 826, salt: 99999n };
    const notInTreeHash = computeHash(notInTreeCred.birthYear, notInTreeCred.nationality, notInTreeCred.salt);

    const input = {
      birthYear: notInTreeCred.birthYear,
      nationality: notInTreeCred.nationality,
      salt: notInTreeCred.salt.toString(),
      pathIndices: witness.pathIndices,
      siblings: witness.siblings,
      currentYear: 2023,
      minAge: 18,
      credentialHash: notInTreeHash,
      merkleRoot: witness.root,
      nonce: "1",
      requestTimestamp: 1700000000000,
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

  it("should fail when age < minAge even with valid Merkle proof", async function () {
    const birthYear = 2010; // Too young
    const nationality = 840;
    const salt = 12345n;
    const credentialHash = computeHash(birthYear, nationality, salt);

    const leaves = [BigInt(credentialHash)];
    const depth = 10;
    const layers = buildMerkleTree(leaves, depth);
    const witness = getWitness(layers, 0, depth);

    const input = {
      birthYear: birthYear,
      nationality: nationality,
      salt: salt.toString(),
      pathIndices: witness.pathIndices,
      siblings: witness.siblings,
      currentYear: 2023,
      minAge: 18,
      credentialHash: credentialHash,
      merkleRoot: witness.root,
      nonce: "1",
      requestTimestamp: 1700000000000,
    };

    try {
      await circuit.calculateWitness(input);
      throw new Error("Expected constraint failure but proof succeeded");
    } catch (error) {
      if (error.message.includes("Expected constraint failure")) {
        throw error;
      }
      // Success - age constraint properly failed
    }
  });

  it("should fail when credentialHash doesn't match private inputs", async function () {
    const birthYear = 2000;
    const nationality = 840;
    const salt = 12345n;
    const correctHash = computeHash(birthYear, nationality, salt);

    // Use a different credential hash in the tree
    const wrongCred = { birthYear: 1995, nationality: 826, salt: 99999n };
    const wrongHash = computeHash(wrongCred.birthYear, wrongCred.nationality, wrongCred.salt);

    const leaves = [BigInt(wrongHash)];
    const depth = 10;
    const layers = buildMerkleTree(leaves, depth);
    const witness = getWitness(layers, 0, depth);

    const input = {
      birthYear: birthYear,
      nationality: nationality,
      salt: salt.toString(),
      pathIndices: witness.pathIndices,
      siblings: witness.siblings,
      currentYear: 2023,
      minAge: 18,
      credentialHash: wrongHash, // Merkle proof is for this hash
      merkleRoot: witness.root,
      nonce: "1",
      requestTimestamp: 1700000000000,
    };

    try {
      await circuit.calculateWitness(input);
      throw new Error("Expected constraint failure but proof succeeded");
    } catch (error) {
      if (error.message.includes("Expected constraint failure")) {
        throw error;
      }
      // Success - hash binding constraint properly failed
    }
  });

  it("should fail when pathIndices contains non-binary values", async function () {
    const birthYear = 2000;
    const nationality = 840;
    const salt = 12345n;
    const credentialHash = computeHash(birthYear, nationality, salt);

    const leaves = [BigInt(credentialHash)];
    const depth = 10;
    const layers = buildMerkleTree(leaves, depth);
    const witness = getWitness(layers, 0, depth);

    // Corrupt a pathIndex with a non-binary value
    const corruptedPathIndices = [...witness.pathIndices];
    corruptedPathIndices[0] = 2; // Invalid: should be 0 or 1

    const input = {
      birthYear: birthYear,
      nationality: nationality,
      salt: salt.toString(),
      pathIndices: corruptedPathIndices,
      siblings: witness.siblings,
      currentYear: 2023,
      minAge: 18,
      credentialHash: credentialHash,
      merkleRoot: witness.root,
      nonce: "1",
      requestTimestamp: 1700000000000,
    };

    try {
      await circuit.calculateWitness(input);
      throw new Error("Expected constraint failure but proof succeeded");
    } catch (error) {
      if (error.message.includes("Expected constraint failure")) {
        throw error;
      }
      // Success - binary constraint properly failed
    }
  });
});
