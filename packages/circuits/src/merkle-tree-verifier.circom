pragma circom 2.1.6;

include "../node_modules/circomlib/circuits/poseidon.circom";
include "../node_modules/circomlib/circuits/switcher.circom";
include "../node_modules/circomlib/circuits/comparators.circom";

/**
 * MerkleTreeVerifier: Verifies Merkle inclusion proof using Poseidon hash
 *
 * Reusable template that verifies a leaf is included in a Merkle tree
 * by recomputing the root from the leaf and authentication path.
 *
 * Convention matches revocation-accumulator.ts:
 *   - pathIndices[i] = 0 means current node is LEFT child
 *   - pathIndices[i] = 1 means current node is RIGHT child
 *
 * Template parameter:
 *   - depth: Height of the Merkle tree (number of levels above leaves)
 *
 * Inputs:
 *   - leaf: The leaf value to verify
 *   - pathIndices[depth]: Binary array indicating left (0) or right (1) at each level
 *   - siblings[depth]: Sibling hashes along the authentication path
 *   - root: Expected Merkle root
 */
template MerkleTreeVerifier(depth) {
    signal input leaf;
    signal input pathIndices[depth];
    signal input siblings[depth];
    signal input root;

    // Track the computed hash as we traverse up the tree
    signal computedHash[depth + 1];
    computedHash[0] <== leaf;

    // For each level, verify pathIndex is binary, order nodes, and hash
    component isZero[depth];
    component switchers[depth];
    component hashers[depth];

    for (var i = 0; i < depth; i++) {
        // Ensure pathIndices[i] is binary (0 or 1)
        isZero[i] = IsZero();
        isZero[i].in <== pathIndices[i];

        // pathIndices[i] * (1 - pathIndices[i]) must equal 0
        // This is true only when pathIndices[i] is 0 or 1
        pathIndices[i] * (1 - pathIndices[i]) === 0;

        // Use Switcher to order left/right based on pathIndex
        // When pathIndices[i] = 0 (left child):  L = computedHash[i], R = siblings[i]
        // When pathIndices[i] = 1 (right child): L = siblings[i], R = computedHash[i]
        switchers[i] = Switcher();
        switchers[i].sel <== pathIndices[i];
        switchers[i].L <== computedHash[i];
        switchers[i].R <== siblings[i];

        // Hash the pair using domain-separated Poseidon(3)
        // Domain tag 2 = DOMAIN_MERKLE (must match poseidon.ts constants)
        hashers[i] = Poseidon(3);
        hashers[i].inputs[0] <== 2; // DOMAIN_MERKLE
        hashers[i].inputs[1] <== switchers[i].outL;
        hashers[i].inputs[2] <== switchers[i].outR;

        computedHash[i + 1] <== hashers[i].out;
    }

    // Final constraint: computed root must match expected root
    computedHash[depth] === root;
}
