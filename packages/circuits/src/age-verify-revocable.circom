pragma circom 2.1.6;

include "../node_modules/circomlib/circuits/comparators.circom";
include "../node_modules/circomlib/circuits/poseidon.circom";
include "./merkle-tree-verifier.circom";

/**
 * AgeVerifyRevocable: Age verification with Merkle inclusion proof (non-revocation)
 *
 * Combines the standard AgeVerify logic with a Merkle tree inclusion proof
 * to verify that the credential has not been revoked (is in the valid set).
 *
 * The issuer maintains a Merkle tree of valid (non-revoked) credential hashes.
 * The prover must demonstrate both:
 *   1. They know the credential preimage (birthYear, nationality, salt)
 *   2. The credential hash is included in the valid-set Merkle tree
 *
 * Private inputs:
 *   - birthYear: The actual birth year
 *   - nationality: Nationality code (not constrained)
 *   - salt: Salt used in credential hash
 *   - pathIndices[10]: Merkle path indices (0 = left, 1 = right)
 *   - siblings[10]: Merkle sibling hashes for authentication path
 *
 * Public inputs:
 *   - currentYear: Current year for age calculation
 *   - minAge: Minimum required age
 *   - credentialHash: Public credential commitment
 *   - merkleRoot: Root of the valid credentials Merkle tree
 *   - nonce: Replay protection nonce
 *   - requestTimestamp: Request timestamp for binding
 *
 * Template parameter:
 *   - depth: Merkle tree depth (default 10, supports up to 1024 credentials)
 */
template AgeVerifyRevocable(depth) {
    // Private inputs
    signal input birthYear;
    signal input nationality;
    signal input salt;
    signal input pathIndices[depth];
    signal input siblings[depth];

    // Public inputs
    signal input currentYear;
    signal input minAge;
    signal input credentialHash;
    signal input merkleRoot;
    signal input nonce;
    signal input requestTimestamp;

    // ===== Age Verification Logic (from age-verify.circom) =====

    // Compute age
    signal age <== currentYear - birthYear;

    // Verify age >= minAge
    component ageCheck = GreaterEqThan(12); // 12 bits allows ages 0-4095
    ageCheck.in[0] <== age;
    ageCheck.in[1] <== minAge;
    ageCheck.out === 1;

    // Sanity check: birth year must be <= current year
    component birthYearCheck = LessEqThan(12); // 12 bits for year (0-4095)
    birthYearCheck.in[0] <== birthYear;
    birthYearCheck.in[1] <== currentYear;
    birthYearCheck.out === 1;

    // Verify credential binding: hash matches public credentialHash
    component hasher = Poseidon(3);
    hasher.inputs[0] <== birthYear;
    hasher.inputs[1] <== nationality;
    hasher.inputs[2] <== salt;
    hasher.out === credentialHash;

    // Bind nonce to the proof
    signal nonceCopy <== nonce;
    nonceCopy === nonce;

    // Bind request timestamp to the proof
    signal requestTimestampCopy <== requestTimestamp;
    requestTimestampCopy === requestTimestamp;

    // ===== Merkle Inclusion Proof (Non-Revocation) =====

    // Verify that credentialHash is included in the Merkle tree
    component merkleVerifier = MerkleTreeVerifier(depth);
    merkleVerifier.leaf <== credentialHash;
    merkleVerifier.root <== merkleRoot;

    for (var i = 0; i < depth; i++) {
        merkleVerifier.pathIndices[i] <== pathIndices[i];
        merkleVerifier.siblings[i] <== siblings[i];
    }
}

component main {public [currentYear, minAge, credentialHash, merkleRoot, nonce, requestTimestamp]} = AgeVerifyRevocable(10);
