pragma circom 2.1.6;

include "../node_modules/circomlib/circuits/comparators.circom";
include "../node_modules/circomlib/circuits/poseidon.circom";

/**
 * NationalityVerify: Proves nationality matches target without revealing birth year
 *
 * Inputs:
 *   - birthYear: Private input (not constrained, enables selective disclosure)
 *   - nationality: Private input (the actual nationality code)
 *   - salt: Private input (salt used in credential hash)
 *   - targetNationality: Public input (the nationality to verify against)
 *   - credentialHash: Public input (Poseidon hash of the credential for binding)
 *   - nonce: Public input (replay protection, bound to proof)
 *   - requestTimestamp: Public input (request time, bound to proof)
 *
 * Output:
 *   - Constraint passes if nationality === targetNationality and credential hash is valid
 */
template NationalityVerify() {
    // Private inputs
    signal input birthYear;
    signal input nationality;
    signal input salt;

    // Public inputs
    signal input targetNationality;
    signal input credentialHash;
    signal input nonce;
    signal input requestTimestamp;

    // Verify nationality matches target
    component nationalityCheck = IsEqual();
    nationalityCheck.in[0] <== nationality;
    nationalityCheck.in[1] <== targetNationality;

    // Constraint: nationality must equal targetNationality
    nationalityCheck.out === 1;

    // Verify credential binding: compute hash from private inputs
    // and verify it matches the public credentialHash
    component hasher = Poseidon(3);
    hasher.inputs[0] <== birthYear;
    hasher.inputs[1] <== nationality;
    hasher.inputs[2] <== salt;
    hasher.out === credentialHash;

    // Bind nonce to the proof (no additional constraints)
    signal nonceCopy <== nonce;
    nonceCopy === nonce;

    // Bind request timestamp to the proof (no additional constraints)
    signal requestTimestampCopy <== requestTimestamp;
    requestTimestampCopy === requestTimestamp;
}

component main {public [targetNationality, credentialHash, nonce, requestTimestamp]} = NationalityVerify();
