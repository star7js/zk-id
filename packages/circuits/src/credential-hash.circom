pragma circom 2.1.6;

include "../node_modules/circomlib/circuits/poseidon.circom";

/**
 * CredentialHash: Computes a commitment to a credential using Poseidon hash
 *
 * This creates a binding commitment to the credential attributes without revealing them.
 * The hash can be used as a public identifier while keeping attributes private.
 *
 * Inputs:
 *   - birthYear: The user's birth year
 *   - salt: Random salt for privacy (prevents rainbow table attacks)
 *
 * Output:
 *   - out: Poseidon hash of (birthYear, salt)
 */
template CredentialHash() {
    signal input birthYear;
    signal input salt;
    signal output out;

    // Use Poseidon hash with 2 inputs
    component hasher = Poseidon(2);
    hasher.inputs[0] <== birthYear;
    hasher.inputs[1] <== salt;

    out <== hasher.out;
}

component main = CredentialHash();
