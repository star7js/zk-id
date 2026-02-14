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
 *   - nationality: The user's nationality (ISO 3166-1 numeric code)
 *   - salt: Random salt for privacy (prevents rainbow table attacks)
 *
 * Output:
 *   - out: Poseidon hash of (birthYear, nationality, salt)
 */
template CredentialHash() {
    signal input birthYear;
    signal input nationality;
    signal input salt;
    signal output out;

    // Use Poseidon hash with domain separation (4 inputs: domain tag + 3 attributes)
    // Domain separation tag 0 = DOMAIN_CREDENTIAL (must match poseidon.ts constants)
    component hasher = Poseidon(4);
    hasher.inputs[0] <== 0; // DOMAIN_CREDENTIAL
    hasher.inputs[1] <== birthYear;
    hasher.inputs[2] <== nationality;
    hasher.inputs[3] <== salt;

    out <== hasher.out;
}

component main = CredentialHash();
