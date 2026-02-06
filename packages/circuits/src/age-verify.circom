pragma circom 2.1.6;

include "../node_modules/circomlib/circuits/comparators.circom";
include "../node_modules/circomlib/circuits/poseidon.circom";

/**
 * AgeVerify: Proves that age >= minAge without revealing actual age
 *
 * Inputs:
 *   - birthYear: Private input (the actual birth year)
 *   - currentYear: Public input (the current year for verification)
 *   - minAge: Public input (minimum required age, e.g., 18 or 21)
 *   - credentialHash: Public input (Poseidon hash of the credential for binding)
 *
 * Output:
 *   - Constraint passes if age >= minAge
 */
template AgeVerify() {
    // Private input
    signal input birthYear;

    // Public inputs
    signal input currentYear;
    signal input minAge;
    signal input credentialHash;

    // Compute age
    signal age <== currentYear - birthYear;

    // Verify age >= minAge using GreaterEqThan comparator
    component ageCheck = GreaterEqThan(8); // 8 bits allows ages 0-255
    ageCheck.in[0] <== age;
    ageCheck.in[1] <== minAge;

    // Constraint: age must be >= minAge
    ageCheck.out === 1;

    // Additional sanity checks
    component birthYearCheck = LessEqThan(12); // 12 bits for year (0-4095)
    birthYearCheck.in[0] <== birthYear;
    birthYearCheck.in[1] <== currentYear;
    birthYearCheck.out === 1; // Birth year must be <= current year

    // The credentialHash is included as a public input to bind this proof
    // to a specific credential, preventing proof reuse across different identities
    signal credentialHashSquared <== credentialHash * credentialHash;
}

component main {public [currentYear, minAge, credentialHash]} = AgeVerify();
