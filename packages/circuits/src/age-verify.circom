pragma circom 2.1.6;

include "../node_modules/circomlib/circuits/comparators.circom";
include "../node_modules/circomlib/circuits/poseidon.circom";

/**
 * AgeVerify: Proves that age >= minAge without revealing actual age
 *
 * Inputs:
 *   - birthYear: Private input (the actual birth year)
 *   - nationality: Private input (not constrained, enables selective disclosure)
 *   - salt: Private input (salt used in credential hash)
 *   - currentYear: Public input (the current year for verification)
 *   - minAge: Public input (minimum required age, e.g., 18 or 21)
 *   - credentialHash: Public input (Poseidon hash of the credential for binding)
 *   - nonce: Public input (replay protection, bound to proof)
 *   - requestTimestamp: Public input (request time, bound to proof)
 *
 * Output:
 *   - Constraint passes if age >= minAge and credential hash is valid
 */
template AgeVerify() {
    // Private inputs
    signal input birthYear;
    signal input nationality;
    signal input salt;

    // Public inputs
    signal input currentYear;
    signal input minAge;
    signal input credentialHash;
    signal input nonce;
    signal input requestTimestamp;

    // Compute age
    signal age <== currentYear - birthYear;

    // Verify age >= minAge using GreaterEqThan comparator
    component ageCheck = GreaterEqThan(12); // 12 bits allows ages 0-4095
    ageCheck.in[0] <== age;
    ageCheck.in[1] <== minAge;

    // Constraint: age must be >= minAge
    ageCheck.out === 1;

    // Additional sanity checks
    component birthYearCheck = LessEqThan(12); // 12 bits for year (0-4095)
    birthYearCheck.in[0] <== birthYear;
    birthYearCheck.in[1] <== currentYear;
    birthYearCheck.out === 1; // Birth year must be <= current year

    // Lower bound check: prevent field wrapping (birthYear must be >= 1900)
    component birthYearLowerBound = GreaterEqThan(12);
    birthYearLowerBound.in[0] <== birthYear;
    birthYearLowerBound.in[1] <== 1900;
    birthYearLowerBound.out === 1; // Birth year must be >= 1900

    // Verify credential binding: compute hash from private inputs
    // and verify it matches the public credentialHash
    component hasher = Poseidon(3);
    hasher.inputs[0] <== birthYear;
    hasher.inputs[1] <== nationality;
    hasher.inputs[2] <== salt;
    hasher.out === credentialHash;

    // Bind nonce to the proof
    // NOTE: Nonce is intentionally NOT range-constrained in the circuit.
    // It serves as a replay protection mechanism validated server-side.
    // The circuit only ensures the nonce is bound to the proof as a public signal.
    signal nonceCopy <== nonce;
    nonceCopy === nonce;

    // Bind request timestamp to the proof
    // NOTE: Timestamp is intentionally NOT range-constrained in the circuit.
    // It's validated server-side for freshness (within maxRequestAgeMs window).
    // The circuit only ensures the timestamp is bound to the proof as a public signal.
    signal requestTimestampCopy <== requestTimestamp;
    requestTimestampCopy === requestTimestamp;
}

component main {public [currentYear, minAge, credentialHash, nonce, requestTimestamp]} = AgeVerify();
