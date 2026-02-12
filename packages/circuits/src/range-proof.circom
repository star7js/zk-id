pragma circom 2.0.0;

include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/poseidon.circom";

/**
 * Generic Range Proof Circuit
 *
 * Proves that a value lies within a specified range [minValue, maxValue]
 * without revealing the actual value.
 *
 * Public Inputs:
 *   - minValue: Lower bound of the range (inclusive)
 *   - maxValue: Upper bound of the range (inclusive)
 *   - commitment: Poseidon(value, salt) - binds the value to a commitment
 *
 * Private Inputs:
 *   - value: The actual value to prove (kept private)
 *   - salt: Random salt for commitment uniqueness
 *
 * The circuit verifies:
 *   1. The commitment matches Poseidon(value, salt)
 *   2. value >= minValue
 *   3. value <= maxValue
 */

template RangeProof(WIDTH) {
    // Private inputs
    signal input value;
    signal input salt;

    // Public inputs
    signal input minValue;
    signal input maxValue;
    signal input commitment;

    // Output (always 1 if constraints pass)
    signal output valid;

    // 1. Verify commitment: commitment === Poseidon(value, salt)
    component hasher = Poseidon(2);
    hasher.inputs[0] <== value;
    hasher.inputs[1] <== salt;
    commitment === hasher.out;

    // 2. Range check: value >= minValue
    component geq = GreaterEqThan(WIDTH);
    geq.in[0] <== value;
    geq.in[1] <== minValue;
    geq.out === 1;

    // 3. Range check: value <= maxValue
    component leq = LessEqThan(WIDTH);
    leq.in[0] <== value;
    leq.in[1] <== maxValue;
    leq.out === 1;

    // All constraints passed
    valid <== 1;
}

// Main component: 32-bit width allows values up to ~4.2 billion
// Public signals: [minValue, maxValue, commitment]
component main {public [minValue, maxValue, commitment]} = RangeProof(32);
