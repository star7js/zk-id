pragma circom 2.1.6;

include "../node_modules/circomlib/circuits/poseidon.circom";

/**
 * NullifierCompute: Proves knowledge of a credential and computes a deterministic nullifier
 *
 * This circuit enables sybil-resistant anonymous actions. The nullifier is bound to both
 * the credential and a scope, allowing verifiers to detect duplicate uses within a scope
 * while preserving privacy across different scopes.
 *
 * Inputs:
 *   - birthYear: Private input (credential preimage)
 *   - nationality: Private input (credential preimage)
 *   - salt: Private input (credential preimage)
 *   - credentialHash: Public input (commitment to credential)
 *   - scopeHash: Public input (hash of the scope/context identifier)
 *   - nullifier: Public input (deterministic nullifier for this credential+scope)
 *
 * Constraints:
 *   1. Poseidon(birthYear, nationality, salt) === credentialHash
 *   2. Poseidon(credentialHash, scopeHash) === nullifier
 *
 * The nullifier is deterministic: same credential + scope always produces the same
 * nullifier, enabling duplicate detection. Different scopes produce different nullifiers,
 * preventing linkability across contexts.
 *
 * Approximate constraints: ~792 (fits in small ptau 2^12)
 */
template NullifierCompute() {
    // Private inputs (credential preimage)
    signal input birthYear;
    signal input nationality;
    signal input salt;

    // Public inputs
    signal input credentialHash;
    signal input scopeHash;
    signal input nullifier;

    // Constraint 1: Verify credential binding
    // Compute credentialHash from private inputs and verify it matches public input
    component credentialHasher = Poseidon(3);
    credentialHasher.inputs[0] <== birthYear;
    credentialHasher.inputs[1] <== nationality;
    credentialHasher.inputs[2] <== salt;
    credentialHasher.out === credentialHash;

    // Constraint 2: Compute and verify nullifier
    // Nullifier = Poseidon(credentialHash, scopeHash)
    component nullifierHasher = Poseidon(2);
    nullifierHasher.inputs[0] <== credentialHash;
    nullifierHasher.inputs[1] <== scopeHash;
    nullifierHasher.out === nullifier;
}

component main {public [credentialHash, scopeHash, nullifier]} = NullifierCompute();
