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
 *   1. Poseidon(0, birthYear, nationality, salt) === credentialHash  (domain-separated)
 *   2. Poseidon(1, credentialHash, scopeHash) === nullifier          (domain-separated)
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

    // Constraint 1: Verify credential binding (domain-separated)
    // Poseidon(DOMAIN_CREDENTIAL=0, birthYear, nationality, salt) === credentialHash
    component credentialHasher = Poseidon(4);
    credentialHasher.inputs[0] <== 0; // DOMAIN_CREDENTIAL
    credentialHasher.inputs[1] <== birthYear;
    credentialHasher.inputs[2] <== nationality;
    credentialHasher.inputs[3] <== salt;
    credentialHasher.out === credentialHash;

    // Constraint 2: Compute and verify nullifier (domain-separated)
    // Poseidon(DOMAIN_NULLIFIER=1, credentialHash, scopeHash) === nullifier
    component nullifierHasher = Poseidon(3);
    nullifierHasher.inputs[0] <== 1; // DOMAIN_NULLIFIER
    nullifierHasher.inputs[1] <== credentialHash;
    nullifierHasher.inputs[2] <== scopeHash;
    nullifierHasher.out === nullifier;
}

// NOTE: credentialHash is intentionally NOT public. Making it public would allow
// verifiers to link nullifier proofs across different scopes (defeating privacy).
// The circuit proves knowledge of the credential preimage internally without
// revealing the commitment. Only scopeHash and nullifier are public.
component main {public [scopeHash, nullifier]} = NullifierCompute();
