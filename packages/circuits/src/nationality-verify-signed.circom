pragma circom 2.1.6;

include "../node_modules/circomlib/circuits/comparators.circom";
include "../node_modules/circomlib/circuits/poseidon.circom";
include "../node_modules/circomlib/circuits/eddsa.circom";
include "../node_modules/circomlib/circuits/bitify.circom";

/**
 * NationalityVerifySigned: Proves nationality matches target and validates issuer EdDSA signature
 *
 * Inputs:
 *   - birthYear: Private input
 *   - nationality: Private input
 *   - salt: Private input
 *   - targetNationality: Public input
 *   - credentialHash: Public input
 *   - nonce: Public input
 *   - requestTimestamp: Public input
 *   - issuerPublicKey: Public input (EdDSA pubkey bits, packed point)
 *   - signatureR8: Private input (signature R8 bits)
 *   - signatureS: Private input (signature S bits)
 */

template NationalityVerifySigned() {
    // Private inputs
    signal input birthYear;
    signal input nationality;
    signal input salt;
    signal input signatureR8[256];
    signal input signatureS[256];

    // Public inputs
    signal input targetNationality;
    signal input credentialHash;
    signal input nonce;
    signal input requestTimestamp;
    signal input issuerPublicKey[256];

    component nationalityCheck = IsEqual();
    nationalityCheck.in[0] <== nationality;
    nationalityCheck.in[1] <== targetNationality;
    nationalityCheck.out === 1;

    component hasher = Poseidon(3);
    hasher.inputs[0] <== birthYear;
    hasher.inputs[1] <== nationality;
    hasher.inputs[2] <== salt;
    hasher.out === credentialHash;

    signal nonceCopy <== nonce;
    nonceCopy === nonce;
    signal requestTimestampCopy <== requestTimestamp;
    requestTimestampCopy === requestTimestamp;

    component hashBits = Num2Bits(256);
    hashBits.in <== credentialHash;

    component eddsa = EdDSAVerifier(256);
    for (var i = 0; i < 256; i++) {
        eddsa.msg[i] <== hashBits.out[i];
        eddsa.A[i] <== issuerPublicKey[i];
        eddsa.R8[i] <== signatureR8[i];
        eddsa.S[i] <== signatureS[i];
    }
}

component main {public [targetNationality, credentialHash, nonce, requestTimestamp, issuerPublicKey]} = NationalityVerifySigned();
