pragma circom 2.0.0;

include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/poseidon.circom";
include "./credential-hash.circom";

/**
 * Generic Predicate Proof Circuit
 *
 * Proves that a credential field satisfies a predicate without revealing the field value.
 * Supports: equality (==), inequality (!=), greater than (>), less than (<), and range checks.
 *
 * Public inputs:
 * - credentialCommitment: Poseidon hash of credential (birthYear, nationality, nonce)
 * - predicateType: 0=EQ, 1=NEQ, 2=GT, 3=LT, 4=GTE, 5=LTE, 6=RANGE
 * - targetValue: Value to compare against (or range min for RANGE)
 * - rangeMax: Maximum value for RANGE predicate (unused for other types)
 * - fieldSelector: 0=birthYear, 1=nationality (extensible)
 * - nonce: Unique nonce for this proof
 * - timestamp: Unix timestamp when proof was generated
 *
 * Private inputs:
 * - birthYear: Birth year (1900-2100)
 * - nationality: Nationality code (ISO 3166-1 numeric)
 * - credentialNonce: Nonce used in credential commitment
 */
template GenericPredicate() {
    // Public inputs
    signal input credentialCommitment;
    signal input predicateType; // 0=EQ, 1=NEQ, 2=GT, 3=LT, 4=GTE, 5=LTE, 6=RANGE
    signal input targetValue;
    signal input rangeMax; // Only used for RANGE predicate
    signal input fieldSelector; // 0=birthYear, 1=nationality
    signal input nonce;
    signal input timestamp;

    // Private inputs
    signal input birthYear;
    signal input nationality;
    signal input credentialNonce;

    // Output: 1 if predicate is satisfied, 0 otherwise
    signal output satisfied;

    // Validate credential commitment
    component credHash = CredentialHash();
    credHash.birthYear <== birthYear;
    credHash.nationality <== nationality;
    credHash.nonce <== credentialNonce;
    credentialCommitment === credHash.commitment;

    // Range checks on private inputs
    component birthYearRange = LessEqThan(12); // 2^12 = 4096 > 2100
    birthYearRange.in[0] <== birthYear;
    birthYearRange.in[1] <== 2100;
    birthYearRange.out === 1;

    component birthYearMin = GreaterEqThan(12);
    birthYearMin.in[0] <== birthYear;
    birthYearMin.in[1] <== 1900;
    birthYearMin.out === 1;

    component nationalityRange = LessEqThan(10); // 2^10 = 1024 > 999
    nationalityRange.in[0] <== nationality;
    nationalityRange.in[1] <== 999;
    nationalityRange.out === 1;

    // Select field based on fieldSelector
    signal selectedField;
    component fieldMux = Mux1();
    fieldMux.c[0] <== birthYear;
    fieldMux.c[1] <== nationality;
    fieldMux.s <== fieldSelector;
    selectedField <== fieldMux.out;

    // Predicate evaluation
    // EQ: selectedField == targetValue
    component eq = IsEqual();
    eq.in[0] <== selectedField;
    eq.in[1] <== targetValue;

    // NEQ: selectedField != targetValue
    signal neq <== 1 - eq.out;

    // GT: selectedField > targetValue
    component gt = GreaterThan(32);
    gt.in[0] <== selectedField;
    gt.in[1] <== targetValue;

    // LT: selectedField < targetValue
    component lt = LessThan(32);
    lt.in[0] <== selectedField;
    lt.in[1] <== targetValue;

    // GTE: selectedField >= targetValue
    component gte = GreaterEqThan(32);
    gte.in[0] <== selectedField;
    gte.in[1] <== targetValue;

    // LTE: selectedField <= targetValue
    component lte = LessEqThan(32);
    lte.in[0] <== selectedField;
    lte.in[1] <== targetValue;

    // RANGE: targetValue <= selectedField <= rangeMax
    component rangeMin = GreaterEqThan(32);
    rangeMin.in[0] <== selectedField;
    rangeMin.in[1] <== targetValue;

    component rangeMaxCheck = LessEqThan(32);
    rangeMaxCheck.in[0] <== selectedField;
    rangeMaxCheck.in[1] <== rangeMax;

    signal rangeCheck <== rangeMin.out * rangeMaxCheck.out;

    // Select result based on predicateType
    // Using a series of multiplexers to select the correct result
    signal predicateResults[7];
    predicateResults[0] <== eq.out;      // EQ
    predicateResults[1] <== neq;          // NEQ
    predicateResults[2] <== gt.out;       // GT
    predicateResults[3] <== lt.out;       // LT
    predicateResults[4] <== gte.out;      // GTE
    predicateResults[5] <== lte.out;      // LTE
    predicateResults[6] <== rangeCheck;   // RANGE

    // Multi-way multiplexer for predicate type selection
    component typeMux0 = Mux1();
    typeMux0.c[0] <== predicateResults[0];
    typeMux0.c[1] <== predicateResults[1];
    typeMux0.s <== predicateType; // Will be 0 or 1 for first two types

    component typeMux1 = Mux1();
    typeMux1.c[0] <== predicateResults[2];
    typeMux1.c[1] <== predicateResults[3];
    typeMux1.s <== predicateType - 2; // Adjusted selector

    component typeMux2 = Mux1();
    typeMux2.c[0] <== predicateResults[4];
    typeMux2.c[1] <== predicateResults[5];
    typeMux2.s <== predicateType - 4; // Adjusted selector

    // Final selection based on predicate type range
    component finalMux0 = Mux1();
    finalMux0.c[0] <== typeMux0.out;
    finalMux0.c[1] <== typeMux1.out;
    finalMux0.s <== (predicateType - 2) * (predicateType - 3) * (predicateType - 4) * (predicateType - 5) * (predicateType - 6); // 0 if type is 2+

    component finalMux1 = Mux1();
    finalMux1.c[0] <== typeMux2.out;
    finalMux1.c[1] <== predicateResults[6];
    finalMux1.s <== predicateType - 6; // 0 for types 4-5, positive for type 6

    // Simplified final mux (this is a simplified version - in production use proper multi-way mux)
    signal intermediateResult;
    component isLowType = LessThan(3);
    isLowType.in[0] <== predicateType;
    isLowType.in[1] <== 2;

    component isMidType = LessThan(3);
    isMidType.in[0] <== predicateType;
    isMidType.in[1] <== 4;

    component isHighType = LessThan(3);
    isHighType.in[0] <== predicateType;
    isHighType.in[1] <== 6;

    // Simplified result selection (proper implementation would use efficient multi-way mux)
    signal result0 <== isLowType.out * typeMux0.out;
    signal result1 <== (isMidType.out - isLowType.out) * typeMux1.out;
    signal result2 <== (isHighType.out - isMidType.out) * typeMux2.out;
    signal result3 <== (1 - isHighType.out) * predicateResults[6];

    satisfied <== result0 + result1 + result2 + result3;

    // Ensure timestamp is reasonable (not in the far future)
    component timestampCheck = LessThan(64);
    timestampCheck.in[0] <== timestamp;
    timestampCheck.in[1] <== 2000000000000; // Year ~2033 in ms
    timestampCheck.out === 1;
}

component main {public [credentialCommitment, predicateType, targetValue, rangeMax, fieldSelector, nonce, timestamp]} = GenericPredicate();
