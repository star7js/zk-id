# Cryptographic Parameters

This document details the cryptographic parameters used in zk-id circuits and implementations.

## Poseidon Hash Function

### Overview

zk-id uses the Poseidon hash function for all in-circuit hashing operations. Poseidon is a ZK-friendly hash function optimized for use in SNARKs, designed by Grassi, Khovratovich, Rechberger, Roy, and Schofnegger.

**Reference**: [Poseidon: A New Hash Function for Zero-Knowledge Proof Systems](https://eprint.iacr.org/2019/458.pdf)

### Field

- **Field**: BN128 (BN254) scalar field
- **Prime**: `21888242871839275222246405745257275088548364400416034343698204186575808495617`
- **Bit length**: ~254 bits

### Parameters

zk-id uses Poseidon with the following parameters, as specified in the Poseidon paper (Table 2, Table 8):

#### For Poseidon(3) - Used in Credential Hashing

- **t** (width): 4
  - Input size: 3 elements (birthYear, nationality, salt)
  - State size: t = nInputs + 1 = 4
- **RF** (full rounds): 8
- **RP** (partial rounds): 56
- **Total rounds**: 64
- **Security level**: 128 bits

**Used in circuits**:
- `credential-hash.circom`
- `age-verify.circom`
- `age-verify-signed.circom`
- `age-verify-revocable.circom`
- `nationality-verify.circom`
- `nationality-verify-signed.circom`
- `nullifier.circom` (credential hashing)

#### For Poseidon(2) - Used in Nullifier Computation

- **t** (width): 3
  - Input size: 2 elements (credentialHash, scopeHash)
  - State size: t = nInputs + 1 = 3
- **RF** (full rounds): 8
- **RP** (partial rounds): 57
- **Total rounds**: 65
- **Security level**: 128 bits

**Used in circuits**:
- `nullifier.circom` (nullifier computation)

### Implementation

#### Circuit Implementation (circomlib)

zk-id circuits use `circomlib v2.0.5` for Poseidon hashing.

**Source**: [`circomlib/circuits/poseidon.circom`](https://github.com/iden3/circomlib/blob/master/circuits/poseidon.circom)

The circomlib implementation:
1. Uses parameters from the Poseidon whitepaper
2. Generated using the official reference implementation: https://extgit.iaik.tugraz.at/krypto/hadeshash
3. Rounded to nearest integer that divides evenly by t

```circom
// From circomlib/circuits/poseidon.circom
var N_ROUNDS_P[16] = [56, 57, 56, 60, 60, 63, 64, 63, 60, 66, 60, 65, 70, 60, 64, 68];
var t = nInputs + 1;
var nRoundsF = 8;
var nRoundsP = N_ROUNDS_P[t - 2];
```

#### TypeScript Implementation (circomlibjs)

zk-id TypeScript code uses `circomlibjs@0.1.7` for Poseidon hashing outside of circuits.

**Source**: [`circomlibjs`](https://github.com/iden3/circomlibjs)

**Verification**: circomlibjs is the official JavaScript implementation provided by iden3 to compute witnesses for circomlib circuits. It uses identical parameters and constants to ensure circuit/witness compatibility.

**Usage in zk-id**:
```typescript
import { buildPoseidon } from 'circomlibjs';

const poseidon = await buildPoseidon();
const hash = poseidon([input1, input2, input3]);
```

### Parameter Verification

The parameters used in zk-id have been verified to match the canonical BN128 Poseidon parameters:

✅ **Field**: BN128 scalar field (as specified)
✅ **t=4, RF=8, RP=56**: Matches Poseidon paper Table 8 for t=4, security level 128
✅ **t=3, RF=8, RP=57**: Matches Poseidon paper Table 8 for t=3, security level 128
✅ **circomlib and circomlibjs**: Both use identical parameters from official reference

### Security Considerations

1. **Collision Resistance**: 128-bit security level for collision resistance
2. **Preimage Resistance**: 254-bit security level (limited by field size)
3. **Constant Generation**: All round constants and MDS matrices are generated deterministically from the reference implementation
4. **No Known Attacks**: As of 2026, no practical attacks against Poseidon with these parameters are known

### Round Constant Provenance

The round constants (C), S-boxes, MDS matrix (M), and sparse matrix (P) are:
- Generated using the official `calc_round_numbers.py` script from the Poseidon authors
- Embedded in `circomlib/circuits/poseidon_constants.circom`
- Reproduced identically in `circomlibjs/src/poseidon_constants.js`
- Deterministic and verifiable against the reference implementation

### Testing

Poseidon hash compatibility between circuits and TypeScript is verified through:
1. Unit tests in `packages/core/test/poseidon.test.ts`
2. Integration tests in `packages/core/test/credential.test.ts`
3. Circuit tests in `packages/circuits/test/*.test.js`

All tests verify that:
- Circuit and TypeScript implementations produce identical hashes
- Hash values are deterministic
- Different inputs produce different hashes

---

## EdDSA (Baby Jubjub)

### Signature Scheme

zk-id uses EdDSA signatures over the Baby Jubjub elliptic curve for credential issuance.

**Curve**: Baby Jubjub (twisted Edwards curve over BN128 scalar field)
**Reference**: [ERC-2494 - Baby Jubjub Elliptic Curve](https://eips.ethereum.org/EIPS/eip-2494)

### Parameters

- **Curve equation**: `ax² + y² = 1 + dx²y²`
- **a**: 168700
- **d**: 168696
- **Base point order (L)**: `2736030358979909402780800718157159386076813972158567259200215660948447373041`
- **Cofactor**: 8

### Implementation

**Circuit**: `circomlib/circuits/eddsa.circom` (EdDSAVerifier)
**JavaScript**: `circomlibjs` (signature generation and verification)

### Security

- **Signature Length**: 512 bits (R8x, R8y, S)
- **Security Level**: ~128 bits
- **Subgroup Order Check**: EdDSAVerifier enforces S < L (subgroup order)

---

## Groth16 Proving System

### Parameters

- **Curve**: BN128 (BN254)
- **Pairing**: Optimal ate pairing
- **Security Level**: ~100 bits (as of 2026)

### Trusted Setup

See `docs/TRUSTED-SETUP.md` for ceremony documentation.

---

## Version Information

- **circomlib**: v2.0.5
- **circomlibjs**: v0.1.7
- **Document Version**: v0.6.0
- **Last Verified**: 2026-02-09
