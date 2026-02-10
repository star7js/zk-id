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

## Signature Schemes: Ed25519 vs Baby Jubjub EdDSA

**IMPORTANT**: zk-id uses **two different signature schemes** for different purposes. They are **NOT bridged** or converted between each other — they operate independently.

### 1. Ed25519 (Classical Edwards Curve) — Off-Chain Signatures

**Use Case**: Default credential issuance (`CredentialIssuer`)

**Purpose**: Off-chain signature verification by the server/verifier (not in ZK circuit)

**Implementation**:

- **Library**: Node.js `crypto` module
- **Curve**: Ed25519 (classical Edwards curve over prime field)
- **Signature Algorithm**: RFC 8032 Ed25519
- **Key Generation**: `crypto.generateKeyPairSync('ed25519')`
- **Signing**: `crypto.sign(null, message, privateKey)`
- **Verification**: `crypto.verify(null, message, publicKey, signature)`

**Where Used**:

- `packages/issuer/src/issuer.ts` — `CredentialIssuer` class
- Signs `SignedCredential` objects for off-chain verification
- Signature included in credential metadata (not in ZK proof)
- Server validates signature before accepting credential from user

**Characteristics**:

- Fast signing/verification (~50 μs)
- Small signatures (64 bytes)
- NOT circuit-compatible (Ed25519 curve arithmetic too expensive in circuits)

### 2. Baby Jubjub EdDSA — In-Circuit Signatures

**Use Case**: Signed circuits (`CircuitCredentialIssuer`)

**Purpose**: In-circuit signature verification as part of the ZK proof

**Implementation**:

- **Library**: `circomlibjs` (JavaScript) + `circomlib` (circuits)
- **Curve**: Baby Jubjub (twisted Edwards curve over BN128 scalar field)
- **Signature Algorithm**: Pedersen hash-based EdDSA
- **Key Generation**: `eddsa.prv2pub(randomBytes(32))`
- **Signing**: `eddsa.signPedersen(privateKey, message)`
- **Verification**: `EdDSAVerifier(256)` circuit in circomlib

**Where Used**:

- `packages/issuer/src/circuit-issuer.ts` — `CircuitCredentialIssuer` class
- `packages/circuits/src/age-verify-signed.circom`
- `packages/circuits/src/nationality-verify-signed.circom`
- Signature verified **inside the ZK proof** (issuer trust proven in-circuit)

**Characteristics**:

- Circuit-compatible (BN128 field arithmetic)
- Large proving overhead (~19,656 constraints for EdDSA verification)
- Slow proving (~15s on M1 Pro)
- Self-contained proofs (no need for server-side issuer registry)

### Why Two Different Schemes?

| Aspect                    | Ed25519 (Off-Chain)                         | Baby Jubjub EdDSA (In-Circuit)     |
| ------------------------- | ------------------------------------------- | ---------------------------------- |
| **Verification Location** | Server-side (outside proof)                 | Inside ZK circuit                  |
| **Trust Model**           | Verifier checks issuer signature separately | Issuer trust proven in ZK proof    |
| **Performance**           | Fast (50 μs verify)                         | Slow (15s proving)                 |
| **Proof Size**            | Same (192 bytes)                            | Same (192 bytes)                   |
| **Public Inputs**         | 5 signals                                   | 261 signals (pubkey + sig bits)    |
| **Circuit Constraints**   | 303 (no sig verification)                   | 19,656 (with sig verification)     |
| **Use When**              | Standard deployments, registry available    | Self-contained proofs, no registry |

### No Signature Bridge

**There is no conversion or "bridge" between Ed25519 and Baby Jubjub EdDSA.**

These are fundamentally different cryptographic schemes:

- Ed25519 uses a different elliptic curve (Curve25519)
- Baby Jubjub is designed specifically for BN128-based ZK circuits
- They have incompatible key formats and signature formats
- Converting between them is cryptographically impossible

A credential signed with Ed25519 (by `CredentialIssuer`) **cannot** be used with signed circuits. Conversely, a credential signed with Baby Jubjub EdDSA (by `CircuitCredentialIssuer`) **cannot** be verified using standard Ed25519 verification.

**Deployment Choice**:

- Use Ed25519 (`CredentialIssuer`) for most deployments (faster, simpler)
- Use Baby Jubjub EdDSA (`CircuitCredentialIssuer`) only when issuer trust must be proven in-circuit (e.g., decentralized deployments with no trusted issuer registry)

---

## Credential Commitment Scheme

### Construction

Credential commitments use Poseidon(3) hash:

```
commitment = H(birthYear, nationality, salt)
```

Where:

- `birthYear`: 12-bit value (1900-4095)
- `nationality`: 10-bit value (1-999, ISO 3166-1 numeric)
- `salt`: 256-bit random value (32 bytes from `crypto.randomBytes`)

### Collision Resistance

**Collision Scenario**: Two credentials with identical `Poseidon(birthYear, nationality, salt)` are cryptographically indistinguishable. The prover could use either credential interchangeably.

**Security Margin**:

- **Preimage resistance**: Finding `(birthYear, nationality, salt)` given `commitment` requires ~2^128 operations (Poseidon security level)
- **Collision resistance**: Finding two distinct inputs with the same hash requires ~2^128 operations (birthday bound for 254-bit output)
- **Salt entropy**: 256 bits of randomness makes accidental collisions negligible

**Probability Analysis**:

- **Single collision probability**: `1 / 2^254` (negligible, ~10^-76)
- **Birthday attack** (after issuing N credentials): `N^2 / 2^255`
  - 1 billion credentials → probability ~10^-58 (negligible)
  - 2^64 credentials → probability ~10^-38 (still negligible)
- **Targeted collision** (attacker tries to match a specific commitment): ~2^128 hash operations required

**Practical Security**: With 256-bit salt entropy and Poseidon's 128-bit security level, credential hash collisions are computationally infeasible for any realistic deployment scale.

---

## Groth16 Proving System

### Parameters

- **Curve**: BN128 (BN254)
- **Pairing**: Optimal ate pairing
- **Security Level**: ~100 bits (as of 2026)

### Trusted Setup

See `docs/TRUSTED-SETUP.md` for ceremony documentation.

---

## Random Number Generation (CSPRNG)

### Implementation

All random value generation in zk-id uses Node.js `crypto.randomBytes()`.

```typescript
import { randomBytes } from 'crypto';

// Credential salt (256-bit entropy)
const salt = randomBytes(32).toString('hex');

// Credential ID (128-bit entropy)
const id = randomBytes(16).toString('hex');

// Circuit issuer private key (256-bit entropy)
const privateKey = randomBytes(32);

// Nonce generation (248-bit entropy)
const nonce = BigInt('0x' + randomBytes(31).toString('hex')).toString();

// KMS envelope encryption IV (96-bit entropy for AES-GCM)
const iv = randomBytes(12);
```

### CSPRNG Properties

**Node.js `crypto.randomBytes()` is cryptographically secure:**

| Platform    | Implementation    | Source                                              |
| ----------- | ----------------- | --------------------------------------------------- |
| **Linux**   | `/dev/urandom`    | Kernel CSPRNG (getrandom syscall on modern kernels) |
| **macOS**   | `/dev/urandom`    | Kernel CSPRNG (arc4random_buf)                      |
| **Windows** | `BCryptGenRandom` | Windows CNG (Cryptography Next Generation)          |

**Security Guarantees** (from Node.js documentation):

- Cryptographically strong pseudo-random data
- Suitable for cryptographic key generation, nonces, and salts
- Seeded from OS-level entropy sources
- Blocking behavior: Will wait for sufficient entropy on first call after boot (extremely rare in production)

**Entropy Sources:**

- Hardware RNG (RDRAND/RDSEED on x86, RNDRND on ARM)
- Interrupt timing
- Disk I/O timing
- Network packet timing
- Other OS-specific sources

### Usage in zk-id

| Component          | Purpose                       | Size                | Security Requirement               |
| ------------------ | ----------------------------- | ------------------- | ---------------------------------- |
| Credential salt    | Privacy, collision resistance | 32 bytes (256 bits) | High - used in Poseidon commitment |
| Credential ID      | Uniqueness                    | 16 bytes (128 bits) | Medium - collision resistance      |
| Circuit issuer key | EdDSA private key             | 32 bytes (256 bits) | Critical - key material            |
| Nonce              | Replay protection             | 31 bytes (248 bits) | High - must be unpredictable       |
| KMS IV             | AES-GCM nonce                 | 12 bytes (96 bits)  | Critical - must never repeat       |

**All uses are appropriate for their security requirements.**

### Platform Support

**Supported Platforms**: Node.js 18+ on Linux, macOS, Windows

**Not Supported**: Browser environments (Web Crypto API would be required for browser support)

The zk-id library is designed for Node.js server environments and does not currently support browser-based credential generation. This is intentional:

- Credential issuance should occur in a trusted environment (issuer server)
- Proof generation can occur client-side using pre-issued credentials
- Browser support for proof generation is planned for future releases

### Verification

The CSPRNG implementation can be verified by:

1. Reading Node.js source code: `src/node_crypto.cc` → `RandomBytes` function
2. Statistical tests: NIST SP 800-22 test suite (would require millions of samples)
3. Entropy analysis: Checking `/dev/urandom` properties on Unix systems

**Recommendation**: Trust Node.js crypto module as it is battle-tested and audited by the Node.js security team.

---

## Version Information

- **circomlib**: v2.0.5
- **circomlibjs**: v0.1.7
- **Document Version**: v0.6.0
- **Last Verified**: 2026-02-09
