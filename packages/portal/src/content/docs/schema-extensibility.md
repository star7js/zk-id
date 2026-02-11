---
title: 'Schema Extensibility'
description: 'How the zk-id credential schema works, why it is fixed, and how to extend it.'
category: 'Architecture'
order: 14
---

# Credential Schema Extensibility

How the zk-id credential schema works, why it is fixed, and how to extend it.

---

## Current Schema

Every zk-id credential commits to exactly **3 fields** via a Poseidon hash:

```
commitment = Poseidon(birthYear, nationality, salt)
```

| Field         | Type   | Range                      | Size     |
| ------------- | ------ | -------------------------- | -------- |
| `birthYear`   | number | 1900–4095                  | 12 bits  |
| `nationality` | number | 1–999 (ISO 3166-1 numeric) | 10 bits  |
| `salt`        | hex    | 256-bit random             | 256 bits |

This structure is **hardcoded** in every circuit:

- `age-verify.circom` — proves `currentYear - birthYear >= minAge`
- `nationality-verify.circom` — proves `nationality == targetNationality`
- `age-verify-signed.circom` — signed variant with BabyJub EdDSA
- `nationality-verify-signed.circom` — signed variant
- `age-verify-revocable.circom` — revocable variant with Merkle inclusion

---

## Why the Schema Is Fixed

**Poseidon arity is a circuit-level parameter.** The Poseidon hash in each circuit takes exactly 3 inputs. Changing the number of inputs changes the hash output, which means:

1. A credential with `Poseidon(birthYear, nationality, dateOfBirth, salt)` produces a **different commitment** than `Poseidon(birthYear, nationality, salt)`
2. Existing circuits cannot verify proofs against the new commitment
3. Existing credentials cannot be used with new circuits

**Backwards compatibility is not automatic** — new fields = new commitment = new circuits.

---

## Adding a New Attribute

To add a new attribute (e.g., `dateOfBirth`, `residenceCountry`, `documentType`):

### Step 1: Design the New Commitment

Choose the Poseidon arity for the new schema:

```
commitment_v2 = Poseidon(birthYear, nationality, dateOfBirth, residenceCountry, salt)
```

Constraints:

- Each input must fit in the BN128 scalar field (~254 bits)
- Poseidon arity affects circuit size (more inputs = more constraints)
- All circuits that check the commitment must agree on the input order

### Step 2: Write New Circuits

Every circuit that opens the commitment must be updated:

```circom
// age-verify-v2.circom (conceptual)
template AgeVerifyV2() {
    signal input birthYear;
    signal input nationality;
    signal input dateOfBirth;       // new
    signal input residenceCountry;  // new
    signal input salt;
    signal input minAge;
    signal input currentYear;

    // Recompute commitment with new arity
    component hasher = Poseidon(5);  // was Poseidon(3)
    hasher.inputs[0] <== birthYear;
    hasher.inputs[1] <== nationality;
    hasher.inputs[2] <== dateOfBirth;
    hasher.inputs[3] <== residenceCountry;
    hasher.inputs[4] <== salt;

    // ... age constraint unchanged ...
}
```

### Step 3: Compile and Run Trusted Setup

```bash
# Compile new circuit
circom age-verify-v2.circom --r1cs --wasm --sym

# Phase 2 trusted setup (circuit-specific)
snarkjs groth16 setup age-verify-v2.r1cs pot_final.ptau age-verify-v2.zkey
snarkjs zkey export verificationkey age-verify-v2.zkey age-verify-v2_vkey.json
```

### Step 4: Update TypeScript Types

```typescript
// Extended credential interface
interface CredentialV2 extends Credential {
  dateOfBirth: string; // ISO 8601 date
  residenceCountry: number; // ISO 3166-1 numeric
}
```

### Step 5: Update Provers and Verifiers

- `createCredential()` must hash the new fields
- `generateProof()` must supply new private inputs
- Verification keys must be regenerated and distributed
- `ZkIdServer` config must point to new verification keys

### Step 6: Migration

Existing credentials **cannot** be used with new circuits. Options:

- **Reissue**: Issuer reissues credentials with the new schema
- **Dual support**: Server accepts both old and new verification keys during transition
- **Version field**: Use protocol versioning to route to the correct verifier

---

## Complexity Impact

Adding fields increases circuit size and proof generation time:

| Poseidon Arity | Constraints (approx.) | Proof Time Impact |
| -------------- | --------------------- | ----------------- |
| 3 (current)    | ~700                  | Baseline          |
| 5              | ~1,100                | ~1.6x             |
| 8              | ~1,700                | ~2.4x             |

The constraint count is dominated by the Poseidon hash. Other circuit logic (age comparison, Merkle inclusion) is unaffected.

---

## Alternative Approaches

### BBS+ Selective Disclosure

Instead of extending the Poseidon commitment, use BBS+ signatures for multi-attribute credentials with selective disclosure. zk-id has a prototype BBS module (`@zk-id/core/bbs`).

**Tradeoff**: BBS+ provides selective disclosure without custom circuits but cannot prove predicates (e.g., `age >= 18`) — only reveal/hide individual attributes.

### BBS+SNARK Hybrid

Combine BBS+ signed attributes with a SNARK circuit that proves a predicate over the disclosed value. This is on the long-term roadmap.

### Recursive Proofs

Use recursive SNARKs to aggregate multiple single-attribute proofs (e.g., prove age AND nationality AND residency) without changing the base circuit. This requires Groth16-in-Groth16 or Nova/Halo2.

---

## Summary

| Question                                       | Answer                                                 |
| ---------------------------------------------- | ------------------------------------------------------ |
| Can I add a field without new circuits?        | No                                                     |
| Can old credentials work with new circuits?    | No — must reissue                                      |
| Can I run old and new circuits in parallel?    | Yes — use protocol versioning                          |
| Does adding fields affect performance?         | Yes — ~1.5-2.5x per additional field                   |
| Is there an alternative to Poseidon extension? | BBS+ for disclosure, BBS+SNARK for predicates (future) |
