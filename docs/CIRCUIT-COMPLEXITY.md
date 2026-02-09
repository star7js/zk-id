# Circuit Complexity Metrics

This document tracks the complexity of each zk-id circuit to monitor growth and detect unexpected increases.

## Constraint Counts (v0.6.0)

| Circuit | Non-linear Constraints | Linear Constraints | Total Constraints | Public Inputs | Private Inputs | Wires | Labels |
|---------|------------------------|--------------------|--------------------|---------------|----------------|-------|--------|
| **age-verify** | 303 | 350 | 653 | 5 | 3 | 644 | 986 |
| **age-verify-signed** | 19,656 | 965 | 20,621 | 261 | 515 | 21,357 | 53,679 |
| **age-verify-revocable** | 2,773 | 3,110 | 5,883 | 6 | 23 | 5,884 | 8,800 |
| **nationality-verify** | 265 | 343 | 608 | 4 | 3 | 614 | 950 |
| **nationality-verify-signed** | 19,618 | 958 | 20,576 | 260 | 515 | 21,327 | 53,643 |
| **credential-hash** | 264 | 341 | 605 | 0 | 3 | 609 | 939 |
| **nullifier** | 507 | 615 | 1,122 | 3 | 3 | 1,127 | 1,708 |

## Powers of Tau Requirements

| Circuit | Max Constraints | Required ptau | ptau File | Size |
|---------|-----------------|---------------|-----------|------|
| age-verify | 653 | 2^10 (1,024) | powersOfTau28_hez_final_12 (2^12) | 9.8 MB |
| nationality-verify | 608 | 2^10 (1,024) | powersOfTau28_hez_final_12 (2^12) | 9.8 MB |
| credential-hash | 605 | 2^10 (1,024) | powersOfTau28_hez_final_12 (2^12) | 9.8 MB |
| nullifier | 1,122 | 2^11 (2,048) | powersOfTau28_hez_final_12 (2^12) | 9.8 MB |
| age-verify-revocable | 5,883 | 2^13 (8,192) | powersOfTau28_hez_final_13 (2^13) | 19.5 MB |
| age-verify-signed | 20,621 | 2^15 (32,768) | powersOfTau28_hez_final_16 (2^16) | 155 MB |
| nationality-verify-signed | 20,576 | 2^15 (32,768) | powersOfTau28_hez_final_16 (2^16) | 155 MB |

**Note**: We use ptau files one size larger than strictly required to provide headroom for future optimizations.

## Constraint Breakdown by Component

### Basic Circuits (age-verify, nationality-verify, credential-hash)

**Main components**:
- **Poseidon(3) hash**: ~264 constraints (credential binding)
- **Comparators**:
  - `GreaterEqThan(12)`: ~13 constraints (age check)
  - `LessEqThan(12)`: ~13 constraints (birthYear sanity check)
  - `GreaterEqThan(12)`: ~13 constraints (birthYear >= 1900)
- **Signal binding**: negligible (nonce, timestamp)

**Total**: ~303 constraints for age circuits, ~265 for nationality

### Signed Circuits (age-verify-signed, nationality-verify-signed)

**Main components**:
- Basic circuit components: ~303 constraints
- **EdDSAVerifier(256)**: ~19,300 constraints
  - Signature verification over Baby Jubjub curve
  - Includes point multiplication, addition, and hash verification
- **Num2Bits(256)**: ~256 constraints (hash to bits conversion)
- **Public key verification**: 256 constraints (issuer key binding)

**Total**: ~19,656 constraints for age-signed, ~19,618 for nationality-signed

### Revocable Circuit (age-verify-revocable)

**Main components**:
- Basic age circuit: ~303 constraints
- **Merkle tree verification**: ~2,470 constraints
  - Depth 10 (1,024 leaves)
  - 10 Poseidon hashes per level
  - ~247 constraints per Poseidon hash
- **Path validation**: negligible

**Total**: ~2,773 constraints

### Nullifier Circuit

**Main components**:
- **Poseidon(3)**: ~264 constraints (credential hash verification)
- **Poseidon(2)**: ~243 constraints (nullifier computation)

**Total**: ~507 constraints

## Proving and Verification Times

Approximate times on reference hardware (Apple M1 Pro, 16GB RAM):

| Circuit | Proving Time | Verification Time | Proof Size |
|---------|--------------|-------------------|------------|
| age-verify | ~0.3s | ~10ms | 192 bytes |
| nationality-verify | ~0.3s | ~10ms | 192 bytes |
| credential-hash | ~0.3s | ~10ms | 192 bytes |
| nullifier | ~0.4s | ~10ms | 192 bytes |
| age-verify-revocable | ~2.5s | ~15ms | 192 bytes |
| age-verify-signed | ~15s | ~20ms | 192 bytes |
| nationality-verify-signed | ~15s | ~20ms | 192 bytes |

**Note**: All Groth16 proofs are exactly 192 bytes regardless of circuit complexity.

## Growth Monitoring

### Baseline (v0.6.0)

This document establishes the baseline constraint counts for v0.6.0. Future versions should monitor:

1. **Unexpected growth** (>20% increase without documented reason)
2. **Constraint optimization opportunities** (new circomlib versions, better algorithms)
3. **New circuit additions** and their complexity impact

### Change History

| Version | Circuit | Change | Constraint Delta | Reason |
|---------|---------|--------|------------------|--------|
| v0.6.0 | age-verify | +13 | 290 → 303 | Added birthYear >= 1900 lower bound check |
| v0.6.0 | age-verify-signed | +13 | 19,643 → 19,656 | Added birthYear >= 1900 lower bound check |
| v0.6.0 | age-verify-revocable | +13 | 2,760 → 2,773 | Added birthYear >= 1900 lower bound check |
| v0.6.0 | age-verify | +13 | 277 → 290 | Widened GreaterEqThan from 8 to 12 bits |
| v0.6.0 | nullifier | NEW | 0 → 507 | Initial implementation |

## Optimization Opportunities

### Current State

✅ **Well-optimized**:
- Basic circuits use minimal Poseidon hashes
- Comparators use appropriate bit widths
- No redundant constraints identified

🔍 **Potential improvements**:
- EdDSA circuits are large but this is unavoidable with current EdDSAVerifier
- Could investigate Poseidon-based signatures (future work)
- Merkle tree depth is configurable but currently hardcoded

### Future Considerations

1. **Signature schemes**: Evaluate BLS signatures (aggregatable) vs EdDSA (current)
2. **Merkle tree alternatives**: Verkle trees, polynomial commitments
3. **Circuit upgrades**: Monitor circomlib updates for optimized components

## References

- Constraint counts extracted from circom compilation output
- Proving times measured on Apple M1 Pro (16GB RAM)
- Groth16 proof size: always 2 G1 points + 1 G2 point = 192 bytes

---

**Last Updated**: 2026-02-09 (v0.6.0)
**Tool Versions**: circom 0.5.46, snarkjs 0.7.6
