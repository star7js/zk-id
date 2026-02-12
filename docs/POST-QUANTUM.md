# Post-Quantum Cryptography Roadmap

## Current Cryptographic Assumptions

zk-id currently relies on the following cryptographic primitives:

### Proof System

- **Groth16 ZK-SNARKs** over the BN128 (alt-bn128) elliptic curve
- Relies on hardness of discrete logarithm problem over elliptic curves
- Vulnerable to Shor's algorithm on sufficiently large quantum computers

### Signatures

- **Ed25519** for credential signing (standard mode)
- **BabyJub EdDSA** for in-circuit signature verification (signed circuits)
- Both rely on elliptic curve discrete logarithm problem

### Hash Functions

- **Poseidon** hash function (ZK-friendly, used in commitment scheme)
- Designed to be quantum-resistant (symmetric cryptography generally resists known quantum attacks)
- SHA-256 for auxiliary hashing
- Both hash functions remain secure in post-quantum setting

## Quantum Threat Assessment

### Timeline

- **2026 (Current)**: No quantum computer can break Groth16, Ed25519, or BN128
- **2030+**: Potential for cryptographically-relevant quantum computers (CRQC)
- **Ethereum's Timeline**: Planning post-quantum migration around 2028-2030 (preparation phase, not imminent threat)

### Risk Analysis

- **Hash functions**: ✅ Already quantum-resistant
- **Signatures**: ⚠️ Vulnerable to Shor's algorithm (requires ~4000 logical qubits for Ed25519)
- **ZK-SNARKs**: ⚠️ Vulnerable to Shor's algorithm (pairing-based curves broken)
- **Practical Risk (2026)**: Very Low - No quantum computer has sufficient error correction

### Current Position

**We do not implement post-quantum cryptography now because:**

1. No production-ready quantum-resistant ZK-SNARK tooling exists
2. Lattice-based ZK proofs are bleeding-edge research
3. Premature implementation by a solo developer without cryptography expertise introduces more risk than quantum threats
4. The real existential risk is lack of adoption, not future quantum computers

## Migration Path

zk-id is designed with cryptographic agility through the `ProvingSystem` abstraction in `packages/core/src/proving-system.ts`. This allows pluggable proof system backends without breaking the API.

### Phase 1: PLONK Migration (When Ready)

**Target**: 2027-2028
**Trigger**: Stable circom/snarkjs PLONK support

- Migrate from Groth16 to PLONK (universal setup, no trusted ceremony)
- PLONK still uses pairing-based curves (not quantum-resistant)
- Benefits: Better developer experience, no ceremony needed
- Implementation: Add `PlonkProvingSystem` alongside existing Groth16

### Phase 2: STARK Migration (When Practical)

**Target**: 2028-2030
**Trigger**: STARK proof sizes become competitive (<1KB) or layer-2 adoption is standard

- STARKs are hash-based (quantum-resistant)
- Current limitation: 10-100x larger proofs than Groth16 (~200KB vs ~200 bytes)
- Acceptable when:
  - Proof size reduction through compression/batching
  - Layer-2 solutions make verification cost negligible
  - Browser performance improves sufficiently
- Implementation: Add `StarkProvingSystem` backend

### Phase 3: Lattice-Based ZK (When Available)

**Target**: 2030+
**Trigger**: Production-ready tooling from academic research

- Lattice-based ZK-SNARKs (e.g., post-quantum Groth-like schemes)
- Active research areas:
  - Lattice-based pairing replacements
  - FHE-based ZK proofs
  - Quantum-resistant commitment schemes
- Watch: Zama, Polygon zkEVM, StarkWare research
- Implementation: Add `LatticeProvingSystem` when tooling matures

### Phase 4: Signature Migration

**Target**: Aligned with Phases 1-3
**Trigger**: NIST PQC standards finalize (already done for some algorithms)

- Replace Ed25519 with NIST PQC standard:
  - **Dilithium** (lattice-based, ~2-4KB signatures)
  - **Falcon** (lattice-based, ~1KB signatures)
- Replace BabyJub EdDSA in circuits with quantum-resistant alternative
- Challenge: Larger signature sizes increase proof complexity

## Monitoring Strategy

### Standards Bodies

- **NIST PQC**: Monitor standardization of Dilithium, Falcon, SPHINCS+
- **IETF**: Track post-quantum TLS and signature standards
- **Ethereum Foundation**: Follow Ethereum's post-quantum roadmap

### Research Developments

- **Circom/snarkjs**: Watch for PQ-compatible circuit primitives
- **StarkWare**: Monitor STARK proof size optimizations
- **Zama**: Track FHE-based ZK research
- **Academic**: Follow IACR ePrint archive for lattice ZK breakthroughs

### Tooling Maturity Indicators

- Production-ready circom libraries for PQ primitives
- Audited implementations of PQ ZK schemes
- Benchmarks showing competitive proof sizes (<5KB)
- Browser WASM support for PQ proof generation

## Implementation Commitment

**When production-ready tooling exists:**

1. Implement new proving system backend (pluggable via `ProvingSystem`)
2. Support dual-mode operation (legacy + PQ) during transition
3. Provide migration guide for credential re-issuance
4. Maintain backwards compatibility with versioning

**Migration will NOT be backwards compatible because:**

- New cryptographic commitments require new circuits
- Credentials must be re-issued with PQ signatures
- Verifiers must upgrade verification keys

## Documentation

This document will be updated annually (or when major developments occur) to reflect:

- Latest quantum computing capabilities
- New PQ ZK-SNARK research
- Tooling availability from circom/snarkjs
- Ethereum's PQ migration timeline

**Last Updated**: 2026-02-11

## References

- [NIST Post-Quantum Cryptography Standardization](https://csrc.nist.gov/projects/post-quantum-cryptography)
- [Ethereum Post-Quantum Roadmap](https://ethereum.org/en/roadmap/)
- [IACR ePrint Archive: Lattice-Based ZK-SNARKs](https://eprint.iacr.org/)
- [STARKWare: STARKs vs SNARKs](https://starkware.co/stark-vs-snark/)
- [Vitalik Buterin: Quantum Resistance](https://vitalik.eth.limo/general/2021/01/26/snarks.html)

## FAQ

### Why not implement post-quantum now?

**Risk-benefit analysis:**

- **Quantum threat (2026)**: Effectively zero
- **Implementation risk**: High (bugs, performance issues, unaudited code)
- **Opportunity cost**: High (delays adoption, which is the real risk)

Implementing PQ cryptography now would be security theater that hurts the project more than it helps.

### How long will migration take?

**When tooling is ready**: 2-4 months for implementation + 2-3 months for audit.

**Key blocker**: Tooling maturity. We cannot migrate until circom/snarkjs support PQ primitives, or until STARKs become practical for browser-based proof generation.

### What about hybrid approaches?

**Dual-signature schemes** (classical + PQ) are possible but:

- Increase proof size significantly
- Add complexity without clear benefit given current timeline
- Better to wait for pure PQ schemes when ready

### Will users need new credentials?

**Yes.** Post-quantum migration requires:

1. Issuers re-sign credentials with PQ signatures
2. New circuits with PQ-compatible commitments
3. Verifiers upgrade verification keys

This is unavoidable because the commitment scheme binds the cryptographic primitives.
