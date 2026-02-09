# Trusted Setup Ceremony Documentation

## Overview

zk-id uses the Groth16 proving system, which requires a circuit-specific trusted setup ceremony. This document details the ceremony process, security considerations, and procedures for both development and production deployments.

## Current Status (v0.6.0)

### Development/Testing Keys

The proving keys currently in the repository (`packages/circuits/build/*.zkey`) are generated using a **deterministic beacon** for development and CI purposes.

**⚠️ WARNING**: These keys are **NOT secure for production use**. They use a publicly known seed value and should only be used for:
- Local development
- Automated testing
- CI/CD pipelines
- Demonstrations

### Production Deployment

For production deployments, a proper **multi-party computation (MPC) ceremony** MUST be conducted with multiple independent participants to ensure toxic waste is destroyed.

---

## Trusted Setup Process

### Phase 1: Powers of Tau (Universal Setup)

The universal reference string (URS) is generated through a Powers of Tau ceremony.

#### Current Implementation

zk-id uses pre-generated Powers of Tau files from the Hermez/Polygon ceremony:

| Circuit Size | ptau File | Max Constraints | Download Source |
|--------------|-----------|-----------------|-----------------|
| Small | `powersOfTau28_hez_final_12.ptau` | 4,096 (2^12) | https://storage.googleapis.com/zkevm/ptau/ |
| Medium | `powersOfTau28_hez_final_13.ptau` | 8,192 (2^13) | https://storage.googleapis.com/zkevm/ptau/ |
| Large | `powersOfTau28_hez_final_16.ptau` | 65,536 (2^16) | https://storage.googleapis.com/zkevm/ptau/ |

#### Hermez Powers of Tau Ceremony

- **Participants**: 177 contributors
- **Entropy Sources**: Multiple hardware RNGs, dice rolls, radioactive decay
- **Transcript**: Publicly available at https://github.com/hermeznetwork/phase1-setup/
- **Verification**: All contributions verified with `snarkjs powersoftau verify`
- **Security**: Secure if at least 1 of 177 participants honestly generated and destroyed their contribution

### Phase 2: Circuit-Specific Setup

Each circuit requires its own proving and verification keys derived from the Powers of Tau.

#### Development Process (Current)

```bash
# 1. Compile circuits
npm run compile:circuits

# 2. Run deterministic setup (DEV ONLY)
npm run --workspace=@zk-id/circuits setup
```

The script performs:
1. **Initial setup**: `snarkjs groth16 setup <circuit>.r1cs <ptau_file> <circuit>_0000.zkey`
2. **Beacon application**: `snarkjs zkey beacon <circuit>_0000.zkey <circuit>.zkey <beacon_hex> <iterations>`
   - **Beacon value** (dev): `0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20`
   - **Iterations**: 10
   - **WARNING**: This beacon is publicly known and provides NO security
3. **Verification key export**: `snarkjs zkey export verificationkey <circuit>.zkey <circuit>_verification_key.json`

#### Production Process (Multi-Party Ceremony)

For production deployments, follow this MPC ceremony:

##### Step 1: Coordinator Preparation

1. Compile all circuits:
   ```bash
   npm run compile:circuits
   ```

2. Generate initial zkey files:
   ```bash
   snarkjs groth16 setup build/age-verify.r1cs build/pot/powersOfTau28_hez_final_12.ptau build/age-verify_0000.zkey
   # Repeat for all 7 circuits
   ```

3. Publish ceremony information:
   - Circuit r1cs files (verifiable against source)
   - Initial zkey file hashes
   - Participation instructions
   - Communication channels

##### Step 2: Participant Contributions

Each participant (recommended: 5-10 minimum):

1. Download the previous contribution:
   ```bash
   wget https://ceremony.example.com/age-verify_000X.zkey
   ```

2. Verify the previous contribution:
   ```bash
   snarkjs zkey verify build/age-verify.r1cs build/pot/powersOfTau28_hez_final_12.ptau age-verify_000X.zkey
   ```

3. Contribute new randomness:
   ```bash
   snarkjs zkey contribute age-verify_000X.zkey age-verify_000Y.zkey \
     --name="Participant Name" \
     --entropy="<high-entropy-string>"
   ```

   **Entropy sources** (use multiple):
   - Hardware RNG (e.g., `/dev/random`)
   - Physical dice rolls
   - Air-gapped random number generation
   - Environmental noise (radioactive decay, atmospheric noise)

4. **CRITICAL**: Securely delete all local copies and entropy after contribution
   ```bash
   shred -vfz -n 10 age-verify_000X.zkey
   shred -vfz -n 10 entropy_sources.txt
   # Clear shell history
   history -c
   # Reboot to clear memory
   ```

5. Upload contribution and attestation:
   ```bash
   # Upload new zkey
   # Publish attestation with:
   # - Contribution hash
   # - Entropy generation method
   # - PGP-signed statement
   ```

##### Step 3: Final Randomness (Beacon)

After all participants contribute, apply a public random beacon:

```bash
# Use a future block hash or other unpredictable public randomness
# Example: Ethereum block hash from block mined AFTER all contributions
snarkjs zkey beacon age-verify_FINAL.zkey age-verify.zkey <block_hash> 10 \
  --name="Ethereum block <block_number>"
```

**Beacon sources**:
- Ethereum block hashes (future blocks)
- NIST randomness beacon
- Combined outputs from multiple sources

##### Step 4: Verification and Publication

1. Verify the final zkey:
   ```bash
   snarkjs zkey verify build/age-verify.r1cs build/pot/powersOfTau28_hez_final_12.ptau age-verify.zkey
   ```

2. Export verification key:
   ```bash
   snarkjs zkey export verificationkey age-verify.zkey age-verify_verification_key.json
   ```

3. Publish ceremony artifacts:
   - All contribution zkey files
   - Participant attestations
   - Contribution verification log
   - Final zkey and verification key
   - SHA-256 hashes (update `docs/circuit-hashes.json`)

---

## Circuit-Specific Setup Parameters

| Circuit | ptau Size | Constraints | Participants Required | Estimated Duration |
|---------|-----------|-------------|----------------------|-------------------|
| age-verify | Small (2^12) | 303 | 5-10 | 2-3 days |
| age-verify-signed | Large (2^16) | 19,656 | 10-15 | 1-2 weeks |
| age-verify-revocable | Medium (2^13) | 2,773 | 5-10 | 2-3 days |
| nationality-verify | Small (2^12) | 265 | 5-10 | 2-3 days |
| nationality-verify-signed | Large (2^16) | 19,618 | 10-15 | 1-2 weeks |
| credential-hash | Small (2^12) | 264 | 5-10 | 2-3 days |
| nullifier | Small (2^12) | 507 | 5-10 | 2-3 days |

---

## Security Considerations

### Toxic Waste

The intermediate values (`α`, `β`, `γ`, `δ`) used during setup are "toxic waste" that MUST be destroyed. If any participant retains this data, they can forge proofs.

**Security Property**: The ceremony is secure if at least ONE participant:
1. Generated their contribution with true randomness
2. Securely destroyed their toxic waste

### Participant Selection

For production ceremonies:

- **Minimum**: 5 independent participants
- **Recommended**: 10-15 participants
- **Diversity**: Participants from different:
  - Geographic locations
  - Organizations
  - Technical backgrounds
  - Trust domains

### Entropy Generation Best Practices

1. **Never use**:
   - Pseudorandom number generators (PRNGs)
   - Publicly known seeds
   - Low-entropy sources (timestamps, PIDs)

2. **Recommended**:
   - Hardware RNGs (`/dev/random` on Linux)
   - Physical processes (dice, coin flips)
   - Atmospheric noise
   - Radioactive decay
   - Combination of multiple sources

3. **Verification**:
   - Use `ent` or `rng-test` to verify entropy quality
   - Aim for >7.9 bits per byte

### Attestation

Each participant SHOULD publish:
1. PGP-signed statement including:
   - Contribution hash
   - Entropy generation method
   - Hardware used
   - Timestamp
2. Video/photo evidence (optional but recommended)
3. Witness signatures (optional)

---

## Verification

### Verify Current Keys (Development)

```bash
cd packages/circuits
npm run verify:hashes
```

This verifies that build artifacts match committed hashes in `docs/circuit-hashes.json`.

### Verify Production Ceremony

For production keys, third parties can verify:

1. **Powers of Tau**: Verify against Hermez ceremony transcript
2. **Contributions**: Verify each contribution in sequence:
   ```bash
   snarkjs zkey verify <circuit>.r1cs <ptau_file> <circuit>_XXXX.zkey
   ```
3. **Beacon**: Verify beacon value against public source (e.g., Ethereum block hash)
4. **Final zkey**: Verify complete chain from Phase 1 → all contributions → final key

---

## Migration to Production Keys

When production keys are ready:

1. **Update `docs/circuit-hashes.json`** with production key hashes
2. **Update this document** with:
   - Ceremony dates
   - Participant list (or anonymous count)
   - Attestation links
   - Verification instructions
3. **Update `SECURITY.md`** noting the production ceremony
4. **Archive ceremony artifacts** in a public, tamper-evident location (IPFS, GitHub release)

---

## References

- [snarkjs Documentation](https://github.com/iden3/snarkjs)
- [Hermez Powers of Tau Ceremony](https://github.com/hermeznetwork/phase1-setup)
- [Groth16 Paper](https://eprint.iacr.org/2016/260.pdf)
- [Trusted Setup Ceremonies - Best Practices](https://zkproof.org/2021/06/30/setup-ceremonies/)

---

## Changelog

- **v0.6.0** (2026-02-09): Initial documentation
  - Development keys use deterministic beacon
  - Production ceremony process defined
  - 7 circuits documented
