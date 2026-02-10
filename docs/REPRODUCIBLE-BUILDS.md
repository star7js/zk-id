# Reproducible Builds

This document provides step-by-step instructions for reproducing circuit artifacts from source. Following these exact steps should produce cryptographically identical proving keys and verification keys that match the hashes in `docs/circuit-hashes.json`.

## Prerequisites

### Required Software Versions

**CRITICAL**: Circuit compilation is deterministic but platform-specific. To match published hashes exactly, use the same platform and toolchain versions.

| Tool            | Version  | Installation                      |
| --------------- | -------- | --------------------------------- |
| **Node.js**     | v22.19.0 | https://nodejs.org/               |
| **npm**         | 11.6.2   | (bundled with Node.js)            |
| **circom**      | 0.5.46   | See installation below            |
| **snarkjs**     | 0.7.6    | `npm install` (from package.json) |
| **circomlib**   | 2.0.5    | `npm install` (from package.json) |
| **circomlibjs** | 0.1.7    | `npm install` (from package.json) |

### Platform Information

**Reference Platform** (for canonical hashes):

- **OS**: macOS (Darwin 25.2.0)
- **Architecture**: arm64 (Apple Silicon)
- **Note**: WASM files may differ on other platforms; only zkey and verification key hashes are security-critical

**Alternative Platforms**:

- Linux (x86_64, aarch64)
- macOS (Intel, Apple Silicon)
- Windows (WSL2 recommended)

**Important**: Different platforms/architectures may produce different WASM files due to compiler differences. The verification script (`verify-hashes.sh`) skips WASM verification for this reason.

---

## circom Installation

circom must be installed from source to ensure the exact version:

### Option 1: Install from cargo (Recommended)

```bash
# Install Rust if not already installed
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Install circom 0.5.46
cargo install --git https://github.com/iden3/circom.git --tag v0.5.46

# Verify installation
circom --version
# Should output: 0.5.46
```

### Option 2: Build from source

```bash
git clone https://github.com/iden3/circom.git
cd circom
git checkout v0.5.46
cargo build --release
cargo install --path circom

# Verify installation
circom --version
```

---

## Reproducible Build Process

### Step 1: Clone Repository

```bash
git clone https://github.com/star7js/zk-id.git
cd zk-id
git checkout v0.6.0  # Or specific commit hash
```

### Step 2: Install Dependencies

```bash
npm install
```

This installs all dependencies with exact versions from `package-lock.json`:

- `snarkjs@0.7.6`
- `circomlib@2.0.5`
- `circomlibjs@0.1.7`
- All other dependencies

### Step 3: Compile Circuits

```bash
npm run compile:circuits
```

This executes `packages/circuits/scripts/compile.sh` which runs:

```bash
circom <circuit>.circom \
  --r1cs \
  --wasm \
  --sym \
  -o build/ \
  --prime bn128 \
  -l ../../node_modules
```

**Compilation flags**:

- `--r1cs`: Generate R1CS constraint system
- `--wasm`: Generate WebAssembly witness generator
- `--sym`: Generate symbol table for debugging
- `--prime bn128`: Use BN128 scalar field
- `-l ../../node_modules`: Include circomlib from node_modules

**Output** (per circuit):

- `build/<circuit>.r1cs` - Constraint system
- `build/<circuit>_js/<circuit>.wasm` - Witness generator
- `build/<circuit>.sym` - Symbol table

### Step 4: Download Powers of Tau

Powers of Tau files are downloaded automatically during setup:

```bash
npm run --workspace=@zk-id/circuits setup
```

This downloads (if not cached):

- `powersOfTau28_hez_final_12.ptau` (4,096 constraints) - 9.8 MB
- `powersOfTau28_hez_final_13.ptau` (8,192 constraints) - 19.5 MB
- `powersOfTau28_hez_final_16.ptau` (65,536 constraints) - 155 MB

**Source**: https://storage.googleapis.com/zkevm/ptau/
**Provenance**: Hermez/Polygon Powers of Tau ceremony (177 participants)

### Step 5: Generate Proving and Verification Keys

```bash
npm run --workspace=@zk-id/circuits setup
```

This executes `packages/circuits/scripts/trusted-setup.sh` which performs:

For each circuit:

1. **Setup**: `snarkjs groth16 setup <circuit>.r1cs <ptau_file> <circuit>_0000.zkey`
2. **Beacon**: `snarkjs zkey beacon <circuit>_0000.zkey <circuit>.zkey <beacon_hex> 10`
3. **Export**: `snarkjs zkey export verificationkey <circuit>.zkey <circuit>_verification_key.json`

**Deterministic Beacon** (development/testing only):

- Hex value: `0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20`
- Iterations: 10
- ⚠️ **Not secure for production** (publicly known seed)

**Output** (per circuit):

- `build/<circuit>.zkey` - Proving key (~5-150 MB depending on circuit)
- `build/<circuit>_verification_key.json` - Verification key (~1-2 KB)

### Step 6: Generate Artifact Hashes

```bash
npm run --workspace=@zk-id/circuits generate-hashes > docs/circuit-hashes.json
```

This computes SHA-256 hashes of all build artifacts.

### Step 7: Verify Hashes

```bash
bash packages/circuits/scripts/verify-hashes.sh
```

**Expected output**:

```
✓ age-verify: Cryptographic artifacts verified (zkey, verification key)
✓ credential-hash: Cryptographic artifacts verified (zkey, verification key)
✓ nationality-verify: Cryptographic artifacts verified (zkey, verification key)
✓ age-verify-signed: Cryptographic artifacts verified (zkey, verification key)
✓ nationality-verify-signed: Cryptographic artifacts verified (zkey, verification key)
✓ age-verify-revocable: Cryptographic artifacts verified (zkey, verification key)
✓ nullifier: Cryptographic artifacts verified (zkey, verification key)

✓ All cryptographic artifacts verified successfully
```

---

## Circuit Artifact Hashes (v0.6.0)

Reference hashes for verification:

| Circuit                   | zkey SHA-256                                                       | Verification Key SHA-256                                           |
| ------------------------- | ------------------------------------------------------------------ | ------------------------------------------------------------------ |
| age-verify                | `c2e99f334c4ef2884e151856645961b35092be423afdd7dbe667643226a8b643` | `5f33a5fdaf9ff8031b6ce71264b140db0ce1f1073ed2531f562d4cf0e997b185` |
| age-verify-signed         | `dcae79c18b28498fc3a2dea8a09cee787aa00849366b997b590ce9b7725c1973` | `fbced27c62f0cd36b6139d3086b96b17d2090c763a2c24e71c38d2882188e730` |
| age-verify-revocable      | `f50e6ef51912392252f2f7c09c068f3a5aa6fd5a4ea16d13eccc4baf47fa42d3` | `31fd45aa6a48f5aaa8d6a44459d17fb007d83b0da44f5650aff122bdedbe9ea3` |
| nationality-verify        | `ef7e54ddf62bb8fa13fccad34418509fc63be7cdc671ae7f98dbc2ea5c91f712` | `8dfb1965ddd0123b936cf5bcc1881eb217d0989c19451b3ea171aad3fc9e37b2` |
| nationality-verify-signed | `d1c505529af9d0ef5d236395856ee1db6520906c3f91a8652e2f61f634353c4b` | `97a957ad4538977db5bee45bcee8d919e1071d3ce0f427250c1bf738ea95e68f` |
| credential-hash           | `152f22944e2ebe11c9d607ae64f9c32da366a994a68a4fe931b75c39650c05fb` | `6ba8171dffa42b8840ff7c8f47eca6f726d241c4c4054e5aeeec477473746d2b` |
| nullifier                 | `b3361efc978be6da6898e471414889923d1d63a3bcd21ab7b301cec81faf9189` | `d5b663c06e59b79a18e31ba25ac1ad8f07b8b50c66da08cee229bfd0494ee1ea` |

Full hashes including WASM files: `docs/circuit-hashes.json`

---

## Determinism and Platform Differences

### Deterministic Outputs

The following are **deterministic** and should match exactly across platforms:

- ✅ R1CS files (`.r1cs`)
- ✅ Proving keys (`.zkey`) - **security-critical**
- ✅ Verification keys (`_verification_key.json`) - **security-critical**

### Non-Deterministic Outputs

The following may differ across platforms/compilers:

- ⚠️ WASM files (`.wasm`) - Circom v2.x WASM generation is not cross-platform deterministic
- ⚠️ Symbol files (`.sym`) - May include platform-specific paths

**Verification Strategy**: The `verify-hashes.sh` script only verifies zkey and verification key hashes, skipping WASM files.

### Why WASM Differs

Circom v2.x uses Rust's WebAssembly backend, which may produce different byte layouts on:

- Different architectures (x86_64 vs aarch64)
- Different OS (Linux vs macOS vs Windows)
- Different compiler versions (rustc version)

This does **NOT** affect security, as WASM is only used for witness generation (off-chain). The proving and verification keys are deterministic and security-critical.

---

## Troubleshooting

### Hash Mismatch

If `verify-hashes.sh` fails:

1. **Check versions**:

   ```bash
   circom --version    # Should be 0.5.46
   npx snarkjs --version  # Should be 0.7.6
   ```

2. **Check platform**: Note that canonical hashes are generated on macOS arm64. Platform differences in WASM are expected.

3. **Check git ref**:

   ```bash
   git rev-parse HEAD  # Should match expected commit
   git status          # Should be clean
   ```

4. **Clean rebuild**:

   ```bash
   rm -rf packages/circuits/build
   npm run compile:circuits
   npm run --workspace=@zk-id/circuits setup
   ```

5. **Verify Powers of Tau**:
   ```bash
   shasum -a 256 packages/circuits/build/pot/*.ptau
   # Compare against Hermez ceremony hashes
   ```

### Version Mismatches

If you have a different circom or snarkjs version:

```bash
# Uninstall current circom
cargo uninstall circom

# Install exact version
cargo install --git https://github.com/iden3/circom.git --tag v0.5.46

# Verify
circom --version
```

For snarkjs, it's locked in `package-lock.json`, so `npm install` should get the right version.

---

## CI/CD Integration

zk-id includes GitHub Actions workflows that:

1. Compile circuits from scratch
2. Run trusted setup
3. Generate hashes
4. Verify against committed `docs/circuit-hashes.json`
5. Fail if hashes don't match (indicates non-reproducible build or uncommitted changes)

See `.github/workflows/` for implementation details.

---

## Security Implications

### Why Reproducibility Matters

Reproducible builds allow third parties to:

1. **Verify integrity**: Confirm build artifacts match published source
2. **Detect tampering**: Identify if published artifacts have been modified
3. **Audit supply chain**: Ensure no malicious code injected during build
4. **Trust but verify**: Don't trust published keys - rebuild and verify

### Verification Workflow

For production deployments, third parties SHOULD:

1. Clone repository at specific git tag
2. Verify git signatures (if available)
3. Follow this reproducible build guide
4. Compare generated hashes against `docs/circuit-hashes.json`
5. **Only use artifacts that match** published hashes

### Known Limitations

- **WASM non-determinism**: Accept that WASM may differ; it's not security-critical
- **Platform dependencies**: Some platform-specific differences are expected
- **Build environment**: Exact node/npm versions may affect dependency resolution

---

## References

- [Circom Documentation](https://docs.circom.io/)
- [snarkjs Documentation](https://github.com/iden3/snarkjs)
- [Reproducible Builds Project](https://reproducible-builds.org/)
- [Hermez Powers of Tau](https://github.com/hermeznetwork/phase1-setup)

---

## Changelog

- **v0.6.0** (2026-02-09): Initial documentation
  - 7 circuits documented
  - Reference hashes for macOS arm64
  - Deterministic beacon setup (development only)
  - circom 0.5.46, snarkjs 0.7.6
