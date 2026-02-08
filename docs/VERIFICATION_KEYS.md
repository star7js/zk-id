# Circuit Verification Keys and Build Reproducibility

This document describes how circuit artifacts are generated, verified, and reproduced to ensure integrity and trustworthiness of the zero-knowledge proof system.

## Build Environment

All circuit artifacts are built using the following toolchain:

- **Circom**: v2.1.8
- **snarkjs**: ^0.7.6
- **Node.js**: 20.x
- **Curve**: BN128 (bn254)
- **Platform**: Linux/macOS (deterministic across both)

## Powers of Tau Ceremony

The circuits use pre-computed Powers of Tau (PTAU) files from the Hermez/Polygon ceremony:

| Circuit | Constraints | PTAU File | Source |
|---------|-------------|-----------|--------|
| age-verify | ~2,048 | powersOfTau28_hez_final_12.ptau | Hermez Ceremony |
| credential-hash | ~2,048 | powersOfTau28_hez_final_12.ptau | Hermez Ceremony |
| nationality-verify | ~2,048 | powersOfTau28_hez_final_12.ptau | Hermez Ceremony |
| age-verify-signed | ~8,192 | powersOfTau28_hez_final_13.ptau | Hermez Ceremony |
| nationality-verify-signed | ~8,192 | powersOfTau28_hez_final_13.ptau | Hermez Ceremony |
| age-verify-revocable | ~32,768 | powersOfTau28_hez_final_16.ptau | Hermez Ceremony |

PTAU files are downloaded from:
```
https://storage.googleapis.com/zkevm/ptau/powersOfTau28_hez_final_{12,13,16}.ptau
```

These files are cached in `packages/circuits/build/pot/` and verified by hash on first download.

## Phase 2 Ceremony (Development)

⚠️ **WARNING**: The current phase 2 ceremony uses **hardcoded entropy** for development convenience. These artifacts are **NOT suitable for production use**.

The entropy is deterministic:
```
ZK-ID DEVELOPMENT ENTROPY - DO NOT USE IN PRODUCTION
```

This allows reproducible builds across CI and developer machines but provides **no security** against malicious key generation.

### Production Recommendations

For production deployments:

1. **Conduct a proper Phase 2 ceremony** with multiple participants
2. **Use hardware entropy** from trusted sources (HSMs, secure enclaves)
3. **Verify all contributions** through independent auditors
4. **Document ceremony participants** and their verification procedures
5. **Consider using a trusted setup service** (e.g., SnarkJS ceremony tools)

See [SECURITY.md](../SECURITY.md#trusted-setup-requirements) for full production ceremony requirements.

## Artifact Integrity

All 18 circuit build artifacts (6 WASM, 6 ZKEY, 6 verification keys) are tracked via SHA-256 hashes in `docs/circuit-hashes.json`.

### Manifest Structure

```json
{
  "algorithm": "SHA-256",
  "circomVersion": "0.5.46",
  "snarkjsVersion": "0.7.6",
  "generatedAt": "2026-02-08T21:22:24Z",
  "circuits": {
    "age-verify": {
      "wasm": "f1526de4c5267fe9743b70dece85569c...",
      "zkey": "948b52ff43b8b625d73ae3198ae59d1d...",
      "verificationKey": "df5809ee7688e44760d509430023d667..."
    },
    ...
  }
}
```

### Verifying Artifacts Locally

To verify that your local build artifacts match the committed hashes:

```bash
npm run verify:hashes
```

This computes SHA-256 hashes of all artifacts and compares them against `docs/circuit-hashes.json`. Any mismatch indicates:
- Circuit source code changes
- Toolchain version differences
- Build environment issues
- Potential cache corruption

### Updating the Manifest

After modifying circuit source files (`packages/circuits/src/*.circom`):

1. Rebuild all circuits:
   ```bash
   npm run compile:circuits
   npm run --workspace=@zk-id/circuits setup
   ```

2. Regenerate the hash manifest:
   ```bash
   bash packages/circuits/scripts/generate-hashes.sh > docs/circuit-hashes.json
   ```

3. Commit the updated manifest:
   ```bash
   git add docs/circuit-hashes.json
   git commit -m "Update circuit artifact hashes after [describe changes]"
   ```

## Continuous Verification

### Fast Verification (Every CI Run)

The main CI workflow (`.github/workflows/ci.yml`) verifies artifacts against the manifest on every push. This catches:
- Cache corruption
- Inconsistent build outputs
- Toolchain drift

### Full Reproducibility Check (Weekly + On Circuit Changes)

A separate workflow (`.github/workflows/verify-circuits.yml`) performs complete fresh builds:
- Triggered on circuit source changes
- Runs weekly (Monday 6AM UTC)
- Builds from scratch (no cache)
- Verifies all artifacts match committed hashes

This ensures long-term reproducibility and catches subtle build environment issues.

## Security Considerations

1. **Hash Verification**: Always run `npm run verify:hashes` after pulling changes or rebuilding circuits
2. **Toolchain Pinning**: Use exact versions of Circom and snarkjs specified above
3. **PTAU Integrity**: PTAU files are verified by hardcoded SHA-256 hashes in `trusted-setup.sh`
4. **Phase 2 Security**: Current setup is **development-only** - see production recommendations above
5. **Artifact Distribution**: Never distribute ZKEY files to untrusted parties without proper ceremony

## References

- [Hermez Powers of Tau Ceremony](https://github.com/iden3/snarkjs#powers-of-tau)
- [SnarkJS Documentation](https://github.com/iden3/snarkjs)
- [Circom Documentation](https://docs.circom.io/)
- [ZK-ID Security Policy](../SECURITY.md)
