# @zk-id/circuits

**Circom zero-knowledge circuits for identity verification**

This package provides seven Circom circuits for age verification, nationality verification, credential hashing, nullifier computation, and Merkle tree inclusion. It includes compiled WASM, zkey, and verification key build artifacts for Groth16 proving.

## Circuits

| Circuit | Purpose | Constraints | Public Signals |
|---------|---------|------------|----------------|
| `credential-hash` | Poseidon commitment | 605 | `credentialHash` |
| `age-verify` | Age >= minAge | 653 | `currentYear`, `minAge`, `credentialHash`, `nonce`, `requestTimestamp` |
| `nationality-verify` | Nationality match | 608 | `targetNationality`, `credentialHash`, `nonce`, `requestTimestamp` |
| `age-verify-signed` | Age + EdDSA sig | 20,621 | + 256 issuer pubkey bits |
| `nationality-verify-signed` | Nationality + EdDSA sig | 20,576 | + 256 issuer pubkey bits |
| `age-verify-revocable` | Age + Merkle inclusion | 5,883 | + `merkleRoot` |
| `nullifier` | Sybil-resistance | 1,122 | `credentialHash`, `scopeHash`, `nullifier` |

Constraint counts are for v0.6.0. See `docs/CIRCUIT-COMPLEXITY.md` for detailed breakdown.

## Installation

```bash
npm install @zk-id/circuits
```

**Note:** This package ships pre-compiled build artifacts (~44 MB). No compilation needed for consumers.

## Usage from Code

Resolve circuit artifact paths using `require.resolve`:

```typescript
const wasmPath = require.resolve('@zk-id/circuits/build/age-verify_js/age-verify.wasm');
const zkeyPath = require.resolve('@zk-id/circuits/build/age-verify.zkey');

// Or use the *Auto functions from @zk-id/core which handle path resolution automatically
import { generateAgeProofAuto } from '@zk-id/core';
const proof = await generateAgeProofAuto(credential, minAge, nonce, timestamp);
```

## Building from Source

### Prerequisites

- circom 0.5.46 or later
- Rust toolchain (for circom compilation)
- snarkjs 0.7.6 or later
- Node.js 18+

### Build Steps

```bash
# 1. Compile circuits (.circom → .wasm + .r1cs)
npm run compile

# 2. Trusted setup (generates .zkey + verification_key.json)
npm run setup

# 3. Verify artifact integrity (checks SHA-256 hashes)
npm run verify-hashes
```

**Note:** The setup phase downloads Powers of Tau files (~155 MB for signed circuits).

## Build Artifacts

Each circuit produces:

- **`.wasm`** — WebAssembly witness generator (runs in Node.js or browser)
- **`.r1cs`** — Rank-1 constraint system (circuit definition)
- **`.zkey`** — Proving key (includes circuit constraints + trusted setup parameters)
- **`verification_key.json`** — Verification key (for off-chain and on-chain verification)

Artifacts are in `build/` directory after compilation.

## Security Notes

### Development Powers of Tau

This package uses development Powers of Tau ceremonies from the Hermez project. **These are NOT suitable for production use.**

For production deployments:
1. Participate in or run a production Powers of Tau ceremony
2. Recompile circuits using production `ptau` files
3. Regenerate all `.zkey` and verification keys
4. Audit circuit logic and constraints

See `docs/TRUSTED-SETUP.md` for details.

### Platform-Dependent Artifact Hashes

Circuit artifact hashes are **platform-dependent** due to:
- circom compiler differences (macOS vs Linux)
- WASM binary format variations
- ptau file endianness

The `verify-hashes` script checks hashes but allows for platform differences. Always verify artifact integrity from your CI/CD pipeline.

### Merkle Tree Depth Hardcoded

The `age-verify-revocable` circuit uses a **hardcoded Merkle tree depth of 10** (1,024 max leaves). If you need more credentials, you must:
1. Modify the circuit to increase depth
2. Recompile with larger Powers of Tau
3. Regenerate proving and verification keys
4. Update verifier contracts

### EdDSA Signed Circuits

The signed circuits (`age-verify-signed`, `nationality-verify-signed`) use BabyJub EdDSA, which adds ~20k constraints (~15s proving time). These are designed for trustless verification scenarios where maintaining an issuer registry is impractical.

## Testing

```bash
npm test
```

Tests use `circom_tester` to verify witness generation and proof validity for all circuits.

## Related Packages

- `@zk-id/core` — Generate and verify proofs using these circuits
- `@zk-id/contracts` — Solidity verifier contracts for on-chain verification
- `@zk-id/sdk` — Server-side verification SDK

## License

Apache-2.0
