# ZK-ID Examples

This directory contains example applications demonstrating zk-id functionality.

## Web Application Demo

**Location:** `web-app/`

A full-featured web application demonstrating zero-knowledge identity verification with:

- **Age Verification**: Prove you meet age requirements without revealing your exact age
- **Nationality Verification**: Prove your nationality without exposing other attributes
- **Credential Issuance**: Issue test credentials with birth year and nationality
- **Revocation Support**: Demonstrate credential revocation
- **Multiple Proof Types**: Standard, signed (in-circuit), and revocable proofs

### Running the Web Demo

1. **Prerequisites**: Circuits must be compiled first
   ```bash
   # From repository root
   npm run compile:circuits
   npm run --workspace=@zk-id/circuits setup
   ```

2. **Start the server**:
   ```bash
   cd examples/web-app
   npm start
   ```

3. **Open browser**: Navigate to `http://localhost:3000`

### Features

- **Client-side proof generation**: ZK proofs run entirely in the browser using WebAssembly
- **Privacy-first architecture**: Credential data never sent to server
- Server-side proof verification only
- Interactive UI for testing age and nationality verification
- Performance metrics and timing information
- Privacy-preserving selective disclosure

### Architecture

- **Backend**: Express server handling verification only (no proof generation)
- **Frontend**: Browser-based proof generation using snarkjs + WASM
- **Proof System**: Groth16 on BN128 curve via snarkjs
- **Circuits**: Circom circuits served as static assets, executed client-side

### Security Notes

- This is a **demo application** for educational purposes
- Uses in-memory storage (not production-ready)
- Implements basic rate limiting
- Real deployments require proper key management and database storage
