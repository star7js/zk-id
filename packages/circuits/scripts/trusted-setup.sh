#!/bin/bash
set -e

echo "Performing trusted setup (Powers of Tau)..."

CIRCUITS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="$CIRCUITS_DIR/build"
POT_DIR="$BUILD_DIR/pot"
ROOT_DIR="$CIRCUITS_DIR/../.."

# Use npx to run snarkjs from node_modules
SNARKJS="npx snarkjs"

mkdir -p "$POT_DIR"

# Download Powers of Tau file (or generate if needed)
# For testing, we use a small ceremony (2^12 constraints = 4096)
# Production should use larger ceremonies from trusted sources

POT_FILE="$POT_DIR/powersOfTau28_hez_final_12.ptau"

if [ ! -f "$POT_FILE" ]; then
  echo "Downloading Powers of Tau file..."
  # Use the official snarkjs repository URL
  curl -L -o "$POT_FILE" https://storage.googleapis.com/zkevm/ptau/powersOfTau28_hez_final_12.ptau
fi

# Generate proving and verification keys for age-verify
echo "Generating keys for age-verify circuit..."
$SNARKJS groth16 setup \
  "$BUILD_DIR/age-verify.r1cs" \
  "$POT_FILE" \
  "$BUILD_DIR/age-verify_0000.zkey"

# Contribute to the ceremony (this should be done by multiple parties in production)
echo "Contributing randomness..."
$SNARKJS zkey contribute \
  "$BUILD_DIR/age-verify_0000.zkey" \
  "$BUILD_DIR/age-verify.zkey" \
  --name="First contribution" \
  -v \
  -e="random entropy"

# Export verification key
echo "Exporting verification key..."
$SNARKJS zkey export verificationkey \
  "$BUILD_DIR/age-verify.zkey" \
  "$BUILD_DIR/age-verify_verification_key.json"

# Generate keys for credential-hash
echo "Generating keys for credential-hash circuit..."
$SNARKJS groth16 setup \
  "$BUILD_DIR/credential-hash.r1cs" \
  "$POT_FILE" \
  "$BUILD_DIR/credential-hash_0000.zkey"

$SNARKJS zkey contribute \
  "$BUILD_DIR/credential-hash_0000.zkey" \
  "$BUILD_DIR/credential-hash.zkey" \
  --name="First contribution" \
  -v \
  -e="random entropy"

$SNARKJS zkey export verificationkey \
  "$BUILD_DIR/credential-hash.zkey" \
  "$BUILD_DIR/credential-hash_verification_key.json"

# Generate keys for nationality-verify
echo "Generating keys for nationality-verify circuit..."
$SNARKJS groth16 setup \
  "$BUILD_DIR/nationality-verify.r1cs" \
  "$POT_FILE" \
  "$BUILD_DIR/nationality-verify_0000.zkey"

$SNARKJS zkey contribute \
  "$BUILD_DIR/nationality-verify_0000.zkey" \
  "$BUILD_DIR/nationality-verify.zkey" \
  --name="First contribution" \
  -v \
  -e="random entropy"

$SNARKJS zkey export verificationkey \
  "$BUILD_DIR/nationality-verify.zkey" \
  "$BUILD_DIR/nationality-verify_verification_key.json"

# Cleanup intermediate files
rm "$BUILD_DIR"/*_0000.zkey

echo "✓ Trusted setup complete"
echo "Keys generated:"
echo "  - $BUILD_DIR/age-verify.zkey"
echo "  - $BUILD_DIR/age-verify_verification_key.json"
echo "  - $BUILD_DIR/credential-hash.zkey"
echo "  - $BUILD_DIR/credential-hash_verification_key.json"
echo "  - $BUILD_DIR/nationality-verify.zkey"
echo "  - $BUILD_DIR/nationality-verify_verification_key.json"
