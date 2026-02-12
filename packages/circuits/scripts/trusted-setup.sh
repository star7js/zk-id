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

POT_FILE_SMALL="$POT_DIR/powersOfTau28_hez_final_12.ptau"
POT_FILE_MEDIUM="$POT_DIR/powersOfTau28_hez_final_13.ptau"
POT_FILE_LARGE="$POT_DIR/powersOfTau28_hez_final_16.ptau"

if [ ! -f "$POT_FILE_SMALL" ]; then
  echo "Downloading Powers of Tau (small) file..."
  curl -L -o "$POT_FILE_SMALL" https://storage.googleapis.com/zkevm/ptau/powersOfTau28_hez_final_12.ptau
fi

if [ ! -f "$POT_FILE_MEDIUM" ]; then
  echo "Downloading Powers of Tau (medium) file..."
  curl -L -o "$POT_FILE_MEDIUM" https://storage.googleapis.com/zkevm/ptau/powersOfTau28_hez_final_13.ptau
fi

if [ ! -f "$POT_FILE_LARGE" ]; then
  echo "Downloading Powers of Tau (large) file..."
  curl -L -o "$POT_FILE_LARGE" https://storage.googleapis.com/zkevm/ptau/powersOfTau28_hez_final_16.ptau
fi

# Generate proving and verification keys for age-verify
echo "Generating keys for age-verify circuit..."
$SNARKJS groth16 setup \
  "$BUILD_DIR/age-verify.r1cs" \
  "$POT_FILE_SMALL" \
  "$BUILD_DIR/age-verify_0000.zkey"

# Apply deterministic beacon for reproducible dev/CI builds
# Production should use a proper multi-party ceremony with multiple contributors
echo "Applying beacon (deterministic)..."
$SNARKJS zkey beacon \
  "$BUILD_DIR/age-verify_0000.zkey" \
  "$BUILD_DIR/age-verify.zkey" \
  0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20 10 \
  --name="Final beacon phase2"

# Export verification key
echo "Exporting verification key..."
$SNARKJS zkey export verificationkey \
  "$BUILD_DIR/age-verify.zkey" \
  "$BUILD_DIR/age-verify_verification_key.json"

# Generate keys for credential-hash
echo "Generating keys for credential-hash circuit..."
$SNARKJS groth16 setup \
  "$BUILD_DIR/credential-hash.r1cs" \
  "$POT_FILE_SMALL" \
  "$BUILD_DIR/credential-hash_0000.zkey"

$SNARKJS zkey beacon \
  "$BUILD_DIR/credential-hash_0000.zkey" \
  "$BUILD_DIR/credential-hash.zkey" \
  0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20 10 \
  --name="Final beacon phase2"

$SNARKJS zkey export verificationkey \
  "$BUILD_DIR/credential-hash.zkey" \
  "$BUILD_DIR/credential-hash_verification_key.json"

# Generate keys for nationality-verify
echo "Generating keys for nationality-verify circuit..."
$SNARKJS groth16 setup \
  "$BUILD_DIR/nationality-verify.r1cs" \
  "$POT_FILE_SMALL" \
  "$BUILD_DIR/nationality-verify_0000.zkey"

$SNARKJS zkey beacon \
  "$BUILD_DIR/nationality-verify_0000.zkey" \
  "$BUILD_DIR/nationality-verify.zkey" \
  0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20 10 \
  --name="Final beacon phase2"

$SNARKJS zkey export verificationkey \
  "$BUILD_DIR/nationality-verify.zkey" \
  "$BUILD_DIR/nationality-verify_verification_key.json"

# Generate keys for age-verify-signed
echo "Generating keys for age-verify-signed circuit..."
$SNARKJS groth16 setup \
  "$BUILD_DIR/age-verify-signed.r1cs" \
  "$POT_FILE_LARGE" \
  "$BUILD_DIR/age-verify-signed_0000.zkey"

$SNARKJS zkey beacon \
  "$BUILD_DIR/age-verify-signed_0000.zkey" \
  "$BUILD_DIR/age-verify-signed.zkey" \
  0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20 10 \
  --name="Final beacon phase2"

$SNARKJS zkey export verificationkey \
  "$BUILD_DIR/age-verify-signed.zkey" \
  "$BUILD_DIR/age-verify-signed_verification_key.json"

# Generate keys for nationality-verify-signed
echo "Generating keys for nationality-verify-signed circuit..."
$SNARKJS groth16 setup \
  "$BUILD_DIR/nationality-verify-signed.r1cs" \
  "$POT_FILE_LARGE" \
  "$BUILD_DIR/nationality-verify-signed_0000.zkey"

$SNARKJS zkey beacon \
  "$BUILD_DIR/nationality-verify-signed_0000.zkey" \
  "$BUILD_DIR/nationality-verify-signed.zkey" \
  0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20 10 \
  --name="Final beacon phase2"

$SNARKJS zkey export verificationkey \
  "$BUILD_DIR/nationality-verify-signed.zkey" \
  "$BUILD_DIR/nationality-verify-signed_verification_key.json"

# Generate keys for age-verify-revocable
echo "Generating keys for age-verify-revocable circuit..."
$SNARKJS groth16 setup \
  "$BUILD_DIR/age-verify-revocable.r1cs" \
  "$POT_FILE_MEDIUM" \
  "$BUILD_DIR/age-verify-revocable_0000.zkey"

$SNARKJS zkey beacon \
  "$BUILD_DIR/age-verify-revocable_0000.zkey" \
  "$BUILD_DIR/age-verify-revocable.zkey" \
  0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20 10 \
  --name="Final beacon phase2"

$SNARKJS zkey export verificationkey \
  "$BUILD_DIR/age-verify-revocable.zkey" \
  "$BUILD_DIR/age-verify-revocable_verification_key.json"

# Generate keys for nullifier
echo "Generating keys for nullifier circuit..."
$SNARKJS groth16 setup \
  "$BUILD_DIR/nullifier.r1cs" \
  "$POT_FILE_SMALL" \
  "$BUILD_DIR/nullifier_0000.zkey"

$SNARKJS zkey beacon \
  "$BUILD_DIR/nullifier_0000.zkey" \
  "$BUILD_DIR/nullifier.zkey" \
  0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20 10 \
  --name="Final beacon phase2"

$SNARKJS zkey export verificationkey \
  "$BUILD_DIR/nullifier.zkey" \
  "$BUILD_DIR/nullifier_verification_key.json"

# Generate keys for predicate
echo "Generating keys for predicate circuit..."
$SNARKJS groth16 setup \
  "$BUILD_DIR/predicate.r1cs" \
  "$POT_FILE_MEDIUM" \
  "$BUILD_DIR/predicate_0000.zkey"

$SNARKJS zkey beacon \
  "$BUILD_DIR/predicate_0000.zkey" \
  "$BUILD_DIR/predicate.zkey" \
  0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20 10 \
  --name="Final beacon phase2"

$SNARKJS zkey export verificationkey \
  "$BUILD_DIR/predicate.zkey" \
  "$BUILD_DIR/predicate_verification_key.json"

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
echo "  - $BUILD_DIR/age-verify-signed.zkey"
echo "  - $BUILD_DIR/age-verify-signed_verification_key.json"
echo "  - $BUILD_DIR/nationality-verify-signed.zkey"
echo "  - $BUILD_DIR/nationality-verify-signed_verification_key.json"
echo "  - $BUILD_DIR/age-verify-revocable.zkey"
echo "  - $BUILD_DIR/age-verify-revocable_verification_key.json"
echo "  - $BUILD_DIR/nullifier.zkey"
echo "  - $BUILD_DIR/nullifier_verification_key.json"
echo "  - $BUILD_DIR/predicate.zkey"
echo "  - $BUILD_DIR/predicate_verification_key.json"
