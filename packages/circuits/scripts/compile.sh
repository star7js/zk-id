#!/bin/bash
set -e

echo "Compiling Circom circuits..."

CIRCUITS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="$CIRCUITS_DIR/build"
SRC_DIR="$CIRCUITS_DIR/src"

mkdir -p "$BUILD_DIR"

# Compile age-verify circuit
echo "Compiling age-verify.circom..."
circom "$SRC_DIR/age-verify.circom" \
  --r1cs \
  --wasm \
  --sym \
  -o "$BUILD_DIR" \
  --prime bn128

# Compile credential-hash circuit
echo "Compiling credential-hash.circom..."
circom "$SRC_DIR/credential-hash.circom" \
  --r1cs \
  --wasm \
  --sym \
  -o "$BUILD_DIR" \
  --prime bn128

echo "✓ Circuits compiled successfully"
echo "Next step: Run 'npm run setup' to perform trusted setup (Powers of Tau ceremony)"
