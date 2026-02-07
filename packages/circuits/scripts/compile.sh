#!/bin/bash
set -e

echo "Compiling Circom circuits..."

CIRCUITS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="$CIRCUITS_DIR/build"
SRC_DIR="$CIRCUITS_DIR/src"
ROOT_DIR="$CIRCUITS_DIR/../.."

# Use cargo-installed circom 2.x if available
CIRCOM="${HOME}/.cargo/bin/circom"
if [ ! -f "$CIRCOM" ]; then
  CIRCOM="circom"
fi

mkdir -p "$BUILD_DIR"

# Compile age-verify circuit
echo "Compiling age-verify.circom..."
"$CIRCOM" "$SRC_DIR/age-verify.circom" \
  --r1cs \
  --wasm \
  --sym \
  -o "$BUILD_DIR" \
  --prime bn128 \
  -l "$ROOT_DIR/node_modules"

# Compile credential-hash circuit
echo "Compiling credential-hash.circom..."
"$CIRCOM" "$SRC_DIR/credential-hash.circom" \
  --r1cs \
  --wasm \
  --sym \
  -o "$BUILD_DIR" \
  --prime bn128 \
  -l "$ROOT_DIR/node_modules"

# Compile nationality-verify circuit
echo "Compiling nationality-verify.circom..."
"$CIRCOM" "$SRC_DIR/nationality-verify.circom" \
  --r1cs \
  --wasm \
  --sym \
  -o "$BUILD_DIR" \
  --prime bn128 \
  -l "$ROOT_DIR/node_modules"

echo "✓ Circuits compiled successfully"
echo "Next step: Run 'npm run setup' to perform trusted setup (Powers of Tau ceremony)"
