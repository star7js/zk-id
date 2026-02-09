#!/bin/bash
set -e

CIRCUITS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="$CIRCUITS_DIR/build"

# Check if build directory exists
if [ ! -d "$BUILD_DIR" ]; then
  echo "Error: Build directory not found. Run 'npm run compile' first." >&2
  exit 1
fi

# Get versions
CIRCOM_VERSION=$(circom --version 2>/dev/null | head -n1 || echo "unknown")
SNARKJS_VERSION=$(node -e "console.log(require('$CIRCUITS_DIR/../../node_modules/snarkjs/package.json').version)" 2>/dev/null || echo "unknown")

# Circuit names
CIRCUITS=(
  "age-verify"
  "credential-hash"
  "nationality-verify"
  "age-verify-signed"
  "nationality-verify-signed"
  "age-verify-revocable"
  "nullifier"
)

# Start JSON output
echo "{"
echo "  \"algorithm\": \"SHA-256\","
echo "  \"circomVersion\": \"$CIRCOM_VERSION\","
echo "  \"snarkjsVersion\": \"$SNARKJS_VERSION\","
echo "  \"generatedAt\": \"$(date -u +"%Y-%m-%dT%H:%M:%SZ")\","
echo "  \"circuits\": {"

# Process each circuit
for i in "${!CIRCUITS[@]}"; do
  CIRCUIT="${CIRCUITS[$i]}"

  # Compute hashes
  WASM_FILE="$BUILD_DIR/${CIRCUIT}_js/${CIRCUIT}.wasm"
  ZKEY_FILE="$BUILD_DIR/${CIRCUIT}.zkey"
  VKEY_FILE="$BUILD_DIR/${CIRCUIT}_verification_key.json"

  if [ ! -f "$WASM_FILE" ]; then
    echo "Error: WASM file not found: $WASM_FILE" >&2
    exit 1
  fi
  if [ ! -f "$ZKEY_FILE" ]; then
    echo "Error: ZKEY file not found: $ZKEY_FILE" >&2
    exit 1
  fi
  if [ ! -f "$VKEY_FILE" ]; then
    echo "Error: Verification key file not found: $VKEY_FILE" >&2
    exit 1
  fi

  WASM_HASH=$(shasum -a 256 "$WASM_FILE" | awk '{print $1}')
  ZKEY_HASH=$(shasum -a 256 "$ZKEY_FILE" | awk '{print $1}')
  VKEY_HASH=$(shasum -a 256 "$VKEY_FILE" | awk '{print $1}')

  # Output circuit entry
  echo "    \"$CIRCUIT\": {"
  echo "      \"wasm\": \"$WASM_HASH\","
  echo "      \"zkey\": \"$ZKEY_HASH\","
  echo "      \"verificationKey\": \"$VKEY_HASH\""

  # Add comma if not last circuit
  if [ $i -lt $((${#CIRCUITS[@]} - 1)) ]; then
    echo "    },"
  else
    echo "    }"
  fi
done

echo "  }"
echo "}"
