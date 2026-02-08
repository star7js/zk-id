#!/bin/bash
set -e

CIRCUITS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="$CIRCUITS_DIR/build"
ROOT_DIR="$CIRCUITS_DIR/../.."
MANIFEST_FILE="$ROOT_DIR/docs/circuit-hashes.json"

# Check if manifest exists
if [ ! -f "$MANIFEST_FILE" ]; then
  echo "Error: Hash manifest not found at $MANIFEST_FILE" >&2
  echo "Run 'npm run generate-hashes' to create it." >&2
  exit 1
fi

# Check if build directory exists
if [ ! -d "$BUILD_DIR" ]; then
  echo "Error: Build directory not found. Run 'npm run compile' first." >&2
  exit 1
fi

echo "Verifying circuit artifact hashes against manifest..."
echo "Note: WASM verification skipped (Circom v2.x is not cross-platform deterministic)"
echo ""

# Parse circuit names from manifest using Node
CIRCUITS=$(node -e "
  const fs = require('fs');
  const manifest = JSON.parse(fs.readFileSync('$MANIFEST_FILE', 'utf8'));
  console.log(Object.keys(manifest.circuits).join(' '));
")

FAILED=0

# Verify each circuit
for CIRCUIT in $CIRCUITS; do
  WASM_FILE="$BUILD_DIR/${CIRCUIT}_js/${CIRCUIT}.wasm"
  ZKEY_FILE="$BUILD_DIR/${CIRCUIT}.zkey"
  VKEY_FILE="$BUILD_DIR/${CIRCUIT}_verification_key.json"

  # Check file existence (WASM check is informational only)
  if [ ! -f "$WASM_FILE" ]; then
    echo "⚠ $CIRCUIT: WASM file missing (non-fatal)"
  fi
  if [ ! -f "$ZKEY_FILE" ]; then
    echo "✗ $CIRCUIT: ZKEY file missing"
    FAILED=1
    continue
  fi
  if [ ! -f "$VKEY_FILE" ]; then
    echo "✗ $CIRCUIT: Verification key file missing"
    FAILED=1
    continue
  fi

  # Compute actual hashes (skip WASM - not cross-platform deterministic)
  ACTUAL_ZKEY_HASH=$(shasum -a 256 "$ZKEY_FILE" | awk '{print $1}')
  ACTUAL_VKEY_HASH=$(shasum -a 256 "$VKEY_FILE" | awk '{print $1}')

  # Get expected hashes from manifest (skip WASM)
  EXPECTED_HASHES=$(node -e "
    const fs = require('fs');
    const manifest = JSON.parse(fs.readFileSync('$MANIFEST_FILE', 'utf8'));
    const circuit = manifest.circuits['$CIRCUIT'];
    if (!circuit) {
      console.error('Circuit not found in manifest: $CIRCUIT');
      process.exit(1);
    }
    console.log(circuit.zkey + ' ' + circuit.verificationKey);
  ")

  read EXPECTED_ZKEY_HASH EXPECTED_VKEY_HASH <<< "$EXPECTED_HASHES"

  # Compare hashes (WASM skipped - Circom v2.x not cross-platform deterministic)
  CIRCUIT_FAILED=0

  if [ "$ACTUAL_ZKEY_HASH" != "$EXPECTED_ZKEY_HASH" ]; then
    echo "✗ $CIRCUIT: ZKEY hash mismatch"
    echo "  Expected: $EXPECTED_ZKEY_HASH"
    echo "  Actual:   $ACTUAL_ZKEY_HASH"
    CIRCUIT_FAILED=1
  fi

  if [ "$ACTUAL_VKEY_HASH" != "$EXPECTED_VKEY_HASH" ]; then
    echo "✗ $CIRCUIT: Verification key hash mismatch"
    echo "  Expected: $EXPECTED_VKEY_HASH"
    echo "  Actual:   $ACTUAL_VKEY_HASH"
    CIRCUIT_FAILED=1
  fi

  if [ $CIRCUIT_FAILED -eq 0 ]; then
    echo "✓ $CIRCUIT: Cryptographic artifacts verified (zkey, verification key)"
  else
    FAILED=1
  fi
done

if [ $FAILED -eq 0 ]; then
  echo ""
  echo "✓ All cryptographic artifacts verified successfully"
  echo "  (zkey and verification key hashes match - these are the security-critical files)"
  exit 0
else
  echo ""
  echo "✗ Hash verification failed"
  echo "If you've intentionally modified circuits, regenerate the manifest with 'npm run generate-hashes'"
  exit 1
fi
