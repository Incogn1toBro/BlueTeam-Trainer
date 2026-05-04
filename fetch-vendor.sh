#!/usr/bin/env bash
# Download React + Babel UMD bundles for offline use of blueteam-trainer.html
#
# Run this ONCE on a machine with internet access. It populates ./vendor
# with the three JS files the HTML needs. After running, you can copy the
# whole folder onto an air-gapped laptop and the HTML will work offline.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENDOR_DIR="$SCRIPT_DIR/vendor"
mkdir -p "$VENDOR_DIR"

declare -A FILES=(
  ["react.production.min.js"]="https://unpkg.com/react@18.3.1/umd/react.production.min.js"
  ["react-dom.production.min.js"]="https://unpkg.com/react-dom@18.3.1/umd/react-dom.production.min.js"
  ["babel.min.js"]="https://unpkg.com/@babel/standalone@7.25.6/babel.min.js"
)

echo
echo "Fetching vendor libraries to $VENDOR_DIR"
echo

for name in "${!FILES[@]}"; do
  dest="$VENDOR_DIR/$name"
  if [[ -f "$dest" ]]; then
    echo "  [SKIP] $name already present"
    continue
  fi
  echo -n "  [GET ] $name"
  if curl -fsSL "${FILES[$name]}" -o "$dest"; then
    size=$(du -k "$dest" | awk '{print $1}')
    echo "  (${size} KB)"
  else
    echo "  FAILED"
    exit 1
  fi
done

echo
echo "Done. You can now open blueteam-trainer.html in any browser."
echo "To use on an air-gapped machine, copy the entire folder (including ./vendor)."
