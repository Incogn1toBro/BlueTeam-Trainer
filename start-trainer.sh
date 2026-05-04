#!/usr/bin/env bash
# Serve blueteam-trainer.html locally on http://localhost:8080
# Bypasses file:// CORS issues that prevent vendor scripts from loading.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PORT="${1:-8080}"
cd "$SCRIPT_DIR"

# Find Python
if command -v python3 >/dev/null 2>&1; then
  PYTHON=python3
elif command -v python >/dev/null 2>&1; then
  PYTHON=python
else
  echo "Python not found on PATH. Install Python 3 and re-run." >&2
  exit 1
fi

# Verify vendor libs are present
if [[ ! -f "$SCRIPT_DIR/vendor/react.production.min.js" ]]; then
  echo "Vendor libraries missing." >&2
  echo "Run ./fetch-vendor.sh first (needs internet, one time only)." >&2
  exit 1
fi

URL="http://localhost:$PORT/blueteam-trainer.html"

cat <<EOF

  ####################################################
  #                                                  #
  #   Blue Team Trainer - Local Server               #
  #                                                  #
  ####################################################

  Serving on:  $URL
  From:        $SCRIPT_DIR

  Press Ctrl+C to stop the server.

EOF

# Open browser after a short delay (best effort)
(
  sleep 2
  if command -v xdg-open >/dev/null 2>&1; then xdg-open "$URL" >/dev/null 2>&1
  elif command -v open >/dev/null 2>&1; then open "$URL" >/dev/null 2>&1
  fi
) &

exec "$PYTHON" -m http.server "$PORT" --bind 127.0.0.1
