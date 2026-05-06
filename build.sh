#!/usr/bin/env bash
# Blue Team Trainer — top-level build orchestrator.
#
# Runs the full pipeline end to end:
#   1. import-atomics.py    pulls upstream Atomic Red Team data
#   2. build-techniques.py  merges upstream + your curation overlay
#   3. build-html.py        builds the standalone HTML with data embedded
#
# Usage:
#     ./build.sh             # full build (pulls latest from upstream)
#     ./build.sh --offline   # skip git pull (use existing checkout)
#     ./build.sh --html-only # skip data pipeline (faster for UI work)
#
# First-time build pulls ~80 MB of YAML from atomic-red-team into .cache/.
# Subsequent runs are fast (a few seconds total) because git pull is incremental.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# -------- Argument parsing -------------------------------------------------
OFFLINE=0
HTML_ONLY=0
for arg in "$@"; do
    case "$arg" in
        --offline)   OFFLINE=1 ;;
        --html-only) HTML_ONLY=1 ;;
        --help|-h)
            sed -n '2,17p' "$0" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *)
            echo "Unknown argument: $arg" >&2
            echo "Run './build.sh --help' for usage." >&2
            exit 1
            ;;
    esac
done

# -------- Locate Python ----------------------------------------------------
if command -v python3 >/dev/null 2>&1; then
    PYTHON=python3
elif command -v python >/dev/null 2>&1; then
    PYTHON=python
else
    echo "Error: Python 3 not found on PATH." >&2
    exit 1
fi

# -------- Helpers ----------------------------------------------------------
heading() {
    printf '\n\033[1;36m▌\033[0m \033[1m%s\033[0m\n' "$1"
}

# -------- Pipeline ---------------------------------------------------------

if [[ "$HTML_ONLY" -eq 0 ]]; then
    if [[ ! -f tools/import-atomics.py ]]; then
        echo "Error: tools/import-atomics.py not found. Run from the repo root." >&2
        exit 1
    fi

    heading "1/3  Importing upstream Atomic Red Team data"
    if [[ "$OFFLINE" -eq 1 ]]; then
        "$PYTHON" tools/import-atomics.py --no-pull
    else
        "$PYTHON" tools/import-atomics.py
    fi

    heading "2/3  Merging curation overlay"
    "$PYTHON" tools/build-techniques.py
fi

heading "$([ "$HTML_ONLY" -eq 1 ] && echo '1/1' || echo '3/3')  Building standalone HTML"
"$PYTHON" build-html.py

heading "Build complete"
echo "  Open blueteam-trainer.html in a browser, or run ./run-all.sh"
