#!/usr/bin/env bash
# Blue Team Trainer - Run Everything (Ubuntu)
#
# Brings up the backend (FastAPI on :8000) and the frontend HTTP server
# (Python http.server on :8080) together in a tmux session.
#
# Layout:
#   ┌─────────────────────────────────┐
#   │  BACKEND (FastAPI)              │
#   ├─────────────────────────────────┤
#   │  FRONTEND (HTTP server)         │
#   └─────────────────────────────────┘
#
# Controls inside tmux:
#   Ctrl+B then arrow keys  - move between panes
#   Ctrl+B then D           - detach (keeps everything running in background)
#   Ctrl+B then x           - kill current pane
#   Ctrl+C                  - stop the process in the current pane
#
# Re-attach later with:  tmux attach -t bttrainer
# Stop everything:       tmux kill-session -t bttrainer
#
# Usage:
#   ./run-all.sh                  # default: backend :8000, frontend :8080
#   ./run-all.sh 8001 9090        # custom ports
#   ./run-all.sh --no-tmux        # run frontend only, foreground (debug)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# ---- Defaults ----
BACKEND_PORT="${1:-8000}"
FRONTEND_PORT="${2:-8080}"
SESSION_NAME="bttrainer"

# ---- Colours (host shell only - tmux panes will have their own) ----
if [[ -t 1 ]]; then
  RED=$'\033[31m'; GRN=$'\033[32m'; YLW=$'\033[33m'; CYN=$'\033[36m'; RST=$'\033[0m'
else
  RED=''; GRN=''; YLW=''; CYN=''; RST=''
fi

err()  { printf "${RED}[ERR]${RST} %s\n" "$1" >&2; }
warn() { printf "${YLW}[!!]${RST} %s\n" "$1"; }
ok()   { printf "${GRN}[OK]${RST} %s\n" "$1"; }

# ---------------------------------------------------------------------------
# Pre-flight checks
# ---------------------------------------------------------------------------

# Python
if command -v python3 >/dev/null 2>&1; then
  PYTHON=python3
elif command -v python >/dev/null 2>&1; then
  PYTHON=python
else
  err "Python 3 not found. Run ./setup-ubuntu.sh first."
  exit 1
fi

# Backend venv
VENV_DIR="$SCRIPT_DIR/backend/.venv"
if [[ ! -f "$VENV_DIR/bin/activate" ]]; then
  err "Backend venv missing. Run ./setup-ubuntu.sh first."
  exit 1
fi

# Backend .env
if [[ ! -f "$SCRIPT_DIR/backend/.env" ]]; then
  err "backend/.env missing. Run ./setup-ubuntu.sh first."
  exit 1
fi

# Vendor JS files
if [[ ! -f "$SCRIPT_DIR/vendor/react.production.min.js" ]]; then
  err "Frontend vendor libraries missing. Run ./setup-ubuntu.sh first."
  exit 1
fi

# tmux
if ! command -v tmux >/dev/null 2>&1; then
  err "tmux not installed. Run: sudo apt install -y tmux"
  exit 1
fi

# Port availability
check_port() {
  local port="$1"
  local label="$2"
  # Try ss first (modern), fall back to lsof, then a Python socket check
  if command -v ss >/dev/null 2>&1; then
    if ss -tln "( sport = :$port )" 2>/dev/null | grep -q LISTEN; then
      err "$label port $port already in use"
      printf "       Find what's using it:  ${CYN}ss -tlnp 'sport = :%s'${RST}\n" "$port"
      exit 1
    fi
  elif command -v lsof >/dev/null 2>&1; then
    if lsof -i :"$port" -sTCP:LISTEN >/dev/null 2>&1; then
      err "$label port $port already in use"
      exit 1
    fi
  fi
}
check_port "$BACKEND_PORT" "Backend"
check_port "$FRONTEND_PORT" "Frontend"

# Existing session?
if tmux has-session -t "$SESSION_NAME" 2>/dev/null; then
  warn "tmux session '$SESSION_NAME' already running"
  read -rp "Kill it and restart? [y/N] " yn
  if [[ "${yn:-N}" =~ ^[Yy]$ ]]; then
    tmux kill-session -t "$SESSION_NAME"
    ok "Old session killed"
  else
    printf "Attach with:  ${CYN}tmux attach -t %s${RST}\n" "$SESSION_NAME"
    exit 0
  fi
fi

# ---------------------------------------------------------------------------
# Banner
# ---------------------------------------------------------------------------

cat <<EOF

  ####################################################
  #                                                  #
  #   Blue Team Trainer - Starting Platform        #
  #                                                  #
  ####################################################

  Backend  : http://localhost:${BACKEND_PORT}
  Frontend : http://localhost:${FRONTEND_PORT}/blueteam-trainer.html
  Session  : ${SESSION_NAME}

EOF

# ---------------------------------------------------------------------------
# Build commands that run inside each pane
# ---------------------------------------------------------------------------

# Backend pane: activate venv, run uvicorn with reload off (production-ish)
BACKEND_CMD="cd '$SCRIPT_DIR/backend' && \
source .venv/bin/activate && \
echo '=== BACKEND - FastAPI on port ${BACKEND_PORT} ===' && \
echo '=== Logs:                                    ===' && \
exec uvicorn main:app --host 0.0.0.0 --port ${BACKEND_PORT}"

# Frontend pane: simple Python http.server
FRONTEND_CMD="cd '$SCRIPT_DIR' && \
echo '=== FRONTEND - http://localhost:${FRONTEND_PORT}/blueteam-trainer.html ===' && \
echo '=== Access logs:                                                  ===' && \
exec ${PYTHON} -m http.server ${FRONTEND_PORT} --bind 127.0.0.1"

# ---------------------------------------------------------------------------
# Build the tmux session
# ---------------------------------------------------------------------------

# Window 0 = backend (top pane)
tmux new-session  -d -s "$SESSION_NAME" -n trainer "$BACKEND_CMD"

# Split horizontally - frontend goes in bottom pane
tmux split-window -t "$SESSION_NAME":0 -v "$FRONTEND_CMD"

# Make pane sizes roughly equal
tmux select-layout -t "$SESSION_NAME":0 even-vertical

# Start in the backend (top) pane
tmux select-pane -t "$SESSION_NAME":0.0

# ---------------------------------------------------------------------------
# Open browser after a short delay (best effort)
# ---------------------------------------------------------------------------
URL="http://localhost:${FRONTEND_PORT}/blueteam-trainer.html"
(
  sleep 3
  if   command -v xdg-open >/dev/null 2>&1; then xdg-open "$URL" >/dev/null 2>&1
  elif command -v gnome-open >/dev/null 2>&1; then gnome-open "$URL" >/dev/null 2>&1
  elif command -v firefox >/dev/null 2>&1; then firefox "$URL" >/dev/null 2>&1 &
  fi
) &

# ---------------------------------------------------------------------------
# Hand over to the user
# ---------------------------------------------------------------------------

cat <<EOF
${GRN}Started.${RST}

  Inside tmux:
    Ctrl+B then ↑/↓     - move between panes
    Ctrl+B then D       - detach (everything keeps running)
    Ctrl+C in a pane    - stop that service

  From outside:
    tmux attach -t $SESSION_NAME      - re-attach to the session
    tmux kill-session -t $SESSION_NAME - stop everything

  Attaching now...

EOF

sleep 1
exec tmux attach -t "$SESSION_NAME"
