#!/usr/bin/env bash
# Blue Team Trainer - One-time setup for Ubuntu 25.10
#
# Run this ONCE on the Ubuntu laptop. It will:
#   1. Verify Python 3, pip, venv, curl, and tmux are installed
#   2. Create a Python venv in backend/.venv and install requirements
#   3. Fetch the React + Babel vendor libraries (needs internet)
#   4. Set up backend/.env from the template if missing
#
# After this completes, run ./run-all.sh to start the platform.
#
# Tested on Ubuntu 25.10. Should also work on 22.04+ and Debian 12+.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# ---- Colours ----
if [[ -t 1 ]]; then
  RED=$'\033[31m'; GRN=$'\033[32m'; YLW=$'\033[33m'; CYN=$'\033[36m'; DIM=$'\033[2m'; RST=$'\033[0m'
else
  RED=''; GRN=''; YLW=''; CYN=''; DIM=''; RST=''
fi

step() { printf "\n${CYN}==>${RST} %s\n" "$1"; }
ok()   { printf "    ${GRN}[OK]${RST} %s\n" "$1"; }
warn() { printf "    ${YLW}[!!]${RST} %s\n" "$1"; }
err()  { printf "    ${RED}[ERR]${RST} %s\n" "$1" >&2; }

cat <<EOF

  ####################################################
  #                                                  #
  #   Blue Team Trainer - Ubuntu Setup             #
  #                                                  #
  ####################################################
EOF

# ---------------------------------------------------------------------------
# 1. Verify required system packages
# ---------------------------------------------------------------------------
step "Checking system prerequisites"

NEEDED_PKGS=()

check_cmd() {
  local cmd="$1"
  local pkg="$2"
  if ! command -v "$cmd" >/dev/null 2>&1; then
    warn "$cmd not found - need to apt install $pkg"
    NEEDED_PKGS+=("$pkg")
  else
    ok "$cmd present"
  fi
}

check_cmd python3 python3
check_cmd pip3 python3-pip
check_cmd curl curl
check_cmd tmux tmux

# venv module check (it's part of python3 but ships separately on Ubuntu)
if ! python3 -c "import venv" 2>/dev/null; then
  warn "python3-venv module not available"
  NEEDED_PKGS+=("python3-venv")
else
  ok "python3-venv present"
fi

# ensurepip check (needed inside venv for pip to work)
if ! python3 -c "import ensurepip" 2>/dev/null; then
  warn "python3 ensurepip module missing"
  NEEDED_PKGS+=("python3-venv")
fi

if [[ ${#NEEDED_PKGS[@]} -gt 0 ]]; then
  # de-duplicate
  UNIQ_PKGS=($(printf "%s\n" "${NEEDED_PKGS[@]}" | sort -u))
  printf "\n${YLW}Missing packages: ${UNIQ_PKGS[*]}${RST}\n"
  printf "Run:  ${CYN}sudo apt update && sudo apt install -y %s${RST}\n\n" "${UNIQ_PKGS[*]}"
  read -rp "Install them now (requires sudo)? [Y/n] " yn
  yn=${yn:-Y}
  if [[ "$yn" =~ ^[Yy]$ ]]; then
    sudo apt update
    sudo apt install -y "${UNIQ_PKGS[@]}"
    ok "Packages installed"
  else
    err "Cannot continue without these packages"
    exit 1
  fi
fi

# ---------------------------------------------------------------------------
# 2. Create backend venv and install requirements
# ---------------------------------------------------------------------------
step "Setting up backend Python virtual environment"

VENV_DIR="$SCRIPT_DIR/backend/.venv"
if [[ ! -d "$VENV_DIR" ]]; then
  python3 -m venv "$VENV_DIR"
  ok "Created venv at backend/.venv"
else
  ok "Venv already exists at backend/.venv"
fi

# Activate and install
# shellcheck disable=SC1091
source "$VENV_DIR/bin/activate"
pip install --quiet --upgrade pip
pip install --quiet -r "$SCRIPT_DIR/backend/requirements.txt"
ok "Python dependencies installed"
deactivate

# ---------------------------------------------------------------------------
# 3. Fetch vendor JS libraries
# ---------------------------------------------------------------------------
step "Fetching frontend vendor libraries"

VENDOR_DIR="$SCRIPT_DIR/vendor"
mkdir -p "$VENDOR_DIR"

declare -A FILES=(
  ["react.production.min.js"]="https://unpkg.com/react@18.3.1/umd/react.production.min.js"
  ["react-dom.production.min.js"]="https://unpkg.com/react-dom@18.3.1/umd/react-dom.production.min.js"
  ["babel.min.js"]="https://unpkg.com/@babel/standalone@7.25.6/babel.min.js"
)

for name in "${!FILES[@]}"; do
  dest="$VENDOR_DIR/$name"
  if [[ -f "$dest" && -s "$dest" ]]; then
    ok "$name (already present)"
    continue
  fi
  if curl -fsSL "${FILES[$name]}" -o "$dest"; then
    size=$(du -k "$dest" | awk '{print $1}')
    ok "$name (${size} KB)"
  else
    err "Failed to download $name"
    err "If this laptop is offline, run fetch-vendor.sh on a machine with internet"
    err "and copy the ./vendor folder over."
    exit 1
  fi
done

# ---------------------------------------------------------------------------
# 4. Backend .env setup
# ---------------------------------------------------------------------------
step "Configuring backend environment"

ENV_FILE="$SCRIPT_DIR/backend/.env"
ENV_EXAMPLE="$SCRIPT_DIR/backend/.env.example"

if [[ ! -f "$ENV_FILE" ]]; then
  cp "$ENV_EXAMPLE" "$ENV_FILE"
  ok "Created backend/.env from template"
  warn "Edit backend/.env and set VICTIM_HOST, VICTIM_USER, VICTIM_PASS before running"
else
  ok "backend/.env already exists - leaving as-is"
fi

# ---------------------------------------------------------------------------
# Done
# ---------------------------------------------------------------------------
cat <<EOF

  ${GRN}####################################################${RST}
  ${GRN}#                                                  #${RST}
  ${GRN}#   SETUP COMPLETE                                 #${RST}
  ${GRN}#                                                  #${RST}
  ${GRN}####################################################${RST}

  Next steps:
    1. ${CYN}Edit ${SCRIPT_DIR}/backend/.env${RST}
       Set VICTIM_HOST, VICTIM_USER, VICTIM_PASS to match your victim VM.

    2. Start the platform:
       ${CYN}./run-all.sh${RST}

       This brings up the backend (FastAPI :8000) and frontend (HTTP :8080)
       together in a tmux session. Press Ctrl+B then D to detach,
       or Ctrl+C in either pane to stop.

EOF
