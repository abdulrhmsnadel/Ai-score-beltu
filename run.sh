#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="${BELTU_VENV_DIR:-$HOME/.local/share/ai-score-beltu/venv}"

if [[ ! -x "$VENV_DIR/bin/beltu" ]]; then
  printf 'AI-SCORE-BELTU is not installed yet. Run ./install.sh first.\n' >&2
  exit 1
fi

exec "$VENV_DIR/bin/beltu" "$@"
