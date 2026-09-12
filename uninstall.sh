#!/usr/bin/env bash
set -euo pipefail

VENV_DIR="${BELTU_VENV_DIR:-$HOME/.local/share/ai-score-beltu/venv}"
BIN_DIR="${BELTU_BIN_DIR:-$HOME/.local/bin}"

rm -f "$BIN_DIR/beltu" "$BIN_DIR/ai-score-beltu"
rm -rf "$VENV_DIR"

printf 'AI-SCORE-BELTU launcher and virtual environment removed.\n'
printf 'Note: project source files are left untouched.\n'
