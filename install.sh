#!/usr/bin/env bash
set -euo pipefail

APP_NAME="AI-SCORE-BELTU"
PYTHON_BIN="${PYTHON_BIN:-python3}"
VENV_DIR="${BELTU_VENV_DIR:-$HOME/.local/share/ai-score-beltu/venv}"
BIN_DIR="${BELTU_BIN_DIR:-$HOME/.local/bin}"

say() { printf '\n[%s] %s\n' "$APP_NAME" "$*"; }
fail() { printf '\n[%s] ERROR: %s\n' "$APP_NAME" "$*" >&2; exit 1; }

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

command -v "$PYTHON_BIN" >/dev/null 2>&1 || fail "python3 was not found. Install Python 3.11+ first."

PY_VERSION="$($PYTHON_BIN -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')"
if ! "$PYTHON_BIN" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3,11) else 1)'; then
  fail "Python 3.11+ is required (found $PY_VERSION)."
fi

"$PYTHON_BIN" -m venv --help >/dev/null 2>&1 || fail "Python venv support is missing. On Debian/Kali, install the matching python3-venv package."

say "Creating virtual environment: $VENV_DIR"
mkdir -p "$(dirname "$VENV_DIR")" "$BIN_DIR"
"$PYTHON_BIN" -m venv "$VENV_DIR"

VENV_PYTHON="$VENV_DIR/bin/python"
VENV_PIP="$VENV_DIR/bin/pip"

say "Upgrading packaging tools"
"$VENV_PIP" install --upgrade pip

say "Installing $APP_NAME"
"$VENV_PIP" install .

cat > "$BIN_DIR/beltu" <<EOF2
#!/usr/bin/env bash
exec "$VENV_DIR/bin/beltu" "\$@"
EOF2
chmod +x "$BIN_DIR/beltu"

cat > "$BIN_DIR/ai-score-beltu" <<EOF2
#!/usr/bin/env bash
exec "$VENV_DIR/bin/ai-score-beltu" "\$@"
EOF2
chmod +x "$BIN_DIR/ai-score-beltu"

say "Checking installation"
"$BIN_DIR/beltu" version
"$BIN_DIR/beltu" doctor

case ":${PATH}:" in
  *:"$BIN_DIR":*) ;;
  *)
    printf '\nAdd this to your shell profile if beltu is not found:\n  export PATH="%s:$PATH"\n' "$BIN_DIR"
    ;;
esac

say "Installed successfully."
printf 'Try: beltu -h\n'
