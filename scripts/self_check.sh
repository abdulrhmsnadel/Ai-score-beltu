#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

printf '\n[AI-SCORE-BELTU] Syntax check\n'
python -m compileall -q src tests

printf '[AI-SCORE-BELTU] Test suite\n'
python -m pytest -q

printf '[AI-SCORE-BELTU] Version consistency\n'
PYTHONPATH=src python - <<'PYV'
from beltu import __version__
from beltu.version import VERSION
from beltu.core.models import VERSION as MODEL_VERSION
import re
from pathlib import Path
text = Path('pyproject.toml').read_text()
match = re.search(r'^version = \"([^\"]+)\"$', text, re.M)
assert match and match.group(1) == __version__ == VERSION == MODEL_VERSION
print(f'Version consistency PASS: {__version__}')
PYV

printf '[AI-SCORE-BELTU] CLI smoke test\n'
PYTHONPATH=src python -m beltu -v
PYTHONPATH=src python -m beltu -e >/dev/null
PYTHONPATH=src python -m beltu -d >/dev/null

printf '[AI-SCORE-BELTU] Self-check PASS\n'
