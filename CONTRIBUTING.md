# Contributing to AI-SCORE-BELTU

Thanks for contributing.

## Development setup

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev]"
```

Run checks before opening a pull request:

```bash
ruff check .
pytest -q
```

## Engine design

Each engine should:

1. Declare the inputs it requires.
2. Enforce the scope guard before network activity.
3. Prefer conservative, non-destructive checks.
4. Return structured findings with severity, confidence, remediation, and evidence.
5. Avoid storing secrets or unnecessary personal data in evidence.
6. Document limitations and false-positive considerations.

## Adding an engine

Add the implementation under `src/beltu/engines/`, register it in the engine registry/catalog, add tests under `tests/`, and document it under `docs/modules/`.

## Security-sensitive changes

Changes involving authentication, authorization, SSRF, request routing, mail handling, tokens, evidence storage, or scope enforcement require extra review and explicit tests.
