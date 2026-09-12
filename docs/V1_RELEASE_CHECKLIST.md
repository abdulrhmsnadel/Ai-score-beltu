# v1.1.0 release checklist

## Safety
- Explicit host allowlist is mandatory for network engines.
- No Recon, XSS, or SQL Injection modules.
- SSRF uses an operator-owned HTTPS canary and does not probe internal ranges.
- JWT analysis is local; no brute force or forgery.
- Access-control workflows require operator-supplied test identities.

## Quality
- HTTP timeouts and bounded response body size.
- Retry handling limited to transient HTTP status codes.
- Sensitive headers are redacted in evidence.
- Findings carry fingerprints and verification states.
- Risk and credibility scoring are deterministic and inspectable.
- Optional AI is local-first and receives redacted metadata.

## Release hygiene
- Keep secrets out of source and git history.
- Run `pytest -q` and `ruff check src tests`.
- Verify `beltu -v`, `beltu -d`, `beltu -e`.
- Generate JSON/HTML/SARIF reports from a test database.
