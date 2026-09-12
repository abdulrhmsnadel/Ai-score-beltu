# v1.1.0 release notes

## What changed

v1.1.0 is a stability-focused release. The project remains terminal-only and keeps the scope guard as a hard prerequisite for network testing.

### Reliability

- bounded response-body collection via streaming
- controlled transient retries
- stricter sensitive-header redaction
- deterministic finding fingerprints
- explicit verification levels
- richer evidence metadata
- risk and credibility scoring are deterministic and inspectable

### Operator experience

- clean Rich terminal output
- compact one-letter action mode
- version and environment reporting
- JSON, HTML, and SARIF output
- dedicated engine information command

### AI

- local deterministic triage is always available
- optional local Ollama provider
- redacted prompt context
- AI cannot promote a candidate to confirmed

### Scope

No reconnaissance, XSS, or SQL Injection modules are shipped.
