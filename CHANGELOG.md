# Changelog

## 1.6.0 — AI orchestration and integration upgrade

- Added DeepSeek-Coder-V2-compatible OpenAI-format adapter.
- Added bounded LangChain + LangGraph orchestration for evidence-first AI review.
- Added Interactsh official-client integration for OOB canary generation.
- Added PyJWT dependency for local JWT helper/validation.
- Updated scikit-learn to 1.9.1 and added LangChain 1.4.0 / LangGraph 1.2.11 optional AI stack.
- Added 100 varied deterministic engine test vectors and provider contract tests.
- Improved JSON/HTML/SARIF reports with provider summary, verification matrix, priorities, and methodology.
- Kept AI advisory-only; provider agreement never turns a candidate into confirmed proof.

1.3.0 — 2026-09-12
- Access Control guess runner now uses a mixed deterministic candidate order with common object/user identifiers before sequential IDs.
- Response similarity now uses content similarity instead of body-length similarity to reduce false positives.
- Added bundled deterministic 10,000-case mixed and Access Control corpora.
- Credential/password guessing is intentionally excluded.

## 1.1.1 — 2026-09-12

### Fixed
- Centralized sensitive-header redaction now covers custom auth/session-like header names in reports and stored evidence.
- CORS no longer classifies same-origin Origin reflection as an external-origin issue and validates the supplied test Origin.
- Integrity mixed-content detection now runs only for HTTPS targets.
- Access-control object mutation rejects no-op mutations and is stricter about successful responses before treating target markers as strong evidence.
- Version metadata is synchronized at 1.1.1.


## 1.1.0 — 2026-09-12
- Audited and fixed version drift across package metadata, models, tests, and release docs.
- Added same-session object/resource mutation mode to Broken Access Control (`-P/-V/-N`).
- Added centralized evidence redaction for SQLite and JSON/HTML/SARIF exports.
- Added `-x/--details` to report generation and made Ollama probing opt-in in `doctor`.
- Calibrated assessment risk scoring so a single high/critical finding is visible without linear inflation from duplicates.
- Updated the stable Typer dependency pin to 0.26.6; pre-release HTTPX/Pydantic versions remain intentionally excluded.


## 1.0.1
- Added `--details/-x` to scan commands to print finding explanations and redacted evidence in Terminal.
- Added a clear terminal evidence view while preserving JSON/HTML/SARIF reports.
- Redacts common credential/session fields from terminal evidence output.


## 1.0.0 — 2026-09-12

### Added
- Deterministic risk and credibility scoring with evidence quality.
- Stronger AI-assisted triage with explicit verification reasoning.
- Optional Ollama local provider with redacted context.
- JSON, HTML, and SARIF reporting.
- OpenAPI JSON and YAML parsing support.
- HTTP retries for transient status codes, response-size limits, and stricter redaction.
- Rich terminal presentation and clearer assessment summaries.
- Stable version metadata across package, CLI, user-agent, findings, and reports.

### Changed
- CLI is terminal-only and keeps compact shortcut actions.
- Findings now retain verification, evidence, CWE/OWASP tags, request count, scanner version, and fingerprints.

### Removed / Not included
- Reconnaissance
- XSS
- SQL Injection


### Dependency baseline
Runtime/build/test pins were refreshed for the September 12, 2026 release baseline. See `docs/DEPENDENCY_BASELINE.md`.

## 1.2.0 — Guess/Fuzz layer
- Added deterministic 10,000-case guess/test corpus generation.
- Added bounded Access Control object-ID guessing for authorized labs/test systems.
- Added explicit large-run confirmation above 1,000 requests and a minimum request delay.
- Added redacted JSON run summaries and optional HTML findings report.
- Added `beltu -G` shortcut for the new Guess command group.
- Credential/password guessing is intentionally excluded.



## 1.5.0
- Added a deterministic smart guessing corpus for authorized object/resource identifiers.
- Offline corpus generation supports up to 1,000,000 candidates.
- Access-control network guessing remains capped at 10,000 requests per invocation and no credential/password guessing is supported.
- Candidate ordering now interleaves common names, case variants, numeric IDs, and 4–15 character alphanumeric samples instead of 1,2,3 sequencing.

## 1.5.0 — Multi-AI Integration
- Added task-specific AI routing across all security engines.
- Added OpenAI GPT-4o API adapter.
- Added Anthropic Claude adapter with legacy Claude 3.5 compatibility guard.
- Added local Code Llama/Ollama adapter.
- Added Burp message bridge.
- Added planner-only PentestGPT adapter.
- Added optional scikit-learn duplicate/anomaly analysis.
- Added AI metadata to findings, JSON/HTML/SARIF reports, and CLI inspection.
- Added explicit provider activation guards to avoid accidental network/subprocess probing.
