# AI layer

AI-SCORE-BELTU separates deterministic scoring from optional language-model assistance.

## Baseline

The local baseline combines:

- severity
- engine confidence
- verification state
- evidence diversity
- evidence strength
- duplicate grouping

The resulting score is reproducible and inspectable.

## Optional Ollama

The optional Ollama provider uses a local endpoint by default:

```text
http://127.0.0.1:11434
```

Only redacted metadata is sent. BelTu intentionally excludes cookies, authorization values, raw tokens, and raw secrets from the prompt builder.

The current verified Ollama release is **v0.34.0** as of September 9, 2026. See the Ollama release page for details.

## Policy

AI triage never upgrades a candidate to confirmed on its own. Exploitability must be demonstrated by an engine verification workflow or manual reproduction.
