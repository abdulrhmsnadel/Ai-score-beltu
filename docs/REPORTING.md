# Reporting

Reports now contain:

1. Executive summary with risk and credibility.
2. Verification breakdown (`informational`, `candidate`, `corroborated`, `confirmed`).
3. AI triage and provider consensus as advisory metadata.
4. Evidence chain with centralized redaction.
5. Per-finding severity, confidence, engine, target, remediation, CWE/OWASP tags.
6. Request counts and scan durations where the engine supplies them.
7. JSON, HTML, and SARIF output.

AI provider agreement is never treated as proof. A confirmed finding still requires deterministic engine evidence.
