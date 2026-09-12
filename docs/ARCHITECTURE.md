# AI-SCORE-BELTU Architecture

AI-SCORE-BELTU is terminal-first. The Terminal UI is intentionally out of the active release line.

```text
Terminal CLI
   |
   +--> Scope Guard
   |
   +--> Engine Registry
   |      +--> SSRF
   |      +--> CSRF
   |      +--> API Security
   |      +--> Broken Access Control
   |      +--> Authentication
   |      +--> Security Misconfiguration
   |      +--> Cryptographic Failures
   |      +--> Software & Data Integrity
   |      +--> Information Disclosure
   |      +--> CORS
   |      +--> Open Redirect
   |      +--> JWT Security
   |
   +--> Test Identity / Mailpit adapters
   |
   v
Evidence -> SQLite -> JSON/HTML Reports
```

Every engine implements `beltu.core.engine.Engine` and returns structured `Finding` objects. Engines are designed as independent modules so future additions do not require rewriting the CLI core.

The release intentionally does not ship reconnaissance or the previously removed XSS/SQL Injection modules.
