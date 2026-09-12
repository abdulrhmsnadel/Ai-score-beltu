# Engine matrix — v1.1.0

BelTu is intentionally terminal-first. Every engine has its own input contract and verification rules.

| Engine | What you provide | Main detection | Confirmation standard |
|---|---|---|---|
| SSRF | Target + owned HTTPS canary + canary allowlist | URL-like parameters + controlled canary acceptance | External canary callback evidence |
| CSRF | Target HTML URL | State-changing forms, token signals, SameSite cookie posture | Manual/engine workflow reproduction |
| API | API target + OpenAPI JSON/YAML | Security requirements, unsafe sensitive query parameters, undocumented protected operations | Compare spec expectations with authorized runtime behavior |
| Broken Access Control | Two identities for comparison OR one identity + object parameter/value | Differential response or controlled object mutation + marker leakage | Account-specific data visible across identities or target-object marker in a same-session mutation |
| Authentication | Auth/login URL | HTTP transport, password forms, cookie flags, session posture | Reproduce auth/session issue with test accounts |
| Security Misconfiguration | Target URL | Security headers, disclosure headers, cache posture | Confirm application impact/context |
| Cryptographic Failures | HTTPS target | TLS/HSTS/certificate/cookie transport posture | Confirm negotiated transport and sensitive-data exposure |
| Integrity | HTML target | Missing SRI and mixed content | Confirm external script/resource is trusted without integrity protection |
| Information Disclosure | Target URL | Debug traces, stack traces, credential-like patterns | Confirm exposed material is sensitive and reachable |
| CORS | Target + controlled Origin | ACAO reflection/wildcard, credentials, preflight policy | Controlled-origin response demonstrates unsafe cross-origin read conditions |
| Open Redirect | Redirect-like target URL | External marker in Location without following it | Server actually returns redirect to the controlled external marker |
| JWT | Authorized context + test JWT | Local structure, algorithm/claim policy | Manual/authorized workflow confirms actual trust impact |

## What BelTu intentionally does not do

- Reconnaissance
- XSS
- SQL Injection
- Brute force
- Credential stuffing
- Internal-network probing for SSRF
- Cloud metadata probing
- JWT cracking or signature forgery
- Automatic submission of destructive state changes

The goal of v1.1.0 is **credible evidence**, not the largest number of requests.

## Guess / controlled mutation layer

The Guess layer is a cross-cutting testing capability rather than a vulnerability category. It can generate deterministic 10,000-case corpora and currently executes bounded same-session object-ID mutation for Access Control/IDOR-style authorized labs; offline corpus generation supports up to 1,000,000 candidates. It does not perform password/credential brute forcing.
