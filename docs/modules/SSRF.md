# SSRF Engine

**Input:** target URL with a URL-like parameter, operator-owned HTTPS canary, canary allowlist.

**How it works:** BelTu identifies URL-like query parameters, substitutes the operator canary, and sends one controlled request without probing private/local destinations.

**Evidence:** tested URL, parameter, response status, canary hostname.

**Important:** an accepted canary value is only a triage signal. The finding becomes convincing when the operator can confirm a callback in the canary service logs.
