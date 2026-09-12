# Cryptographic Failures Engine

**Input:** authorized HTTPS URL.

**How it works:** verifies HTTPS usage, negotiates TLS, checks for deprecated protocol versions, inspects certificate validity, checks HSTS, and inspects `Secure` cookie flags.

**Evidence:** TLS version/certificate validity and response cookie/header posture.
