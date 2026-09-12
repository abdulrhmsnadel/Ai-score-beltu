# Authentication Engine

**Input:** authorized authentication page.

**How it works:** checks cleartext transport, password-form structure, session-like cookie flags (`HttpOnly`, `Secure`, `SameSite`), and basic nonce/anti-CSRF field presence.

**No brute force:** this engine never guesses passwords or floods login endpoints.
