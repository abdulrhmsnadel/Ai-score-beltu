# JWT Security Engine

**Input:** authorized target URL and a JWT captured from a dedicated test account/request.

**How it works:** decodes the JWT locally and checks algorithm declaration, expiration, issuer/audience presence, and excessive lifetime. It never forges, cracks, or bypasses signatures.

**Evidence:** non-secret header/claim metadata and timing information.
