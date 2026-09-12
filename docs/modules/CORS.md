# CORS Engine

**Input:** authorized URL and controlled test Origin.

**How it works:** sends a simple request with the controlled Origin, then an OPTIONS preflight, and checks `Access-Control-Allow-Origin`, credentials, methods, and `Vary: Origin`.

**Evidence:** relevant CORS response headers. Redirects are not followed.
