# API Security Engine

**Input:** authorized API URL and OpenAPI JSON URL/file.

**How it works:** reviews reusable `securitySchemes`, global/operation security requirements, state-changing operations, sensitive-looking query parameters, and Basic Auth definitions.

**Evidence:** affected OpenAPI operations and security metadata.

**Important:** documentation findings must be verified against live authorization behavior.
