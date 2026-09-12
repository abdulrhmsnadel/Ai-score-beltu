# CSRF Engine

**Input:** authorized HTML URL.

**How it works:** reads state-changing forms, looks for common anti-CSRF token fields, and inspects `Set-Cookie` SameSite posture. It does not submit state-changing forms.

**Evidence:** form method/action/field names and cookie flags.
