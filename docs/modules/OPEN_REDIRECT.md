# Open Redirect Engine

**Input:** authorized URL containing a redirect-like query parameter and an external operator-controlled marker URL.

**How it works:** substitutes the marker and inspects the `Location` response without following it. The external host is compared explicitly to the marker host.

**Evidence:** parameter, status code, and returned Location header.
