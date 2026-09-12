from __future__ import annotations

from beltu.core.engine import Engine
from beltu.core.http import request
from beltu.core.models import Evidence, Finding, ScanContext, Severity

from .common import base_context, finding

RECOMMENDED_HEADERS = {
    "strict-transport-security": (Severity.medium, "Add HSTS on HTTPS responses for appropriate production domains."),
    "content-security-policy": (Severity.medium, "Deploy a context-appropriate Content-Security-Policy."),
    "x-content-type-options": (Severity.low, "Set X-Content-Type-Options: nosniff."),
    "referrer-policy": (Severity.low, "Set a restrictive Referrer-Policy appropriate to the application."),
    "permissions-policy": (Severity.low, "Restrict unnecessary browser capabilities with Permissions-Policy."),
}


class MisconfigEngine(Engine):
    name = "misconfiguration"
    category = "Security Misconfiguration"
    description = "Checks response security headers, implementation disclosure, cache posture, and risky HTTP method hints."

    def run(self, context: ScanContext):
        target = base_context(context)
        response = request(context)
        if not response.ok:
            return [finding(context, self.name, self.category, "Misconfiguration scan failed", Severity.info, 0.1, response.error or "Request failed.", "Retry against an authorized reachable target.")]
        findings: list[Finding] = []
        for header, (severity, remediation) in RECOMMENDED_HEADERS.items():
            if header not in response.headers and (header != "strict-transport-security" or target.lower().startswith("https://")):
                findings.append(finding(context, self.name, self.category, f"Missing security header: {header}", severity, 0.92, f"The response does not include {header}.", remediation, evidence=[Evidence(kind="headers", title="Missing response header", data={"header": header})]))

        disclosed = {k: response.headers[k] for k in ("server", "x-powered-by", "x-aspnet-version", "x-runtime") if k in response.headers}
        if disclosed:
            findings.append(finding(context, self.name, self.category, "Response headers disclose implementation details", Severity.low, 0.93, "Response headers reveal platform or framework information.", "Minimize unnecessary server/framework disclosure in response headers.", evidence=[Evidence(kind="headers", title="Technology disclosure", data=disclosed)]))

        cache_control = response.headers.get("cache-control", "").lower()
        if any(token in target.lower() for token in ("account", "profile", "session", "auth", "dashboard")) and "no-store" not in cache_control:
            findings.append(finding(context, self.name, self.category, "Potentially sensitive endpoint lacks Cache-Control: no-store", Severity.medium, 0.68, "The supplied URL looks sensitive, but the response does not advertise no-store. Confirm whether personalized/authenticated data may be cached.", "Use Cache-Control: no-store for responses containing sensitive personalized data when caching is not appropriate.", evidence=[Evidence(kind="headers", title="Cache posture", data={"cache_control": response.headers.get("cache-control", "")})]))
        return findings
