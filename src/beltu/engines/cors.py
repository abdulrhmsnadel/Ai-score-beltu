from __future__ import annotations

from beltu.core.engine import Engine
from beltu.core.http import request
from urllib.parse import urlsplit

from beltu.core.models import Evidence, Finding, ScanContext, Severity

from .common import base_context, finding


class CorsEngine(Engine):
    name = "cors"
    category = "CORS"
    description = "Tests controlled-origin CORS reflection and a preflight response without following redirects."

    @property
    def requires(self) -> list[str]:
        return ["Authorized target URL", "Explicit target allowlist", "Controlled test Origin"]

    def run(self, context: ScanContext):
        target = base_context(context)
        origin = str(context.options.get("origin", "https://beltu.invalid")).strip()
        origin_parts = urlsplit(origin)
        if origin_parts.scheme not in {"http", "https"} or not origin_parts.hostname:
            return [finding(context, self.name, self.category, "CORS test Origin is invalid", Severity.info, 1.0, "The supplied Origin must be an absolute HTTP(S) origin with a hostname.", "Provide a controlled test origin such as https://beltu.invalid.")]
        method = str(context.options.get("preflight_method", "GET")).upper()
        target_host = (urlsplit(target).hostname or "").lower().rstrip(".")
        origin_host = origin_parts.hostname.lower().rstrip(".")
        is_external_origin = origin_host != target_host
        response = request(context, headers={"Origin": origin})
        if not response.ok:
            return [finding(context, self.name, self.category, "CORS analysis failed", Severity.info, 0.1, response.error or "Request failed.", "Retry against an authorized reachable target.")]

        findings: list[Finding] = []
        acao = response.headers.get("access-control-allow-origin", "")
        acac = response.headers.get("access-control-allow-credentials", "")
        vary = response.headers.get("vary", "")
        evidence = Evidence(kind="headers", title="CORS simple request", data={"origin_sent": origin, "allow_origin": acao, "allow_credentials": acac, "vary": vary, "status_code": response.status_code})

        if is_external_origin and acao == origin and acac.lower() == "true":
            findings.append(finding(context, self.name, self.category, "CORS reflects a controlled external Origin with credentials enabled", Severity.high, 0.97, "The response reflected an origin whose host differs from the target and enabled credentials. This is a strong CORS misconfiguration signal; validate whether the origin is intended to be trusted.", "Allow only explicit trusted origins and enable credentials only for the cross-origin flows that require them.", evidence=[evidence]))
        elif acao == "*" and acac.lower() == "true":
            findings.append(finding(context, self.name, self.category, "CORS advertises wildcard origin with credentials enabled", Severity.medium, 0.88, "The response advertised a wildcard origin together with credentials. Browser enforcement makes the practical impact endpoint-dependent, so confirm actual behavior.", "Use an explicit allowlist of trusted origins and avoid credentialed wildcard CORS policies.", evidence=[evidence]))
        elif is_external_origin and acao == origin and acac.lower() != "true":
            findings.append(finding(context, self.name, self.category, "CORS reflects the controlled external Origin", Severity.medium, 0.82, "The response reflected a non-trusted test Origin. Impact depends on whether sensitive unauthenticated data is exposed and on other CORS policy controls.", "Use a strict allowlist of trusted origins rather than reflecting arbitrary Origin headers.", evidence=[evidence]))

        preflight = request(
            context,
            method="OPTIONS",
            headers={
                "Origin": origin,
                "Access-Control-Request-Method": method,
            },
        )
        if preflight.ok:
            preflight_acao = preflight.headers.get("access-control-allow-origin", "")
            preflight_methods = preflight.headers.get("access-control-allow-methods", "")
            preflight_credentials = preflight.headers.get("access-control-allow-credentials", "")
            preflight_evidence = Evidence(kind="headers", title="CORS preflight", data={"status_code": preflight.status_code, "origin_sent": origin, "allow_origin": preflight_acao, "allow_methods": preflight_methods, "allow_credentials": preflight_credentials, "vary": preflight.headers.get("vary", "")})
            if is_external_origin and preflight_acao == origin and preflight_credentials.lower() == "true":
                findings.append(finding(context, self.name, self.category, "CORS preflight reflects the controlled Origin with credentials enabled", Severity.high, 0.97, "The OPTIONS response accepted the controlled external origin while allowing credentials.", "Use a strict origin allowlist and require explicit authorization for credentialed cross-origin requests.", evidence=[preflight_evidence]))

        if is_external_origin and acao == origin and "origin" not in vary.lower():
            findings.append(finding(context, self.name, self.category, "CORS response varies by Origin without a Vary: Origin header", Severity.low, 0.72, "When a server dynamically changes Access-Control-Allow-Origin by request origin, caches need Vary: Origin to avoid serving one origin's CORS response to another.", "Add Vary: Origin when the response varies by the request Origin header.", evidence=[evidence]))

        return findings
