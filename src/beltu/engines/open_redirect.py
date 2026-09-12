from __future__ import annotations

from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from beltu.core.engine import Engine
from beltu.core.http import request
from beltu.core.models import Evidence, Finding, ScanContext, Severity, VerificationLevel

from .common import base_context, url_host, finding

PARAM_HINTS = {"next", "url", "redirect", "redirect_uri", "return", "returnurl", "return_url", "continue", "dest", "destination", "target", "callback"}


def is_external(location: str, marker: str) -> bool:
    if not location:
        return False
    marker_host = url_host(marker)
    loc = urlsplit(location)
    if loc.scheme in {"http", "https"} and loc.hostname:
        return loc.hostname.lower().rstrip(".") == marker_host
    return location.startswith("//") and url_host(f"https:{location}") == marker_host


class OpenRedirectEngine(Engine):
    name = "open-redirect"
    category = "Open Redirect"
    description = "Checks redirect-like parameters and validates the returned Location host without following the external redirect."

    @property
    def requires(self) -> list[str]:
        return ["Authorized URL containing redirect-like parameters", "Explicit target allowlist", "Operator-controlled external marker URL"]

    def run(self, context: ScanContext):
        target = base_context(context)
        parts = urlsplit(target)
        params = parse_qsl(parts.query, keep_blank_values=True)
        marker = str(context.options.get("redirect_target", "https://beltu.invalid/")).strip()
        if not urlsplit(marker).hostname:
            return [finding(context, self.name, self.category, "Redirect marker is invalid", Severity.info, 1.0, "The supplied redirect marker is not an absolute URL with a hostname.", "Provide an operator-controlled external HTTPS marker URL.")]
        findings: list[Finding] = []
        for name, _value in params:
            if name.lower() not in PARAM_HINTS:
                continue
            mutated = [(k, marker if k == name else v) for k, v in params]
            test_url = urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(mutated), parts.fragment))
            response = request(context, url=test_url)
            location = response.headers.get("location", "") if response.ok else ""
            if response.ok and 300 <= int(response.status_code or 0) < 400 and is_external(location, marker):
                findings.append(Finding(
                    engine=self.name, category=self.category,
                    title=f"Open redirect verified through '{name}'", severity=Severity.medium, confidence=0.99,
                    target=test_url, parameter=name, verification=VerificationLevel.confirmed,
                    description="The application returned a redirect to the operator-controlled external marker. BelTu did not follow the redirect.",
                    remediation="Allow only approved destinations or map redirect choices to server-side identifiers. Validate absolute and protocol-relative URLs consistently.",
                    evidence=[Evidence(kind="http", title="Verified redirect response", data={"parameter": name, "marker_host": url_host(marker), "status_code": response.status_code, "location": location})],
                ))
        return findings
