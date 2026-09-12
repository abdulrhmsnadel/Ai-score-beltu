from __future__ import annotations

from urllib.parse import urljoin, urlsplit

from beltu.core.engine import Engine
from beltu.core.http import request
from beltu.core.models import Evidence, Finding, ScanContext, Severity

from .common import base_context, cookie_flags, html_forms, finding


class CsrfEngine(Engine):
    name = "csrf"
    category = "CSRF"
    description = "Inspects state-changing forms, anti-CSRF token fields, SameSite cookies, and cross-origin form actions without submitting them."

    def run(self, context: ScanContext):
        target = base_context(context)
        response = request(context)
        if not response.ok:
            return [finding(context, self.name, self.category, "CSRF analysis could not complete", Severity.info, 0.1, response.error or "Request failed.", "Retry against an authorized reachable page.")]
        findings: list[Finding] = []
        cookies = cookie_flags(response.values("set-cookie"))
        for cookie in cookies:
            if not cookie["samesite"]:
                findings.append(finding(context, self.name, self.category, f"Cookie '{cookie['name']}' has no explicit SameSite attribute", Severity.low, 0.75, "SameSite is not explicitly declared. This is a posture signal, not proof of CSRF.", "Set an explicit SameSite value appropriate for the application's cross-site flows and keep a server-validated CSRF defense for state-changing requests.", evidence=[Evidence(kind="cookie", title="SameSite posture", data=cookie)]))

        target_host = urlsplit(target).hostname or ""
        for form in html_forms(response.text):
            method = str(form["method"]).upper()
            if method not in {"POST", "PUT", "PATCH", "DELETE"}:
                continue
            action = str(form.get("action", ""))
            action_url = urljoin(target, action or target)
            action_host = urlsplit(action_url).hostname or ""
            fields = list(form["inputs"])
            tokenish = [i for i in fields if any(word in str(i["name"]).lower() for word in ("csrf", "xsrf", "authenticity", "anti_forgery", "token"))]
            evidence = Evidence(kind="html", title="State-changing form", data={"method": method, "action": action_url, "cross_origin_action": action_host.lower() != target_host.lower(), "field_names": [str(i["name"]) for i in fields]})
            if not tokenish:
                severity = Severity.high if action_host.lower() == target_host.lower() else Severity.medium
                findings.append(finding(context, self.name, self.category, "State-changing form has no obvious anti-CSRF token field", severity, 0.78 if severity == Severity.high else 0.7, "No common anti-CSRF token field was found in a state-changing form. Custom request-header defenses or same-origin controls may still exist.", "Use a server-validated anti-CSRF token or an equivalent robust defense, and review SameSite/cookie settings.", evidence=[evidence]))
        return findings
