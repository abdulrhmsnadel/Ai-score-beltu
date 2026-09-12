from __future__ import annotations

from beltu.core.engine import Engine
from beltu.core.http import request
from beltu.core.models import Evidence, Finding, ScanContext, Severity

from .common import base_context, cookie_flags, html_forms, finding


SESSION_NAMES = ("session", "sess", "sid", "auth", "token", "jwt", "access", "refresh")


class AuthenticationEngine(Engine):
    name = "authentication"
    category = "Authentication"
    description = "Assesses authentication-page transport, session cookie flags, password form structure, and basic anti-automation signals without brute force."

    def run(self, context: ScanContext):
        target = base_context(context)
        response = request(context)
        if not response.ok:
            return [finding(context, self.name, self.category, "Authentication analysis failed", Severity.info, 0.1, response.error or "Request failed.", "Retry against an authorized reachable authentication page.")]
        findings: list[Finding] = []
        if target.lower().startswith("http://"):
            findings.append(finding(context, self.name, self.category, "Authentication page is served over HTTP", Severity.high, 1.0, "The supplied authentication page uses cleartext transport.", "Serve authentication and credential submission over HTTPS and redirect HTTP to HTTPS."))

        forms = html_forms(response.text)
        password_forms = [f for f in forms if any(i["type"] == "password" for i in f["inputs"])]
        if password_forms:
            for form in password_forms:
                user_fields = [i["name"] for i in form["inputs"] if any(x in i["name"].lower() for x in ("user", "email", "login"))]
                token_fields = [i["name"] for i in form["inputs"] if any(x in i["name"].lower() for x in ("csrf", "xsrf", "token", "nonce"))]
                if not token_fields:
                    findings.append(finding(context, self.name, self.category, "Password form has no obvious anti-CSRF/nonce field", Severity.low, 0.68, "The password form contains no common CSRF/nonce-style hidden field. Applications may defend through SameSite cookies or request-header mechanisms.", "Review login CSRF protections and session fixation defenses.", evidence=[Evidence(kind="form", title="Password form structure", data={"action": form.get("action"), "user_fields": user_fields, "token_fields": token_fields})]))
        else:
            findings.append(finding(context, self.name, self.category, "No password field detected", Severity.info, 0.95, "The supplied URL may not be a conventional login page or may use a non-password authentication flow.", "Provide the actual authentication endpoint when using this engine."))

        cookies = cookie_flags(response.values("set-cookie"))
        for cookie in cookies:
            name = str(cookie["name"])
            lower_name = name.lower()
            likely_session = any(part in lower_name for part in SESSION_NAMES)
            if likely_session and not cookie["httponly"]:
                findings.append(finding(context, self.name, self.category, f"Session-like cookie '{name}' lacks HttpOnly", Severity.medium, 0.9, "A likely authentication/session cookie is readable by client-side scripts.", "Set HttpOnly on authentication/session cookies unless script access is explicitly required.", evidence=[Evidence(kind="cookie", title="Session cookie flags", data=cookie)]))
            if likely_session and not cookie["secure"] and target.lower().startswith("https://"):
                findings.append(finding(context, self.name, self.category, f"Session-like cookie '{name}' lacks Secure", Severity.medium, 0.92, "A likely authentication/session cookie can be sent over cleartext HTTP if the browser permits it.", "Set Secure on authentication/session cookies.", evidence=[Evidence(kind="cookie", title="Session cookie flags", data=cookie)]))
            if likely_session and not cookie["samesite"]:
                findings.append(finding(context, self.name, self.category, f"Session-like cookie '{name}' has no explicit SameSite attribute", Severity.low, 0.76, "SameSite is not explicitly declared for a likely session cookie.", "Set an explicit SameSite policy appropriate for the application's cross-site authentication flows.", evidence=[Evidence(kind="cookie", title="Session cookie flags", data=cookie)]))
        return findings
