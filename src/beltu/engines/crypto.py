from __future__ import annotations

import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urlsplit

from beltu.core.engine import Engine
from beltu.core.http import request
from beltu.core.models import Evidence, Finding, ScanContext, Severity

from .common import base_context, cookie_flags, finding


class CryptoEngine(Engine):
    name = "cryptography"
    category = "Cryptographic Failures"
    description = "Checks HTTPS use, negotiated TLS version, certificate validity window, HSTS, and Secure cookie posture."

    def run(self, context: ScanContext):
        target = base_context(context)
        parts = urlsplit(target)
        findings: list[Finding] = []
        if parts.scheme != "https":
            return [finding(context, self.name, self.category, "Target uses HTTP instead of HTTPS", Severity.high, 1.0, "The supplied target uses cleartext HTTP.", "Use HTTPS for authenticated or sensitive traffic and redirect HTTP to HTTPS.")]
        host = parts.hostname or ""
        port = parts.port or 443
        try:
            context_ssl = ssl.create_default_context()
            with socket.create_connection((host, port), timeout=context.timeout_seconds) as sock:
                with context_ssl.wrap_socket(sock, server_hostname=host) as tls_sock:
                    version = tls_sock.version() or "unknown"
                    cert = tls_sock.getpeercert()
                    if version in {"TLSv1", "TLSv1.1"}:
                        findings.append(finding(context, self.name, self.category, f"Deprecated TLS version negotiated: {version}", Severity.high, 1.0, "The server negotiated a deprecated TLS protocol version.", "Disable obsolete TLS protocol versions and require current secure TLS configurations.", evidence=[Evidence(kind="tls", title="Negotiated TLS", data={"version": version})]))
                    if cert and cert.get("notAfter"):
                        expires = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                        days = (expires - datetime.now(timezone.utc)).days
                        if days < 0:
                            findings.append(finding(context, self.name, self.category, "TLS certificate appears expired", Severity.high, 1.0, "The certificate returned during the TLS handshake is past its validity end date.", "Renew the certificate and validate the full certificate chain.", evidence=[Evidence(kind="tls", title="Certificate validity", data={"not_after": cert["notAfter"], "days_remaining": days})]))
                        elif days <= 14:
                            findings.append(finding(context, self.name, self.category, "TLS certificate expires soon", Severity.low, 0.94, "The certificate is within 14 days of expiry.", "Renew certificates before expiry and automate certificate monitoring.", evidence=[Evidence(kind="tls", title="Certificate validity", data={"not_after": cert["notAfter"], "days_remaining": days})]))
        except (OSError, ssl.SSLError, ValueError) as exc:
            findings.append(finding(context, self.name, self.category, "TLS verification could not complete", Severity.medium, 0.45, str(exc), "Check certificate validity, trust chain, hostname configuration, and TLS service availability."))

        response = request(context)
        if response.ok:
            if "strict-transport-security" not in response.headers:
                findings.append(finding(context, self.name, self.category, "HTTPS response has no HSTS header", Severity.medium, 0.92, "HTTPS is enabled but HSTS was not observed on the tested response.", "Consider Strict-Transport-Security for production HTTPS domains."))
            for cookie in cookie_flags(response.values("set-cookie")):
                if not cookie["secure"]:
                    findings.append(finding(context, self.name, self.category, f"Cookie '{cookie['name']}' lacks Secure", Severity.medium, 0.92, "A cookie is set without Secure on an HTTPS response.", "Set Secure on session/authentication cookies that should never traverse cleartext." , evidence=[Evidence(kind="cookie", title="Secure flag", data=cookie)]))
        return findings
