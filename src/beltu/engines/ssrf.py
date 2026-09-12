from __future__ import annotations

import re
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from beltu.core.engine import Engine
from beltu.core.http import request
from beltu.core.models import Evidence, Finding, ScanContext, Severity
from beltu.core.scope import validate_canary

from .common import base_context, finding

URL_PARAM_HINTS = ("url", "uri", "link", "redirect", "callback", "next", "dest", "destination", "endpoint", "fetch", "image", "webhook")


class SsrfEngine(Engine):
    name = "ssrf"
    category = "SSRF"
    description = "Controlled canary-based SSRF triage for URL-like parameters; does not probe local/private/cloud-metadata destinations."

    @property
    def requires(self) -> list[str]:
        return ["Authorized target", "Explicit target allowlist", "Operator-owned HTTPS canary URL"]

    def run(self, context: ScanContext):
        target = base_context(context)
        canary = str(context.options.get("canary_url", "")).strip()
        if not canary:
            return [finding(context, self.name, self.category, "SSRF engine requires a canary URL", Severity.info, 1.0, "Provide an operator-controlled canary URL. BelTu will not attempt internal-network or cloud-metadata targets.", "Use a canary service you own or a dedicated test endpoint and place its hostname in --canary-allow-host.")]
        validate_canary(canary, context.options.get("canary_allow_hosts", []))
        parts = urlsplit(target)
        params = parse_qsl(parts.query, keep_blank_values=True)
        findings: list[Finding] = []
        for name, value in params:
            if name.lower() not in URL_PARAM_HINTS and not re.match(r"https?://", value, re.I):
                continue
            mutated = [(k, canary if k == name else v) for k, v in params]
            test_url = urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(mutated), parts.fragment))
            response = request(context, url=test_url)
            if not response.ok:
                continue
            findings.append(Finding(
                engine=self.name, category=self.category,
                title=f"URL-like input accepted for '{name}'",
                severity=Severity.info, confidence=0.6, target=test_url, parameter=name,
                description="The target accepted a controlled canary value. Acceptance alone does not prove server-side fetching; use the canary's request log or callback evidence to confirm SSRF.",
                remediation="Allowlist outbound destinations, validate scheme/host/IP after DNS resolution, block local/private/link-local ranges, and avoid arbitrary server-side URL fetching.",
                evidence=[Evidence(kind="http", title="Controlled SSRF probe", data={"test_url": test_url, "status_code": response.status_code, "canary_host": urlsplit(canary).hostname})],
            ))
        return findings
