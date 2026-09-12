from __future__ import annotations

import re
from urllib.parse import urljoin, urlsplit

from beltu.core.engine import Engine
from beltu.core.http import request
from beltu.core.models import Evidence, Finding, ScanContext, Severity

from .common import base_context, finding


class IntegrityEngine(Engine):
    name = "integrity"
    category = "Software & Data Integrity"
    description = "Checks external script SRI metadata, mixed content, and unpinned external script references on supplied HTML."

    def run(self, context: ScanContext):
        target = base_context(context)
        response = request(context)
        if not response.ok:
            return [finding(context, self.name, self.category, "Integrity analysis failed", Severity.info, 0.1, response.error or "Request failed.", "Retry against an authorized HTML page.")]
        findings: list[Finding] = []
        origin_host = (urlsplit(target).hostname or "").lower()
        for match in re.finditer(r"<script\b([^>]*)\bsrc=[\"']([^\"']+)[\"'][^>]*>", response.text, re.I):
            tag_attrs, src = match.groups()
            full = urljoin(target, src)
            host = (urlsplit(full).hostname or "").lower()
            external = host and host != origin_host
            integrity_match = re.search(r"\bintegrity=[\"']([^\"']+)[\"']", tag_attrs, re.I)
            if external and not integrity_match:
                findings.append(finding(context, self.name, self.category, "External script has no Subresource Integrity metadata", Severity.medium, 0.86, f"External script {full} is loaded without an integrity attribute.", "Use Subresource Integrity for third-party static assets where practical and pin dependency versions.", evidence=[Evidence(kind="html", title="External script", data={"src": full, "host": host})]))
            elif external and integrity_match:
                hashes = integrity_match.group(1).split()
                supported = [item for item in hashes if item.split("-", 1)[0] in {"sha256", "sha384", "sha512"}]
                if not supported:
                    findings.append(finding(context, self.name, self.category, "External script uses unrecognized SRI hash format", Severity.low, 0.82, f"The integrity attribute on {full} does not contain a recognized sha256/384/512 token.", "Use a standard sha256, sha384, or sha512 SRI digest generated from the exact asset bytes.", evidence=[Evidence(kind="html", title="SRI attribute", data={"src": full, "integrity": integrity_match.group(1)[:300]})]))
        if target.lower().startswith("https://") and re.search(r"<(script|img|link|iframe)\b[^>]+(?:src|href)=[\"']http://", response.text, re.I):
            findings.append(finding(context, self.name, self.category, "Mixed-content resource reference detected", Severity.high, 0.96, "The HTTPS page contains at least one HTTP resource reference.", "Load active and passive resources over HTTPS."))
        return findings
