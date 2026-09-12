from __future__ import annotations

import re

from beltu.core.engine import Engine
from beltu.core.http import request
from beltu.core.models import Evidence, Finding, ScanContext, Severity

from .common import base_context, finding

PATTERNS = {
    "stack_trace": (Severity.medium, re.compile(r"Traceback \(most recent call last\)|Exception in thread|StackTrace|at [A-Za-z0-9_.]+\([A-Za-z0-9_.]+:\d+\)", re.I)),
    "debug": (Severity.medium, re.compile(r"DEBUG\s*=\s*true|APP_DEBUG\s*=\s*true|debug mode", re.I)),
    "credential_hint": (Severity.high, re.compile(r"(?:password|passwd|secret|api[_-]?key)\s*[:=]\s*[\"'][^\"']{6,}[\"']", re.I)),
    "private_key": (Severity.critical, re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----", re.I)),
}


def _redact(text: str) -> str:
    text = re.sub(r"(password|passwd|secret|api[_-]?key)\s*[:=]\s*([\"'])(.*?)(\2)", r"\1=\"[REDACTED]\"", text, flags=re.I)
    text = re.sub(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----(.*?)-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----", "[PRIVATE KEY REDACTED]", text, flags=re.I | re.S)
    return text[:220]


class DisclosureEngine(Engine):
    name = "disclosure"
    category = "Information Disclosure"
    description = "Detects common debug, stack-trace, credential-like, and private-key disclosures while redacting sensitive evidence."

    def run(self, context: ScanContext):
        target = base_context(context)
        response = request(context)
        if not response.ok:
            return [finding(context, self.name, self.category, "Disclosure analysis failed", Severity.info, 0.1, response.error or "Request failed.", "Retry against an authorized reachable target.")]
        findings: list[Finding] = []
        for kind, (severity, pattern) in PATTERNS.items():
            match = pattern.search(response.text)
            if match:
                snippet = _redact(match.group(0))
                confidence = 0.9 if kind in {"private_key", "credential_hint"} else 0.84
                findings.append(finding(context, self.name, self.category, f"Potential {kind.replace('_', ' ')} disclosed in response", severity, confidence, "A known disclosure pattern was found in the response body. Review context to confirm sensitivity; BelTu redacts likely secret material from stored evidence.", "Disable debug output in production, sanitize errors, and remove secrets or internal implementation details from client-visible responses.", evidence=[Evidence(kind="body", title="Redacted disclosure pattern", data={"type": kind, "snippet": snippet, "status_code": response.status_code})]))
        return findings
