from __future__ import annotations

import hashlib
import re
from http.cookies import SimpleCookie
from urllib.parse import urljoin, urlsplit

from beltu.core.models import Evidence, Finding, ScanContext, Severity, VerificationLevel
from beltu.core.scope import validate_url


def base_context(context: ScanContext) -> str:
    return validate_url(context.target, context.allow_hosts)


def finding(
    context: ScanContext,
    engine: str,
    category: str,
    title: str,
    severity: Severity,
    confidence: float,
    description: str,
    remediation: str,
    *,
    parameter: str | None = None,
    evidence: list[Evidence] | None = None,
    verification: VerificationLevel | None = None,
    tags: list[str] | None = None,
    cwe: list[str] | None = None,
    owasp: list[str] | None = None,
    requests_made: int = 0,
    duration_ms: float | None = None,
) -> Finding:
    if verification is None:
        verification = VerificationLevel.informational if severity == Severity.info else VerificationLevel.candidate
    evidence_items = evidence or []
    raw = "|".join([
        engine, category, title.lower().strip(), context.target, parameter or "",
    ])
    fingerprint = hashlib.sha256(raw.encode("utf-8", errors="replace")).hexdigest()[:20]
    return Finding(
        engine=engine,
        category=category,
        title=title,
        severity=severity,
        confidence=confidence,
        target=context.target,
        parameter=parameter,
        description=description,
        remediation=remediation,
        verification=verification,
        evidence=evidence_items,
        tags=tags or [],
        cwe=cwe or [],
        owasp=owasp or [],
        requests_made=requests_made,
        duration_ms=duration_ms,
        fingerprint=fingerprint,
    )


def cookie_flags(set_cookie_headers: list[str]) -> list[dict[str, str | bool]]:
    result: list[dict[str, str | bool]] = []
    for raw in set_cookie_headers:
        jar = SimpleCookie()
        try:
            jar.load(raw)
        except Exception:
            continue
        for morsel in jar.values():
            result.append({
                "name": morsel.key,
                "secure": bool(morsel["secure"]),
                "httponly": bool(morsel["httponly"]),
                "samesite": morsel["samesite"] or "",
                "path": morsel["path"] or "",
                "domain": morsel["domain"] or "",
            })
    return result


def html_forms(text: str) -> list[dict[str, object]]:
    forms: list[dict[str, object]] = []
    for match in re.finditer(r"<form\b([^>]*)>(.*?)</form>", text, re.I | re.S):
        attrs, body = match.groups()
        method_match = re.search(r"\bmethod\s*=\s*[\"']?([^\s\"'>]+)", attrs, re.I)
        action_match = re.search(r"\baction\s*=\s*[\"']?([^\s\"'>]+)", attrs, re.I)
        inputs = re.findall(r"<input\b([^>]*)>", body, re.I)
        fields: list[dict[str, str]] = []
        for input_attrs in inputs:
            type_match = re.search(r"\btype\s*=\s*[\"']?([^\s\"'>]+)", input_attrs, re.I)
            name_match = re.search(r"\bname\s*=\s*[\"']?([^\s\"'>]+)", input_attrs, re.I)
            value_match = re.search(r"\bvalue\s*=\s*[\"']?([^\"'>]*)", input_attrs, re.I)
            if name_match:
                fields.append({
                    "name": name_match.group(1),
                    "type": (type_match.group(1) if type_match else "text").lower(),
                    "value": value_match.group(1) if value_match else "",
                })
        forms.append({
            "method": (method_match.group(1) if method_match else "get").upper(),
            "action": action_match.group(1) if action_match else "",
            "action_url": urljoin("https://beltu.invalid/", action_match.group(1) if action_match else ""),
            "inputs": fields,
        })
    return forms


def url_host(url: str) -> str:
    return (urlsplit(url).hostname or "").lower().rstrip(".")


def body_fingerprint(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()


def normalize_text(text: str, *, limit: int = 250_000) -> str:
    return re.sub(r"\s+", " ", text[:limit]).strip()
