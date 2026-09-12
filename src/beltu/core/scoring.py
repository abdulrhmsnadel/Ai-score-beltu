from __future__ import annotations

from collections import defaultdict

from beltu.core.models import Finding, Severity, VerificationLevel

_SEVERITY = {
    Severity.critical: 100,
    Severity.high: 82,
    Severity.medium: 58,
    Severity.low: 34,
    Severity.info: 8,
}
_VERIFY = {
    VerificationLevel.confirmed: 1.00,
    VerificationLevel.corroborated: 0.88,
    VerificationLevel.candidate: 0.64,
    VerificationLevel.informational: 0.35,
}


def evidence_quality(finding: Finding) -> float:
    """Estimate evidence quality from structured, diverse evidence types."""
    if not finding.evidence:
        return 0.0
    kinds = {item.kind.lower() for item in finding.evidence}
    diversity = min(0.35, 0.08 * len(kinds))
    quantity = min(0.20, 0.06 * len(finding.evidence))
    strong_types = {"callback", "comparison", "http", "preflight", "jwt", "openapi", "tls"}
    strength = 0.35 if kinds & strong_types else 0.15
    return min(1.0, 0.25 + diversity + quantity + strength)


def finding_credibility(finding: Finding) -> int:
    base = _SEVERITY[finding.severity]
    confidence = max(0.0, min(1.0, finding.confidence))
    verified = _VERIFY[finding.verification]
    evidence = evidence_quality(finding)
    score = (base * 0.20) + (confidence * 100 * 0.30) + (verified * 100 * 0.30) + (evidence * 100 * 0.20)
    return max(0, min(100, round(score)))


def calculate_score(findings: list[Finding]) -> int:
    """Return a calibrated 0-100 assessment risk score.

    Each unique finding contributes severity * evidence/verification quality; combined
    findings use diminishing returns so repeated low-severity observations cannot swamp
    one serious issue.
    """
    if not findings:
        return 0
    best_by_key: dict[str, Finding] = {}
    for item in findings:
        key = item.fingerprint or f"{item.engine}:{item.category}:{item.title}:{item.target}:{item.parameter or ''}"
        current = best_by_key.get(key)
        if current is None or finding_credibility(item) > finding_credibility(current):
            best_by_key[key] = item

    residual = 1.0
    for finding in best_by_key.values():
        severity_factor = _SEVERITY[finding.severity] / 100
        quality = 0.40 + 0.60 * (
            0.40 * finding.confidence
            + 0.30 * _VERIFY[finding.verification]
            + 0.30 * evidence_quality(finding)
        )
        contribution = min(0.95, severity_factor * quality)
        residual *= 1.0 - (0.88 * contribution)
    return max(0, min(100, round((1.0 - residual) * 100)))


def summarize(findings: list[Finding]) -> dict[str, int]:
    out = defaultdict(int)
    for finding in findings:
        out[finding.severity.value] += 1
    out["total"] = len(findings)
    out["confirmed"] = sum(f.verification == VerificationLevel.confirmed for f in findings)
    return dict(out)
