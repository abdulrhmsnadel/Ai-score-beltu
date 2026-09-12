from __future__ import annotations

import json
import re
from dataclasses import dataclass
from hashlib import sha256
from typing import Any
from urllib.parse import urlsplit

from beltu.core.models import Finding, VerificationLevel
from beltu.core.scoring import evidence_quality, finding_credibility


@dataclass(slots=True)
class AIAnalysis:
    verdict: str
    confidence: float
    score: int
    credibility: int
    reasons: list[str]
    next_action: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "verdict": self.verdict,
            "confidence": round(self.confidence, 3),
            "score": self.score,
            "credibility": self.credibility,
            "reasons": self.reasons,
            "next_action": self.next_action,
        }


def analyze_finding(finding: Finding) -> AIAnalysis:
    credibility = finding_credibility(finding)
    evidence = evidence_quality(finding)
    score = round(0.55 * credibility + 0.45 * (finding.confidence * 100))
    reasons: list[str] = []

    if finding.verification == VerificationLevel.confirmed:
        reasons.append("The engine marked the finding as confirmed.")
    elif finding.verification == VerificationLevel.corroborated:
        reasons.append("Multiple independent evidence signals corroborate the finding.")
    elif finding.verification == VerificationLevel.candidate:
        reasons.append("The finding is a candidate and should be reproduced before reporting.")
    else:
        reasons.append("This is a posture or informational observation rather than exploit proof.")

    if evidence >= 0.75:
        reasons.append("Evidence has good diversity and at least one strong evidence type.")
    elif evidence > 0:
        reasons.append("Evidence exists but is limited; collect a second independent signal when possible.")
    else:
        reasons.append("No structured evidence was attached.")

    if finding.confidence >= 0.9:
        reasons.append(f"Engine confidence is high ({finding.confidence:.0%}).")
    elif finding.confidence >= 0.75:
        reasons.append(f"Engine confidence is moderate-high ({finding.confidence:.0%}).")
    else:
        reasons.append(f"Engine confidence is limited ({finding.confidence:.0%}).")

    if finding.verification == VerificationLevel.confirmed:
        verdict = "confirmed"
        next_action = "Preserve the evidence chain, document impact, and retest after remediation."
    elif score >= 82:
        verdict = "high-confidence candidate"
        next_action = "Run the engine-specific verification workflow and reproduce with dedicated test identities."
    elif score >= 60:
        verdict = "needs verification"
        next_action = "Collect stronger evidence and verify the finding manually before reporting."
    else:
        verdict = "low-confidence / informational"
        next_action = "Keep as a lead or posture observation until independent evidence is available."

    return AIAnalysis(
        verdict=verdict,
        confidence=min(0.99, max(0.05, score / 100)),
        score=max(0, min(100, score)),
        credibility=credibility,
        reasons=reasons,
        next_action=next_action,
    )


def fingerprint(finding: Finding) -> str:
    normalized_target = re.sub(r"([?#])[^#]*$", "", finding.target.lower())
    raw = "|".join([
        finding.engine,
        finding.category,
        normalized_target,
        finding.parameter or "",
        finding.title.lower().strip(),
    ])
    return sha256(raw.encode("utf-8", errors="replace")).hexdigest()[:16]


def triage(findings: list[Finding]) -> list[dict[str, Any]]:
    grouped: dict[str, list[Finding]] = {}
    for item in findings:
        grouped.setdefault(fingerprint(item), []).append(item)
    rows: list[dict[str, Any]] = []
    for fp, group in grouped.items():
        best = max(group, key=lambda f: (finding_credibility(f), f.confidence))
        analysis = analyze_finding(best)
        rows.append({
            "fingerprint": fp,
            "count": len(group),
            "engine": best.engine,
            "category": best.category,
            "title": best.title,
            "target": best.target,
            "severity": best.severity.value,
            "verification": best.verification.value,
            "analysis": analysis.as_dict(),
        })
    rows.sort(key=lambda x: (-x["analysis"]["score"], x["title"]))
    return rows


def build_prompt(findings: list[Finding]) -> str:
    payload = []
    for item in findings[:100]:
        payload.append({
            "engine": item.engine,
            "category": item.category,
            "title": item.title,
            "severity": item.severity.value,
            "confidence": round(item.confidence, 3),
            "verification": item.verification.value,
            "credibility": finding_credibility(item),
            "target_host": urlsplit(item.target).hostname,
            "parameter": item.parameter,
            "description": item.description[:1200],
            "remediation": item.remediation[:800],
            "evidence_kinds": [e.kind for e in item.evidence],
        })
    return (
        "You are a security finding triage assistant. Analyze only supplied authorized-test findings. "
        "Never invent vulnerabilities, exploit steps, secrets, credentials, or evidence. "
        "Return concise JSON with keys summary, priorities, verification_gaps, false_positive_risks.\n\n"
        + json.dumps(payload, ensure_ascii=False, indent=2)
    )
