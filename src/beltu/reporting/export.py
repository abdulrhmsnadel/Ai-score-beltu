from __future__ import annotations

import html
import json
from collections import Counter, defaultdict
from pathlib import Path

from beltu import APP_NAME, __version__
from beltu.ai import triage
from beltu.core.models import Evidence, Finding, VerificationLevel
from beltu.core.http import redact_data, redact_url
from beltu.core.scoring import calculate_score, summarize, finding_credibility


def _safe_findings(findings: list[Finding]) -> list[Finding]:
    return [
        f.model_copy(update={
            "target": redact_url(f.target),
            "evidence": [Evidence(kind=e.kind, title=e.title, data=redact_data(e.data)) for e in f.evidence],
            "ai": redact_data(f.ai),
        })
        for f in findings
    ]


def _verification_counts(findings: list[Finding]) -> dict[str, int]:
    return {level.value: sum(f.verification == level for f in findings) for level in VerificationLevel}


def _provider_summary(findings: list[Finding]) -> dict[str, dict[str, int]]:
    summary: dict[str, dict[str, int]] = defaultdict(lambda: {"used": 0, "ok": 0, "failed": 0})
    for f in findings:
        for provider, result in (f.ai.get("provider_results", {}) if f.ai else {}).items():
            summary[provider]["used"] += 1
            if isinstance(result, dict) and result.get("ok"):
                summary[provider]["ok"] += 1
            else:
                summary[provider]["failed"] += 1
    return dict(summary)


def _payload(findings: list[Finding]) -> dict:
    safe_findings = _safe_findings(findings)
    high_priority = sorted(
        safe_findings,
        key=lambda f: (finding_credibility(f), f.severity.value == "critical", f.confidence),
        reverse=True,
    )
    return {
        "tool": APP_NAME,
        "version": __version__,
        "summary": summarize(safe_findings),
        "risk_score": calculate_score(safe_findings),
        "verification": _verification_counts(safe_findings),
        "provider_summary": _provider_summary(safe_findings),
        "ai_triage": triage(safe_findings),
        "top_priorities": [
            {
                "id": f.id,
                "engine": f.engine,
                "title": f.title,
                "severity": f.severity.value,
                "verification": f.verification.value,
                "confidence": f.confidence,
                "credibility": finding_credibility(f),
                "remediation": f.remediation,
            }
            for f in high_priority[:20]
        ],
        "findings": [f.model_dump(mode="json") for f in safe_findings],
        "methodology": {
            "detection": "Deterministic engine output",
            "verification": "Engine-specific evidence and reproduction state",
            "ai": "Advisory triage only; provider agreement never proves exploitability",
            "secrets": "Sensitive headers/tokens are redacted before report serialization",
        },
    }


def write_json(findings: list[Finding], path: str | Path) -> None:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text(json.dumps(_payload(findings), indent=2, ensure_ascii=False), encoding="utf-8")


def write_sarif(findings: list[Finding], path: str | Path) -> None:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    findings = _safe_findings(findings)
    rules: list[dict] = []
    results: list[dict] = []
    seen_rules: set[str] = set()
    for finding in findings:
        rule_id = finding.fingerprint or finding.engine
        if rule_id not in seen_rules:
            rules.append({
                "id": rule_id,
                "name": finding.title,
                "shortDescription": {"text": finding.title},
                "help": {"text": finding.remediation or finding.description},
                "properties": {"category": finding.category, "severity": finding.severity.value},
            })
            seen_rules.add(rule_id)
        results.append({
            "ruleId": rule_id,
            "level": "error" if finding.severity.value in {"high", "critical"} else "warning",
            "message": {"text": finding.description or finding.title},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": finding.target}}}],
            "properties": {
                "verification": finding.verification.value,
                "confidence": finding.confidence,
                "credibility": finding_credibility(finding),
                "engine": finding.engine,
            },
        })
    document = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": APP_NAME, "version": __version__, "rules": rules}}, "results": results}],
    }
    Path(path).write_text(json.dumps(document, indent=2, ensure_ascii=False), encoding="utf-8")


def write_html(findings: list[Finding], path: str | Path) -> None:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    findings = _safe_findings(findings)
    counts = Counter(f.severity.value for f in findings)
    verification = _verification_counts(findings)
    triage_rows = triage(findings)
    provider_summary = _provider_summary(findings)
    rows: list[str] = []
    for f in findings:
        evidence_html: list[str] = []
        for ev in f.evidence:
            safe = html.escape(json.dumps(ev.data, ensure_ascii=False, sort_keys=True))
            evidence_html.append(f"<details><summary>{html.escape(ev.title)} ({html.escape(ev.kind)})</summary><pre>{safe}</pre></details>")
        rows.append(
            "<tr>"
            f"<td>{html.escape(f.severity.value)}</td>"
            f"<td>{html.escape(f.verification.value)}</td>"
            f"<td>{html.escape(f.category)}</td>"
            f"<td>{html.escape(f.title)}</td>"
            f"<td>{f.confidence:.0%}</td>"
            f"<td>{finding_credibility(f)}</td>"
            f"<td>{html.escape(f.status.value)}</td>"
            f"<td>{html.escape(f.target)}</td>"
            f"<td>{''.join(evidence_html) or '—'}</td>"
            "</tr>"
        )
    ai_rows: list[str] = []
    for item in triage_rows:
        analysis = item["analysis"]
        ai_rows.append(
            "<tr>"
            f"<td>{html.escape(item['severity'])}</td>"
            f"<td>{html.escape(item['title'])}</td>"
            f"<td>{analysis['score']}</td>"
            f"<td>{analysis['credibility']}</td>"
            f"<td>{html.escape(analysis['verdict'])}</td>"
            f"<td>{html.escape(analysis['next_action'])}</td>"
            "</tr>"
        )
    provider_rows = []
    for name, stats in sorted(provider_summary.items()):
        provider_rows.append(f"<tr><td>{html.escape(name)}</td><td>{stats['used']}</td><td>{stats['ok']}</td><td>{stats['failed']}</td></tr>")
    cards = " ".join(f"<span class='pill'>{html.escape(k)}: {v}</span>" for k, v in sorted(counts.items())) or "<span class='pill'>No findings</span>"
    verify_cards = " ".join(f"<span class='pill'>{html.escape(k)}: {v}</span>" for k, v in verification.items())
    doc = f"""<!doctype html>
<html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'>
<title>{APP_NAME} Report</title>
<style>
body{{font-family:ui-sans-serif,system-ui,-apple-system,sans-serif;margin:0;background:#0b1020;color:#e9eef8;line-height:1.5}}
main{{max-width:1400px;margin:auto;padding:32px}}
.hero{{padding:28px;border:1px solid #26324d;border-radius:18px;background:#111a31;box-shadow:0 10px 40px rgba(0,0,0,.2)}}
.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px;margin:18px 0}}
.card{{padding:16px;border:1px solid #26324d;border-radius:14px;background:#0f172a}}
table{{border-collapse:collapse;width:100%;margin:12px 0 28px;background:#0f172a}}
td,th{{border:1px solid #26324d;padding:9px;text-align:left;vertical-align:top}}
th{{background:#111a31}}
.pill{{display:inline-block;padding:5px 9px;border:1px solid #364361;border-radius:999px;margin:2px;background:#121c33}}
.note{{padding:12px;border:1px solid #364361;border-radius:12px;background:#0f172a;color:#c8d1e5}}
.score{{font-size:2.4rem;font-weight:800}}
.small{{color:#9fb0cb;font-size:.9rem}}
pre{{white-space:pre-wrap;overflow:auto}}
</style></head>
<body><main>
<section class='hero'><div class='small'>{APP_NAME} v{__version__}</div><h1>Security Assessment Report</h1><div class='score'>Risk score: {calculate_score(findings)}/100</div><p class='small'>AI is advisory. Exploitability is established by deterministic evidence and verification state.</p></section>
<div class='grid'>
<div class='card'><b>Total findings</b><br>{len(findings)}</div>
<div class='card'><b>Confirmed</b><br>{verification['confirmed']}</div>
<div class='card'><b>Corroborated</b><br>{verification['corroborated']}</div>
<div class='card'><b>High/Critical</b><br>{sum(f.severity.value in ('high','critical') for f in findings)}</div>
</div>
<h2>Severity</h2><p>{cards}</p>
<h2>Verification</h2><p>{verify_cards}</p>
<h2>AI Provider Summary</h2><table><thead><tr><th>Provider</th><th>Used</th><th>Success</th><th>Failed</th></tr></thead><tbody>{''.join(provider_rows) or '<tr><td colspan=4>No remote/local provider results stored</td></tr>'}</tbody></table>
<h2>AI Triage</h2><table><thead><tr><th>Severity</th><th>Finding</th><th>AI score</th><th>Credibility</th><th>Verdict</th><th>Next action</th></tr></thead><tbody>{''.join(ai_rows) or '<tr><td colspan=6>No findings</td></tr>'}</tbody></table>
<h2>Findings</h2><table><thead><tr><th>Severity</th><th>Verification</th><th>Category</th><th>Title</th><th>Confidence</th><th>Credibility</th><th>Status</th><th>Target</th><th>Evidence</th></tr></thead><tbody>{''.join(rows) or '<tr><td colspan=9>No findings</td></tr>'}</tbody></table>
<section class='note'><b>Methodology:</b> Detection comes from deterministic engines; verification comes from engine-specific evidence; AI provider output is advisory and never proof. Sensitive headers/tokens are redacted before serialization.</section>
</main></body></html>"""
    Path(path).write_text(doc, encoding="utf-8")
