from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import parse_qsl, urlsplit

from beltu import __version__
from beltu.ai import analyze_finding, triage
from beltu.core.http import safe_headers
from beltu.core.models import Evidence, Finding, ScanContext, Severity, VerificationLevel
from beltu.core.scoring import calculate_score, evidence_quality, finding_credibility
from beltu.engines.api import ApiEngine
from beltu.reporting.export import write_html, write_json, write_sarif


def make_finding(**updates):
    data = {
        "engine": "test",
        "category": "Test",
        "title": "Test finding",
        "severity": Severity.high,
        "confidence": 0.9,
        "target": "https://example.com",
        "verification": VerificationLevel.confirmed,
        "evidence": [Evidence(kind="http", title="response", data={"status": 200})],
    }
    data.update(updates)
    return Finding(**data)


def test_version_is_consistent():
    from beltu.core.models import VERSION
    assert __version__ == "1.6.0"
    assert VERSION == __version__


def test_redaction():
    headers = safe_headers({"Authorization": "Bearer super-secret", "Content-Type": "text/plain"})
    assert "super-secret" not in headers["Authorization"]
    assert headers["Content-Type"] == "text/plain"


def test_confirmed_finding_scores_high():
    finding = make_finding()
    assert finding_credibility(finding) >= 80
    assert analyze_finding(finding).verdict == "confirmed"


def test_candidate_is_lower_than_confirmed():
    confirmed = make_finding()
    candidate = make_finding(verification=VerificationLevel.candidate, confidence=0.6, evidence=[])
    assert finding_credibility(confirmed) > finding_credibility(candidate)
    assert calculate_score([confirmed]) >= calculate_score([candidate])


def test_evidence_quality_increases_with_diversity():
    one = make_finding(evidence=[Evidence(kind="http", title="http", data={})])
    two = make_finding(evidence=[Evidence(kind="http", title="http", data={}), Evidence(kind="comparison", title="comparison", data={})])
    assert evidence_quality(two) > evidence_quality(one)


def test_triage_deduplicates():
    a = make_finding(title="Same")
    b = make_finding(title="Same", confidence=0.7)
    rows = triage([a, b])
    assert len(rows) == 1
    assert rows[0]["count"] == 2


def test_json_report_contains_summary(tmp_path: Path):
    output = tmp_path / "report.json"
    write_json([make_finding()], output)
    data = json.loads(output.read_text())
    assert data["version"] == "1.6.0"
    assert data["summary"]["total"] == 1
    assert data["ai_triage"]


def test_sarif_report(tmp_path: Path):
    output = tmp_path / "report.sarif"
    write_sarif([make_finding()], output)
    data = json.loads(output.read_text())
    assert data["version"] == "2.1.0"
    assert data["runs"][0]["results"]


def test_openapi_yaml_load(tmp_path: Path, monkeypatch):
    path = tmp_path / "openapi.yaml"
    path.write_text("""
openapi: 3.0.0
info:
  title: Test
  version: '1'
paths:
  /transfer:
    post:
      responses:
        '200':
          description: ok
components:
  securitySchemes:
    bearer:
      type: http
      scheme: bearer
""".strip())
    url = "http://127.0.0.1:9999"
    context = ScanContext(target=url, allow_hosts=["127.0.0.1"], options={"openapi": str(path)})
    # API engine will emit an informational request-failed finding, but should still parse YAML.
    findings = list(ApiEngine().run(context))
    assert any("state-changing" in f.title.lower() or "security" in f.title.lower() for f in findings)


def test_report_and_store_redact_sensitive_evidence(tmp_path: Path):
    from beltu.core.store import FindingStore
    finding = make_finding(evidence=[Evidence(kind="http", title="headers", data={"Authorization": "Bearer super-secret", "visible": "ok"})])
    store = FindingStore(tmp_path / "findings.sqlite3")
    store.save(finding)
    stored = store.all()[0]
    payload = json.dumps(stored.model_dump(mode="json"))
    assert "super-secret" not in payload
    assert "[REDACTED]" in payload


def test_html_report_redacts_sensitive_evidence(tmp_path: Path):
    from beltu.core.models import Evidence
    output = tmp_path / "report.html"
    finding = make_finding(evidence=[Evidence(kind="http", title="secret header", data={"Authorization": "Bearer super-secret", "safe": "ok"})])
    write_html([finding], output)
    text = output.read_text()
    assert "super-secret" not in text
    assert "[REDACTED]" in text


def test_custom_auth_header_redaction():
    headers = safe_headers({"X-Auth-Token": "custom-secret-value", "X-Trace": "ok"})
    assert "custom-secret-value" not in headers["X-Auth-Token"]
    assert headers["X-Trace"] == "ok"


def test_guess_corpus_has_10000_cases_and_multiple_engines():
    from beltu.guessing import generate_cases
    cases = generate_cases(count=10_000, seed=7)
    assert len(cases) == 10_000
    assert len({case.id for case in cases}) == 10_000
    assert len({case.engine for case in cases}) >= 10


def test_access_control_corpus_has_10000_cases():
    from beltu.guessing import generate_cases
    cases = generate_cases("access-control", count=10_000, seed=7)
    assert len(cases) == 10_000
    assert any(case.value == "carlos" for case in cases)
    assert any(case.value == "9999" for case in cases)


def test_access_control_guess_prioritizes_common_id_and_stops_on_marker(monkeypatch):
    from beltu.engines import access_guess
    from beltu.core.http import HttpResult

    calls = []
    def fake_request(context, method="GET", url=None, **kwargs):
        calls.append(url or context.target)
        target = url or context.target
        value = dict(parse_qsl(urlsplit(target).query)).get("id", "")
        if value == "carlos":
            text = "user=carlos UNIQUE_TARGET_MARKER"
        else:
            text = "user=wiener baseline"
        return HttpResult(True, target, 200, {"content-type": "text/plain"}, {"content-type": ["text/plain"]}, text, 1.0)

    monkeypatch.setattr(access_guess, "request", fake_request)
    context = ScanContext(target="http://example.test/my-account?id=1", allow_hosts=["example.test"])
    result = access_guess.run_access_control_guess(
        context,
        headers_raw="Cookie: session=test",
        object_param="id",
        count=20,
        delay_seconds=0.05,
        markers=["UNIQUE_TARGET_MARKER"],
        stop_on_hit=True,
    )
    assert result.findings
    assert result.findings[0].verification.value == "corroborated"
    assert "id=carlos" in calls[-1]
    assert result.attempted >= 2


def test_smart_access_corpus_contains_names_case_and_alnum():
    from beltu.guessing import generate_cases
    cases = generate_cases("access-control", count=2000, seed=11)
    values = [c.value for c in cases]
    assert any(v.lower() == "carlos" for v in values)
    assert any(v == v.upper() and v.isalpha() for v in values if len(v) >= 4)
    assert any(any(ch.isdigit() for ch in v) and any(ch.isalpha() for ch in v) and 4 <= len(v) <= 15 for v in values)
    assert len(set(values)) >= 1900


def test_access_guess_candidate_order_is_not_sequential(monkeypatch):
    from beltu.engines import access_guess
    from beltu.core.http import HttpResult
    calls = []
    def fake_request(context, method="GET", url=None, **kwargs):
        calls.append(url or context.target)
        return HttpResult(True, url or context.target, 403, {}, {}, "denied", 0.1)
    monkeypatch.setattr(access_guess, "request", fake_request)
    from beltu.core.models import ScanContext
    context = ScanContext(target="http://example.test/object?id=1", allow_hosts=["example.test"])
    access_guess.run_access_control_guess(context, headers_raw="Cookie: session=test", object_param="id", count=25, delay_seconds=0.05, stop_on_hit=True)
    values = [dict(parse_qsl(urlsplit(u).query)).get("id", "") for u in calls[1:]]
    assert values[:5] != ["1", "2", "3", "4", "5"]
    assert "carlos" in values[:25]


def test_smart_stream_produces_long_diverse_access_sequence():
    from beltu.guessing import iter_cases
    cases = []
    stream = iter_cases("access-control", count=50_000, seed=123)
    for _ in range(50_000):
        cases.append(next(stream))
    values = [c.value for c in cases]
    assert len(values) == 50_000
    assert len(set(values)) > 49_000
    structured = [c.value for c in cases if c.family == "alnum"]
    assert structured
    assert all(4 <= len(v) <= 15 and v.isalnum() for v in structured)
    assert any(v.lower() == "carlos" for v in values)
    assert any(any(ch.isdigit() for ch in v) and any(ch.isalpha() for ch in v) for v in values)


def test_ai_routes_cover_all_engines():
    from beltu.ai_router import ENGINE_ROUTES
    required = {"gpt-4o", "codellama", "claude", "deepseek-coder-v2", "sklearn", "burp", "pentestgpt", "langgraph", "langchain", "interactsh", "pyjwt"}
    for name in ("ssrf", "csrf", "api", "access-control", "authentication", "misconfiguration", "cryptography", "integrity", "disclosure", "cors", "open-redirect", "jwt"):
        assert name in ENGINE_ROUTES
        assert set(ENGINE_ROUTES[name]) & required


def test_ai_enrichment_is_local_by_default():
    from beltu.ai_router import enrich_findings
    finding = make_finding()
    enriched = enrich_findings([finding], remote=False)
    assert enriched[0].ai["local"]["score"] >= 0
    assert "gpt-4o" not in enriched[0].ai["providers_used"]


def test_claude_legacy_model_is_routed(monkeypatch):
    from beltu.ai_providers import _anthropic_model
    monkeypatch.setenv("BELTU_ANTHROPIC_MODEL", "claude-3-5-sonnet-20240620")
    model, note = _anthropic_model()
    assert model == "claude-sonnet-4-6"
    assert note and "retired" in note.lower()


def test_ai_provider_modules_import_without_network():
    import beltu.ai_providers as providers
    assert callable(providers.openai_gpt4o)
    assert callable(providers.anthropic_claude)
    assert callable(providers.ollama_chat)
    assert callable(providers.pentestgpt_plan)
    assert callable(providers.deepseek_coder_v2)


def test_ai_provider_env_missing_is_safe(monkeypatch):
    from beltu.ai_providers import openai_gpt4o, anthropic_claude
    monkeypatch.delenv("BELTU_OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("BELTU_ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    assert openai_gpt4o("{}", timeout=0.1).ok is False
    assert anthropic_claude("{}", timeout=0.1).ok is False


def test_ai_metadata_is_redacted_in_store(tmp_path: Path):
    from beltu.core.store import FindingStore
    finding = make_finding(ai={"provider_results": {"gpt-4o": {"data": {"Authorization": "Bearer top-secret", "safe": "ok"}}}})
    store = FindingStore(tmp_path / "ai.sqlite3")
    store.save(finding)
    stored = store.all()[0]
    serialized = json.dumps(stored.model_dump(mode="json"))
    assert "top-secret" not in serialized
    assert "[REDACTED]" in serialized
