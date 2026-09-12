from beltu.core.models import Finding, Severity
from beltu.core.scope import ScopeError, validate_url
from beltu.engines.engine_catalog import CATALOG
from beltu.engines.registry import ENGINE_MAP, get_engine


def test_scope_guard():
    assert validate_url("https://example.com/a", ["example.com"]) == "https://example.com/a"
    try:
        validate_url("https://other.example/a", ["example.com"])
    except ScopeError:
        pass
    else:
        raise AssertionError("out-of-scope target was accepted")


def test_all_engines_registered():
    assert len(ENGINE_MAP) == 12
    assert {m.name for m in CATALOG} == set(ENGINE_MAP)
    for name in ENGINE_MAP:
        assert get_engine(name).name == name


def test_finding():
    f = Finding(engine="test", category="Test", title="x", severity=Severity.low, confidence=0.5, target="https://example.com")
    assert f.status.value == "new"


def test_shortcuts():
    from beltu.cli import expand_shortcuts

    assert expand_shortcuts(["-a", "https://example.com"]) == ["assess", "https://example.com"]
    assert expand_shortcuts(["-t", "cors", "https://example.com"]) == ["scan", "cors", "https://example.com"]
    assert expand_shortcuts(["-f", "--severity", "high"]) == ["findings", "list", "--severity", "high"]
    assert expand_shortcuts(["-g", "-r", "report.html"]) == ["report", "-r", "report.html"]
    assert expand_shortcuts(["-h"]) == ["--help"]


def test_ai_triage_signals_evidence():
    from beltu.ai import analyze_finding
    from beltu.core.models import Evidence, VerificationLevel

    weak = Finding(engine="t", category="T", title="candidate", severity=Severity.medium, confidence=0.5, target="https://example.com")
    strong = weak.model_copy(update={
        "confidence": 0.99,
        "verification": VerificationLevel.confirmed,
        "evidence": [Evidence(kind="http", title="proof", data={"status": 302})],
    })
    assert analyze_finding(strong).score > analyze_finding(weak).score
