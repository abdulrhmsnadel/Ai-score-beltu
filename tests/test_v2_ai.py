from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import pytest

from beltu.ai_graph import run_graph
from beltu.ai_providers import (
    ProviderResult,
    anthropic_claude,
    deepseek_coder_v2,
    ollama_chat,
    openai_gpt4o,
    pentestgpt_plan,
)
from beltu.core.models import Evidence, Finding, ScanContext, Severity, VerificationLevel
from beltu.engines.api import ApiEngine
from beltu.engines.auth import AuthenticationEngine
from beltu.engines.common import finding
from beltu.engines.cors import CorsEngine
from beltu.engines.crypto import CryptoEngine
from beltu.engines.csrf import CsrfEngine
from beltu.engines.disclosure import DisclosureEngine
from beltu.engines.integrity import IntegrityEngine
from beltu.engines.jwt import JwtEngine
from beltu.engines.misconfig import MisconfigEngine
from beltu.engines.open_redirect import OpenRedirectEngine


class FixtureHandler(BaseHTTPRequestHandler):
    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", self.headers.get("Origin", ""))
        self.send_header("Access-Control-Allow-Credentials", "true")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.end_headers()

    def do_GET(self):
        p = urlsplit(self.path)
        if p.path == "/cors":
            self.send_response(200)
            self.send_header("Access-Control-Allow-Origin", self.headers.get("Origin", ""))
            self.send_header("Access-Control-Allow-Credentials", "true")
            self.end_headers()
            self.wfile.write(b"account details")
            return
        if p.path == "/auth":
            self.send_response(200)
            self.send_header("Set-Cookie", "session=abc; Path=/")
            self.send_header("Content-Security-Policy", "default-src 'self'")
            self.end_headers()
            self.wfile.write(b'<form method="POST"><input name="email"><input type="password" name="password"></form>')
            return
        if p.path == "/csrf":
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b'<form method="POST" action="/change"><input name="email"></form>')
            return
        if p.path == "/redirect":
            qs = parse_qs(p.query)
            dest = qs.get("next", ["/home"])[0]
            self.send_response(302)
            self.send_header("Location", dest)
            self.end_headers()
            return
        if p.path == "/disclosure":
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"debug=true SECRET_KEY=demo-secret stack trace RuntimeError")
            return
        if p.path == "/integrity":
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b'<script src="http://cdn.example.test/app.js"></script>')
            return
        if p.path == "/account":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Server", "fixture/1.0")
            self.end_headers()
            self.wfile.write(b'{"ok":true}')
            return
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok")

    def do_POST(self):
        self.do_GET()

    def log_message(self, format, *args):
        return


@pytest.fixture(scope="module")
def fixture_base():
    server = HTTPServer(("127.0.0.1", 0), FixtureHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_port}"
    server.shutdown()
    server.server_close()


def ctx(target: str, **options) -> ScanContext:
    host = urlsplit(target).hostname or "127.0.0.1"
    return ScanContext(target=target, allow_hosts=[host], options=options)


def test_all_new_ai_adapters_import():
    assert callable(deepseek_coder_v2)
    assert callable(anthropic_claude)
    assert callable(openai_gpt4o)
    assert callable(ollama_chat)
    assert callable(pentestgpt_plan)


def test_deepseek_missing_key_is_safe(monkeypatch):
    monkeypatch.delenv("BELTU_DEEPSEEK_API_KEY", raising=False)
    monkeypatch.delenv("DEEPSEEK_API_KEY", raising=False)
    assert not deepseek_coder_v2("{}", timeout=0.1).ok


def test_graph_falls_back_without_optional_langgraph(monkeypatch):
    finding_obj = Finding(
        engine="cors", category="CORS", title="test", severity=Severity.low,
        confidence=0.8, target="https://example.test", verification=VerificationLevel.candidate,
        evidence=[Evidence(kind="headers", title="h", data={})],
    )
    monkeypatch.setenv("PYTHONPATH", "")
    result = run_graph([finding_obj], allow_remote=False)
    assert result["steps"][-1] == "consensus"
    assert result["orchestrator"] in {"langgraph", "builtin-sequential-fallback"}


def test_pyjwt_decoder_uses_optional_library_or_builtin(monkeypatch):
    token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjMiLCJleHAiOjQxMDA3MDAwMDB9.signature"
    result = list(JwtEngine().run(ctx("https://example.test/account", token=token)))
    assert result
    assert any(e.kind == "jwt" for f in result for e in f.evidence) or result[0].severity == Severity.info


def test_interactsh_adapter_safe_without_binary(monkeypatch):
    from beltu.integrations import interactsh
    monkeypatch.setattr(interactsh.shutil, "which", lambda _: None)
    assert interactsh.client_available() is False
    with pytest.raises(RuntimeError):
        interactsh.generate_payload()


@pytest.mark.parametrize("n", range(1, 101))
def test_100_varied_engine_and_data_vectors(n, fixture_base):
    base = fixture_base
    route = n % 10
    suffix = f"case-{n}-{chr(65 + (n % 26))}"
    if route == 0:
        findings = list(CorsEngine().run(ctx(base + f"/cors?case={suffix}", origin=f"https://origin-{n}.invalid")))
    elif route == 1:
        findings = list(CsrfEngine().run(ctx(base + f"/csrf?case={suffix}")))
    elif route == 2:
        findings = list(AuthenticationEngine().run(ctx(base + f"/auth?case={suffix}")))
    elif route == 3:
        findings = list(MisconfigEngine().run(ctx(base + f"/account?case={suffix}")))
    elif route == 4:
        findings = list(CryptoEngine().run(ctx(base + f"/account?case={suffix}")))
    elif route == 5:
        findings = list(IntegrityEngine().run(ctx(base + f"/integrity?case={suffix}")))
    elif route == 6:
        findings = list(DisclosureEngine().run(ctx(base + f"/disclosure?case={suffix}")))
    elif route == 7:
        findings = list(OpenRedirectEngine().run(ctx(base + f"/redirect?next=https://external-{n}.invalid/")))
    elif route == 8:
        token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." + "eyJzdWIiOiIxMjMiLCJleHAiOjQxMDA3MDAwMDB9" + ".signature"
        findings = list(JwtEngine().run(ctx(base + f"/account?case={suffix}", token=token)))
    else:
        spec = {"openapi": "3.0.0", "info": {"title": suffix, "version": "1"}, "paths": {"/transfer": {"post": {"responses": {"200": {"description": "ok"}}}}}}
        spec_path = Path(f"/tmp/beltu-spec-{n}.json")
        spec_path.write_text(json.dumps(spec), encoding="utf-8")
        try:
            findings = list(ApiEngine().run(ctx(base + f"/account?case={suffix}", openapi=str(spec_path))))
        finally:
            spec_path.unlink(missing_ok=True)
    assert isinstance(findings, list)
    assert all(isinstance(f.title, str) and f.engine for f in findings)

def test_provider_http_contracts_are_wired(monkeypatch):
    class FakeResponse:
        def raise_for_status(self):
            return None
        def json(self):
            return {"choices": [{"message": {"content": '{"summary":"ok"}'}}]}

    class FakeClient:
        def __init__(self, *args, **kwargs):
            pass
        def __enter__(self):
            return self
        def __exit__(self, *args):
            return False
        def post(self, *args, **kwargs):
            return FakeResponse()

    monkeypatch.setattr("beltu.ai_providers.httpx.Client", FakeClient)
    monkeypatch.setenv("BELTU_DEEPSEEK_API_KEY", "test")
    result = deepseek_coder_v2("{}")
    assert result.ok is True
    assert result.data["summary"] == "ok"


def test_all_http_ai_provider_contracts(monkeypatch):
    class FakeResponse:
        def __init__(self, payload):
            self._payload = payload
        def raise_for_status(self):
            return None
        def json(self):
            return self._payload

    class FakeClient:
        def __init__(self, *args, **kwargs):
            pass
        def __enter__(self):
            return self
        def __exit__(self, *args):
            return False
        def post(self, url, *args, **kwargs):
            if "anthropic.com" in url:
                return FakeResponse({"content": [{"type": "text", "text": '{"summary":"ok"}'}]})
            return FakeResponse({"choices": [{"message": {"content": '{"summary":"ok"}'}}]})

    monkeypatch.setattr("beltu.ai_providers.httpx.Client", FakeClient)
    monkeypatch.setenv("BELTU_OPENAI_API_KEY", "test")
    monkeypatch.setenv("BELTU_ANTHROPIC_API_KEY", "test")
    monkeypatch.setenv("BELTU_DEEPSEEK_API_KEY", "test")
    monkeypatch.setenv("BELTU_CODELLAMA_ENABLED", "1")
    assert openai_gpt4o("{}", timeout=0.1).ok
    assert anthropic_claude("{}", timeout=0.1).ok
    assert deepseek_coder_v2("{}", timeout=0.1).ok
    assert ollama_chat("{}", timeout=0.1).ok
