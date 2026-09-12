from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit, parse_qs

from beltu.core.models import ScanContext, Severity
from beltu.engines.api import ApiEngine
from beltu.engines.access_control import AccessControlEngine
from beltu.engines.auth import AuthenticationEngine
from beltu.engines.cors import CorsEngine
from beltu.engines.crypto import CryptoEngine
from beltu.engines.csrf import CsrfEngine
from beltu.engines.disclosure import DisclosureEngine
from beltu.engines.integrity import IntegrityEngine
from beltu.engines.jwt import JwtEngine
from beltu.engines.misconfig import MisconfigEngine
from beltu.engines.open_redirect import OpenRedirectEngine
from beltu.engines.ssrf import SsrfEngine


class Handler(BaseHTTPRequestHandler):
    def _write(self, body: str, status: int = 200, headers: dict[str, str] | None = None):
        payload = body.encode()
        self.send_response(status)
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Content-Type", "text/html; charset=utf-8")
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(payload)

    def do_OPTIONS(self):
        self._write("", 204, {
            "Access-Control-Allow-Origin": self.headers.get("Origin", ""),
            "Access-Control-Allow-Credentials": "true",
            "Access-Control-Allow-Methods": "GET, POST",
        })

    def do_GET(self):
        origin = self.headers.get("Origin", "")
        path = urlsplit(self.path).path
        if path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "https://beltu.invalid/")
            self.end_headers()
            return
        if path == "/fetch":
            self._write("fetched", headers={"Content-Type": "text/plain"})
            return
        if path == "/auth":
            self._write('<form method="POST"><input name="email"><input type="password" name="password"></form>', headers={"Set-Cookie": "session=abc; Path=/"})
            return
        if path == "/csrf":
            self._write('<form method="POST" action="/transfer"><input name="amount" value="1"></form>')
            return
        if path == "/integrity":
            self._write('<script src="https://cdn.example.test/a.js"></script><img src="http://cdn.example.test/p.png">')
            return
        if path == "/disclosure":
            self._write("Traceback (most recent call last) DEBUG=true secret='supersecret'")
            return
        if path == "/cors":
            self._write("ok", headers={"Access-Control-Allow-Origin": origin, "Access-Control-Allow-Credentials": "true"})
            return
        if path == "/account":
            self._write('{"user":"A","marker":"A_ONLY_MARKER"}', headers={"Content-Type": "application/json"})
            return
        if path == "/object":
            object_id = parse_qs(urlsplit(self.path).query).get("id", [""])[0]
            if object_id == "carlos":
                self._write('{"user":"carlos","marker":"TARGET_MARKER"}', headers={"Content-Type": "application/json"})
            else:
                self._write('{"user":"wiener","marker":"BASELINE_MARKER"}', headers={"Content-Type": "application/json"})
            return
        self._write('<html><body>hello</body></html>')

    def log_message(self, *_args):
        pass


def server():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    return srv, f"http://127.0.0.1:{srv.server_port}"


def ctx(url: str, **options):
    return ScanContext(target=url, allow_hosts=[urlsplit(url).hostname or ""], options=options)


def test_engine_set_behaviour(tmp_path: Path):
    srv, base = server()
    try:
        findings = list(CorsEngine().run(ctx(base + "/cors", origin="https://beltu.invalid")))
        assert any(f.severity == Severity.high for f in findings)

        findings = list(OpenRedirectEngine().run(ctx(base + "/redirect?next=/home", redirect_target="https://beltu.invalid/")))
        assert findings and findings[0].engine == "open-redirect"

        findings = list(SsrfEngine().run(ctx(base + "/fetch?url=https%3A%2F%2Fexample.test%2F", canary_url="https://beltu.invalid/canary", canary_allow_hosts=["beltu.invalid"])))
        assert findings and findings[0].severity == Severity.info

        findings = list(CsrfEngine().run(ctx(base + "/csrf")))
        assert any("no obvious anti-CSRF" in f.title for f in findings)

        findings = list(AuthenticationEngine().run(ctx(base + "/auth")))
        assert any("HttpOnly" in f.title for f in findings)
        assert any("SameSite" in f.title for f in findings)

        findings = list(DisclosureEngine().run(ctx(base + "/disclosure")))
        assert findings
        for f in findings:
            for e in f.evidence:
                assert "supersecret" not in json.dumps(e.data)

        findings = list(IntegrityEngine().run(ctx(base + "/integrity")))
        assert len(findings) >= 1
        assert not any("Mixed-content" in f.title for f in findings)

        findings = list(MisconfigEngine().run(ctx(base + "/account")))
        assert findings

        findings = list(CryptoEngine().run(ctx(base + "/account")))
        assert findings and findings[0].severity == Severity.high

        a = "Cookie: session=A"
        b = "Cookie: session=B"
        findings = list(AccessControlEngine().run(ctx(base + "/account", identity_a_headers=a, identity_b_headers=b, markers_a=["A_ONLY_MARKER"])))
        assert any(f.severity == Severity.high for f in findings)

        object_findings = list(AccessControlEngine().run(ctx(base + "/object?id=wiener", identity_headers=a, object_param="id", object_value="carlos", markers_target=["TARGET_MARKER"])))
        assert object_findings
        assert object_findings[0].verification.value == "corroborated"

        token = "eyJhbGciOiJub25lIn0.eyJzdWIiOiIxIn0.signature"
        findings = list(JwtEngine().run(ctx(base + "/account", token=token)))
        assert any(f.severity == Severity.high for f in findings)

        spec_path = tmp_path / "openapi.json"
        spec_path.write_text(json.dumps({
            "openapi": "3.0.0",
            "info": {"title": "t", "version": "1"},
            "paths": {"/transfer": {"post": {"responses": {"200": {"description": "ok"}}}}},
            "components": {"securitySchemes": {"bearer": {"type": "http", "scheme": "bearer"}}},
        }))
        findings = list(ApiEngine().run(ctx(base + "/account", openapi=str(spec_path))))
        assert findings

        spec_no_auth_path = tmp_path / "openapi-public.json"
        spec_no_auth_path.write_text(json.dumps({
            "openapi": "3.0.0",
            "info": {"title": "public", "version": "1"},
            "security": [],
            "paths": {"/status": {"get": {"responses": {"200": {"description": "ok"}}}}},
        }))
        findings = list(ApiEngine().run(ctx(base + "/account", openapi=str(spec_no_auth_path))))
        assert any("defines no securitySchemes" in f.title for f in findings)
    finally:
        srv.shutdown()


def test_engine_edge_cases(tmp_path: Path):
    srv, base = server()
    try:
        # Same-origin CORS reflection must not be mislabeled as external-origin CORS.
        same_origin = f"http://127.0.0.1:{srv.server_port}"
        findings = list(CorsEngine().run(ctx(base + "/cors", origin=same_origin)))
        assert not any("external Origin" in f.title for f in findings)

        # Integrity mixed-content signal applies to HTTPS pages, not HTTP pages.
        findings = list(IntegrityEngine().run(ctx(base + "/integrity")))
        assert not any("Mixed-content" in f.title for f in findings)

        # No-op object mutation should stop before sending the second request.
        findings = list(AccessControlEngine().run(ctx(base + "/object?id=wiener", identity_headers="Cookie: session=A", object_param="id", object_value="wiener", markers_target=["TARGET_MARKER"])))
        assert findings and "matches the baseline" in findings[0].title
    finally:
        srv.shutdown()
