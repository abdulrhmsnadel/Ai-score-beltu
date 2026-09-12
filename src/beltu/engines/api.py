from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from beltu.core.engine import Engine
from beltu.core.http import request
from beltu.core.models import Evidence, Finding, ScanContext, Severity
from beltu.core.scope import validate_url

from .common import base_context, finding


STATE_CHANGING = {"post", "put", "patch", "delete"}


class ApiEngine(Engine):
    name = "api"
    category = "API Security"
    description = "Reviews a supplied OpenAPI document and selected API responses for authentication, authorization, and unsafe exposure indicators."

    @property
    def requires(self) -> list[str]:
        return ["Authorized API target", "OpenAPI JSON/YAML-equivalent JSON document", "Explicit allowlist"]

    def _load_spec(self, context: ScanContext) -> tuple[dict[str, Any] | None, str]:
        source = str(context.options.get("openapi", "")).strip()
        if not source:
            return None, "No OpenAPI JSON source was supplied."
        if source.startswith(("http://", "https://")):
            validate_url(source, context.allow_hosts)
            response = request(context, url=source)
            if not response.ok:
                return None, response.error or "OpenAPI request failed."
            try:
                data = json.loads(response.text)
            except json.JSONDecodeError:
                try:
                    import yaml
                    data = yaml.safe_load(response.text)
                except Exception as exc:
                    return None, f"OpenAPI source is not valid JSON/YAML: {exc}"
            if not isinstance(data, dict):
                return None, "OpenAPI document root must be an object."
            return data, source
        path = Path(source)
        if not path.exists():
            return None, "OpenAPI local file does not exist."
        try:
            raw = path.read_text(encoding="utf-8")
            try:
                data = json.loads(raw)
            except json.JSONDecodeError:
                import yaml
                data = yaml.safe_load(raw)
        except (OSError, json.JSONDecodeError, ValueError) as exc:
            return None, str(exc)
        except Exception as exc:
            return None, f"OpenAPI YAML parsing failed: {exc}"
        if not isinstance(data, dict):
            return None, "OpenAPI document root must be an object."
        return data, str(path)

    def run(self, context: ScanContext):
        target = base_context(context)
        findings: list[Finding] = []
        response = request(context)
        if not response.ok:
            findings.append(finding(context, self.name, self.category, "API target request failed", Severity.info, 0.1, response.error or "Request failed.", "Verify the authorized endpoint and supplied headers."))
        spec, source = self._load_spec(context)
        if not spec:
            findings.append(finding(context, self.name, self.category, "API specification review needs input", Severity.info, 1.0, source, "Provide an OpenAPI JSON file or an in-scope URL."))
            return findings

        version = str(spec.get("openapi", spec.get("swagger", "unknown")))
        global_security = spec.get("security")
        global_security_present = isinstance(global_security, list) and len(global_security) > 0
        components = spec.get("components", {}) if isinstance(spec.get("components", {}), dict) else {}
        security_schemes = components.get("securitySchemes", {}) if isinstance(components, dict) else {}
        if not security_schemes:
            findings.append(finding(context, self.name, self.category, "OpenAPI document defines no securitySchemes", Severity.medium, 0.86, "The supplied API specification does not define reusable authentication schemes. This may be documentation drift or a real unauthenticated API.", "Define and enforce the API's authentication mechanisms in the specification and implementation.", evidence=[Evidence(kind="openapi", title="API security metadata", data={"source": source, "version": version})]))
        elif not global_security_present:
            findings.append(finding(context, self.name, self.category, "OpenAPI document has no global security requirement", Severity.low, 0.78, "Authentication schemes exist, but no top-level security requirement was declared.", "Document security requirements globally or at each operation, and enforce them server-side."))

        insecure_operations: list[str] = []
        unauthenticated_operations: list[str] = []
        sensitive_query_keys: list[str] = []
        paths = spec.get("paths", {})
        if isinstance(paths, dict):
            for path, item in paths.items():
                if not isinstance(item, dict):
                    continue
                for method, operation in item.items():
                    if method.lower() not in {"get", "post", "put", "patch", "delete", "options", "head", "trace"} or not isinstance(operation, dict):
                        continue
                    op_name = f"{method.upper()} {path}"
                    operation_security = operation.get("security")
                    if isinstance(operation_security, list):
                        has_security = len(operation_security) > 0
                    else:
                        has_security = global_security_present
                    if not has_security:
                        unauthenticated_operations.append(op_name)
                    if method.lower() in STATE_CHANGING and not has_security:
                        insecure_operations.append(op_name)
                    params = operation.get("parameters", [])
                    if isinstance(params, list):
                        for param in params:
                            if not isinstance(param, dict):
                                continue
                            name = str(param.get("name", "")).lower()
                            if param.get("in") == "query" and any(token in name for token in ("password", "secret", "token", "apikey", "api_key")):
                                sensitive_query_keys.append(op_name + " -> " + name)

        if insecure_operations:
            findings.append(finding(context, self.name, self.category, "State-changing API operations lack documented authentication requirements", Severity.high, 0.93, f"Found {len(insecure_operations)} documented state-changing operation(s) without security requirements.", "Require and document appropriate authentication/authorization on state-changing operations and verify enforcement server-side.", evidence=[Evidence(kind="openapi", title="Unprotected state-changing operations", data={"operations": insecure_operations[:200]})]))
        elif unauthenticated_operations:
            findings.append(finding(context, self.name, self.category, "API operations lack documented authentication requirements", Severity.medium, 0.82, f"Found {len(unauthenticated_operations)} operation(s) without documented security requirements.", "Explicitly mark public operations as intentional and require security on protected operations." , evidence=[Evidence(kind="openapi", title="Operations without security", data={"operations": unauthenticated_operations[:200]})]))

        if sensitive_query_keys:
            findings.append(finding(context, self.name, self.category, "Sensitive-looking values are documented in query parameters", Severity.medium, 0.76, "The API specification places parameter names such as token/secret/password in the query string. Query data can be exposed through logs, browser history, proxies, and referrers.", "Prefer request bodies or authorization headers for sensitive values and review logging/proxy behavior.", evidence=[Evidence(kind="openapi", title="Sensitive query parameters", data={"parameters": sensitive_query_keys[:200]})]))

        basic_auth = [name for name, value in security_schemes.items() if isinstance(value, dict) and value.get("type") == "http" and str(value.get("scheme", "")).lower() == "basic"]
        if basic_auth:
            findings.append(finding(context, self.name, self.category, "OpenAPI defines HTTP Basic authentication", Severity.low, 0.98, f"Basic authentication schemes: {', '.join(basic_auth[:20])}. Basic auth can be acceptable with strong transport and lifecycle controls, but credentials are reusable secrets per request.", "Prefer modern token-based authentication where appropriate, and always require HTTPS for Basic credentials.", evidence=[Evidence(kind="openapi", title="Basic authentication schemes", data={"schemes": basic_auth})]))

        return findings
