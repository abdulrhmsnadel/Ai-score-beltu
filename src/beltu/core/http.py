from __future__ import annotations

from dataclasses import dataclass, field
import re
import time

import httpx

from .models import ScanContext

_SENSITIVE = re.compile(
    r"(?i)^(authorization|proxy-authorization|cookie|set-cookie|x-api-key|api-key|token|secret|password)$"
)



_SENSITIVE_KEY = re.compile(r"(?i)(?:authorization|proxy-authorization|cookie|set-cookie|x-api-key|api-key|password|passwd|token|secret|session|jwt|credential|private[_ -]?key)")

def redact_data(value):
    """Recursively redact secret-like mapping keys in evidence/report structures."""
    if isinstance(value, dict):
        return {
            key: ("[REDACTED]" if _SENSITIVE_KEY.search(str(key)) else redact_data(item))
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [redact_data(item) for item in value]
    if isinstance(value, tuple):
        return [redact_data(item) for item in value]
    if isinstance(value, str):
        value = re.sub(r"(?i)(bearer\s+)[A-Za-z0-9._~+/=-]+", r"\1[REDACTED]", value)
        value = re.sub(r"(?i)(password|passwd|secret|api[_-]?key|token|session)\s*([:=])\s*([^\s,;]+)", r"\1\2[REDACTED]", value)
        return value[:4000] + ("… [truncated]" if len(value) > 4000 else "")
    return value

def redact_url(url: str) -> str:
    """Redact sensitive query-string values while preserving target routing details."""
    try:
        from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
        parts = urlsplit(url)
        pairs = []
        for key, val in parse_qsl(parts.query, keep_blank_values=True):
            safe_val = "[REDACTED]" if _SENSITIVE_KEY.search(key) else val
            pairs.append((key, safe_val))
        return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(pairs), parts.fragment))
    except Exception:
        return url

def redact_value(value: str, *, keep_prefix: int = 4, keep_suffix: int = 2) -> str:
    value = value or ""
    if len(value) <= keep_prefix + keep_suffix + 4:
        return "[REDACTED]"
    return value[:keep_prefix] + "…[REDACTED]…" + value[-keep_suffix:]


def safe_headers(headers: dict[str, str]) -> dict[str, str]:
    return {
        key: redact_value(value) if _SENSITIVE_KEY.search(key) else value
        for key, value in headers.items()
    }


@dataclass(slots=True)
class HttpResult:
    ok: bool
    url: str
    status_code: int | None
    headers: dict[str, str]
    header_values: dict[str, list[str]] = field(default_factory=dict)
    text: str = ""
    elapsed_ms: float = 0.0
    error: str | None = None
    requests_made: int = 1
    truncated: bool = False
    history: list[int] = field(default_factory=list)

    def values(self, name: str) -> list[str]:
        return self.header_values.get(name.lower(), [])

    @property
    def evidence_headers(self) -> dict[str, str]:
        return safe_headers(self.headers)


def _decode(data: bytes, response: httpx.Response) -> str:
    encoding = response.encoding or "utf-8"
    return data.decode(encoding, errors="replace")


def _stream_text(response: httpx.Response, max_bytes: int) -> tuple[str, bool]:
    chunks: list[bytes] = []
    total = 0
    truncated = False
    for chunk in response.iter_bytes():
        remaining = max_bytes - total
        if remaining <= 0:
            truncated = True
            break
        if len(chunk) > remaining:
            chunks.append(chunk[:remaining])
            total += remaining
            truncated = True
            break
        chunks.append(chunk)
        total += len(chunk)
    return _decode(b"".join(chunks), response), truncated


def request(
    context: ScanContext,
    method: str = "GET",
    url: str | None = None,
    *,
    data: object | None = None,
    content: str | bytes | None = None,
    json: object | None = None,
    headers: dict[str, str] | None = None,
) -> HttpResult:
    target = url or context.target
    merged_headers = {"User-Agent": context.user_agent, **context.headers, **(headers or {})}
    started = time.perf_counter()
    attempts = 0
    history: list[int] = []
    try:
        with httpx.Client(
            timeout=context.timeout_seconds,
            follow_redirects=context.follow_redirects,
            headers=merged_headers,
            verify=context.verify_tls,
        ) as client:
            while True:
                attempts += 1
                with client.stream(method, target, data=data, content=content, json=json) as response:
                    history.append(response.status_code)
                    normalized = {k.lower(): v for k, v in response.headers.items()}
                    values = {name.lower(): response.headers.get_list(name) for name in response.headers}
                    if response.status_code in context.retry_statuses and attempts <= context.retries:
                        retry_after = response.headers.get("retry-after")
                        delay = 0.15
                        if retry_after:
                            try:
                                delay = min(float(retry_after), 2.0)
                            except ValueError:
                                pass
                        # Drain/close before retrying to keep the connection pool healthy.
                        response.close()
                        time.sleep(max(0.05, delay))
                        continue
                    text, truncated = _stream_text(response, context.max_body_bytes)
                    elapsed_ms = (time.perf_counter() - started) * 1000
                    return HttpResult(
                        ok=True,
                        url=str(response.url),
                        status_code=response.status_code,
                        headers=normalized,
                        header_values=values,
                        text=text,
                        elapsed_ms=elapsed_ms,
                        requests_made=attempts,
                        truncated=truncated,
                        history=history,
                    )
    except httpx.HTTPError as exc:
        elapsed_ms = (time.perf_counter() - started) * 1000
        return HttpResult(
            False,
            target,
            None,
            {},
            {},
            "",
            elapsed_ms,
            str(exc),
            attempts,
            False,
            history,
        )
