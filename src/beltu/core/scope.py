from __future__ import annotations

from urllib.parse import urlsplit


class ScopeError(ValueError):
    pass


def validate_url(url: str, allow_hosts: list[str], *, allow_http: bool = True) -> str:
    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ScopeError("Only absolute HTTP(S) URLs are supported.")
    if not allow_http and parsed.scheme != "https":
        raise ScopeError("HTTPS is required for this operation.")
    host = parsed.hostname.lower().rstrip(".")
    allowed = {h.lower().rstrip(".") for h in allow_hosts}
    if host not in allowed:
        raise ScopeError(f"Host '{host}' is not in the explicit allowlist.")
    return url


def validate_canary(url: str, allow_hosts: list[str]) -> str:
    # Canary targets are deliberately separate from target hosts and must be explicit too.
    return validate_url(url, allow_hosts, allow_http=False)
