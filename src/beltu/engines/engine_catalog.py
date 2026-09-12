from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class EngineMeta:
    name: str
    display_name: str
    description: str
    inputs: tuple[str, ...]


CATALOG = [
    EngineMeta("ssrf", "SSRF", "Controlled canary-based URL fetching triage; no internal-network probing.", ("Target URL", "Operator-owned HTTPS canary", "Canary allowlist")),
    EngineMeta("csrf", "CSRF", "State-changing form and cookie posture analysis without submitting state changes.", ("Target HTML URL", "Target allowlist")),
    EngineMeta("api", "API Security", "OpenAPI security review for documented auth requirements and sensitive parameter placement.", ("API target", "OpenAPI JSON URL/file", "Target allowlist")),
    EngineMeta("access-control", "Broken Access Control", "Compares two dedicated test identities on the same resource with optional account-specific markers.", ("Resource URL", "One/two test identities", "Optional object parameter/value", "Optional markers")),
    EngineMeta("authentication", "Authentication", "Transport, session cookie, form, and session-flag checks without password guessing.", ("Login/auth URL", "Target allowlist")),
    EngineMeta("misconfiguration", "Security Misconfiguration", "Security headers, technology disclosure, and sensitive-response cache posture.", ("Target URL", "Target allowlist")),
    EngineMeta("cryptography", "Cryptographic Failures", "HTTPS/TLS version, certificate validity, HSTS, and Secure cookie checks.", ("HTTPS target", "Target allowlist")),
    EngineMeta("integrity", "Software & Data Integrity", "External script SRI and mixed-content checks on supplied HTML.", ("HTML target", "Target allowlist")),
    EngineMeta("disclosure", "Information Disclosure", "Debug, stack-trace, credential-like, and private-key disclosure triage with redaction.", ("Target URL", "Target allowlist")),
    EngineMeta("cors", "CORS", "Controlled-origin simple-request and preflight policy analysis.", ("Target URL", "Target allowlist", "Controlled test Origin")),
    EngineMeta("open-redirect", "Open Redirect", "Redirect-parameter testing without following external redirects.", ("URL with redirect-like parameter", "Target allowlist", "External marker URL")),
    EngineMeta("jwt", "JWT Security", "Local token-structure and claim-policy analysis; no forgery or brute force.", ("Authorized target URL", "Test JWT")),
]
