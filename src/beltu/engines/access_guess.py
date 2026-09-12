from __future__ import annotations

from dataclasses import dataclass
from difflib import SequenceMatcher
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from beltu.core.http import request
from beltu.core.models import Evidence, Finding, ScanContext, Severity, VerificationLevel
from beltu.engines.common import body_fingerprint
from beltu.guessing import generate_cases

from .access_control import _parse_headers


@dataclass(slots=True)
class GuessRunResult:
    findings: list[Finding]
    attempted: int
    baseline_status: int | None
    stopped_on_hit: bool


def _set_query_value(target: str, parameter: str, value: str) -> str:
    parts = urlsplit(target)
    pairs = parse_qsl(parts.query, keep_blank_values=True)
    mutated: list[tuple[str, str]] = []
    replaced = False
    for key, current in pairs:
        if key == parameter and not replaced:
            mutated.append((key, value))
            replaced = True
        else:
            mutated.append((key, current))
    if not replaced:
        mutated.append((parameter, value))
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(mutated), parts.fragment))


def run_access_control_guess(
    context: ScanContext,
    *,
    headers_raw: str,
    object_param: str,
    count: int,
    start: int = 1,
    delay_seconds: float = 0.15,
    stop_on_hit: bool = True,
    markers: list[str] | None = None,
) -> GuessRunResult:
    import time

    headers = _parse_headers(headers_raw)
    if not headers:
        return GuessRunResult([], 0, None, False)
    if not object_param.strip():
        return GuessRunResult([], 0, None, False)
    if count > 10_000:
        raise ValueError("Guess runs are capped at 10,000 requests per invocation.")
    if delay_seconds < 0.05:
        raise ValueError("Use --delay >= 0.05 seconds to keep lab/authorized targets from being flooded.")

    context_one = context.model_copy(update={"headers": headers})
    baseline = request(context_one)
    if not baseline.ok:
        return GuessRunResult([], 0, baseline.status_code, False)

    # Smart strategy: common names/roles first, then a deterministic mixed corpus.
    # Deliberately avoids naive 1,2,3,... ordering. Numeric identifiers are interleaved
    # through a seeded permutation and structured 4..15-char alphanumeric candidates.
    cases = generate_cases("access-control", max(count * 3, 300), seed=1337)
    corpus_values = [case.value for case in cases]
    priority = ["carlos", "admin", "administrator", "user", "guest", "test", "me", "self", "0", "1", "2"]
    values: list[str] = []
    seen: set[str] = set()

    def add(value: str) -> None:
        if value and value not in seen and len(values) < count:
            seen.add(value)
            values.append(value)

    for value in priority:
        add(value)
    for value in corpus_values:
        add(value)
        if len(values) >= count:
            break

    marker_values = [m.strip() for m in (markers or []) if m.strip()]
    findings: list[Finding] = []
    attempted = baseline.requests_made
    stopped = False
    baseline_status = baseline.status_code
    baseline_fp = body_fingerprint(baseline.text)
    baseline_body = baseline.text
    for value in values[:count]:
        mutated_target = _set_query_value(context.target, object_param, value)
        mutated = request(context_one, url=mutated_target)
        attempted += mutated.requests_made
        if not mutated.ok:
            time.sleep(delay_seconds)
            continue
        status = int(mutated.status_code or 0)
        marker_hits = [m for m in marker_values if m in mutated.text and m not in baseline_body]
        similarity = SequenceMatcher(None, baseline_body[:50_000], mutated.text[:50_000], autojunk=False).ratio()
        if marker_hits:
            findings.append(Finding(
                engine="access-control",
                category="Broken Access Control",
                title="Guessing discovered target-object content in the same session",
                severity=Severity.high,
                confidence=0.99,
                target=mutated_target,
                parameter=object_param,
                verification=VerificationLevel.corroborated,
                description="A marker supplied by the operator as unique to the protected target object appeared after mutating the object identifier. This is strong evidence for object-level authorization failure in the authorized test environment.",
                remediation="Enforce object ownership/authorization checks server-side for every resource identifier.",
                evidence=[Evidence(kind="guess", title="Matched authorization marker", data={
                    "attempted_value": value,
                    "baseline_status": baseline_status,
                    "mutated_status": status,
                    "matched_markers": marker_hits,
                    "baseline_fingerprint": baseline_fp,
                    "mutated_fingerprint": body_fingerprint(mutated.text),
                })],
                requests_made=attempted,
            ))
            stopped = True
            if stop_on_hit:
                break
        elif status == 200 and baseline_status == 200 and similarity >= 0.995 and value != _baseline_parameter_value(context.target, object_param):
            findings.append(Finding(
                engine="access-control",
                category="Broken Access Control",
                title="Object identifier guess produced a highly similar successful response",
                severity=Severity.medium,
                confidence=0.72,
                target=mutated_target,
                parameter=object_param,
                verification=VerificationLevel.candidate,
                description="A guessed object identifier produced a highly similar successful response. Similarity alone is not proof of unauthorized object access and should be manually verified against the returned resource.",
                remediation="Verify ownership checks for the requested object and deny access when the object is outside the authenticated principal's authorization scope.",
                evidence=[Evidence(kind="guess", title="Response similarity candidate", data={
                    "attempted_value": value,
                    "baseline_status": baseline_status,
                    "mutated_status": status,
                    "similarity": round(similarity, 4),
                    "baseline_fingerprint": baseline_fp,
                    "mutated_fingerprint": body_fingerprint(mutated.text),
                })],
                requests_made=attempted,
            ))
            if stop_on_hit:
                stopped = True
                break
        time.sleep(delay_seconds)
    return GuessRunResult(findings, attempted, baseline_status, stopped)


def _baseline_parameter_value(target: str, parameter: str) -> str | None:
    return next((value for key, value in parse_qsl(urlsplit(target).query, keep_blank_values=True) if key == parameter), None)
