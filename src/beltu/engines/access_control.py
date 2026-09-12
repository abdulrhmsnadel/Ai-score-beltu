from __future__ import annotations

import json
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from beltu.core.engine import Engine
from beltu.core.http import request
from beltu.core.models import Evidence, Finding, ScanContext, Severity, VerificationLevel

from .common import base_context, body_fingerprint, finding


def _parse_headers(raw: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for line in raw.splitlines():
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        if key.strip():
            result[key.strip()] = value.strip()
    return result


def _json_shape(text: str) -> str | None:
    try:
        data = json.loads(text)
    except Exception:
        return None
    if isinstance(data, dict):
        return "dict:" + ",".join(sorted(map(str, data.keys()))[:80])
    if isinstance(data, list):
        return f"list:{len(data)}"
    return type(data).__name__


def _set_query_value(target: str, parameter: str, value: str) -> str:
    parts = urlsplit(target)
    pairs = parse_qsl(parts.query, keep_blank_values=True)
    replaced = False
    mutated: list[tuple[str, str]] = []
    for key, current in pairs:
        if key == parameter and not replaced:
            mutated.append((key, value))
            replaced = True
        else:
            mutated.append((key, current))
    if not replaced:
        mutated.append((parameter, value))
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(mutated), parts.fragment))


class AccessControlEngine(Engine):
    name = "access-control"
    category = "Broken Access Control"
    description = "Supports both two-identity response comparison and same-session object/resource mutation using operator-supplied test accounts."

    @property
    def requires(self) -> list[str]:
        return [
            "Authorized resource URL",
            "One or two dedicated test identities",
            "Permission to compare or mutate object identifiers",
        ]

    def _marker_findings(
        self,
        context: ScanContext,
        target: str,
        baseline,
        mutated,
        markers: list[str],
        *,
        title_prefix: str,
        target_value: str,
    ) -> list[Finding]:
        hits = [marker for marker in markers if marker and marker in mutated.text and marker not in baseline.text]
        if not hits:
            return []
        return [Finding(
            engine=self.name,
            category=self.category,
            title=f"{title_prefix} response contains the target-object marker(s)",
            severity=Severity.high,
            confidence=0.97,
            target=target,
            verification=VerificationLevel.corroborated,
            description="A marker supplied by the operator as unique to the target object was observed after changing the object identifier. This is strong evidence for further object-level authorization verification when the marker is genuinely unique.",
            remediation="Enforce server-side authorization and object-ownership checks for every requested resource, independent of client-controlled identifiers.",
            evidence=[Evidence(kind="comparison", title="Object mutation marker leak", data={
                "baseline_status": baseline.status_code,
                "mutated_status": mutated.status_code,
                "target_value": target_value,
                "matched_markers": hits,
                "baseline_fingerprint": body_fingerprint(baseline.text),
                "mutated_fingerprint": body_fingerprint(mutated.text),
            })],
        )]

    def _run_object_mutation(self, context: ScanContext) -> list[Finding]:
        target = base_context(context)
        headers = _parse_headers(str(context.options.get("identity_headers", "")))
        if not headers:
            return [finding(
                context, self.name, self.category, "Object-mutation mode requires one test identity", Severity.info, 1.0,
                "Provide headers for one dedicated authorized test identity.",
                "Capture a session header from a test account you control.",
            )]
        parameter = str(context.options.get("object_param", "")).strip()
        value = str(context.options.get("object_value", "")).strip()
        if not parameter or not value:
            return [finding(
                context, self.name, self.category, "Object-mutation mode requires an object parameter and value", Severity.info, 1.0,
                "Specify which URL parameter identifies the resource and the alternate authorized test value to request.",
                "Use options such as --object-param id --object-value carlos on a dedicated training lab or authorized test environment.",
            )]

        context_one = context.model_copy(update={"headers": headers})
        baseline = request(context_one)
        if not baseline.ok:
            return [finding(context, self.name, self.category, "Object-mutation baseline request failed", Severity.info, 0.1, baseline.error or "Request failed.", "Confirm the test identity can access the baseline resource.")]

        mutated_target = _set_query_value(target, parameter, value)
        mutated = request(context_one, url=mutated_target)
        if not mutated.ok:
            return [finding(context, self.name, self.category, "Object-mutation request failed", Severity.info, 0.1, mutated.error or "Request failed.", "Confirm the alternate object identifier is valid for the training lab/authorized target.")]

        current_param_values = [current for key, current in parse_qsl(urlsplit(target).query, keep_blank_values=True) if key == parameter]
        if value in current_param_values:
            return [finding(
                context, self.name, self.category, "Object mutation value matches the baseline value", Severity.info, 1.0,
                "The alternate object value is already present in the supplied target URL, so no authorization boundary was exercised.",
                "Choose a different object identifier belonging to another dedicated test object or training-lab account.",
                parameter=parameter,
            )]

        markers = [str(m).strip() for m in context.options.get("markers_target", []) if str(m).strip()]
        if int(baseline.status_code or 0) < 200 or int(baseline.status_code or 0) >= 400:
            markers = []
        if markers and not (200 <= int(mutated.status_code or 0) < 400):
            markers = []
        marker_findings = self._marker_findings(context, mutated_target, baseline, mutated, markers, title_prefix="Object-mutated", target_value=value)
        if marker_findings:
            return marker_findings

        baseline_status = int(baseline.status_code or 0)
        mutated_status = int(mutated.status_code or 0)
        baseline_shape = _json_shape(baseline.text)
        mutated_shape = _json_shape(mutated.text)
        similarity = 1.0 - (abs(len(baseline.text) - len(mutated.text)) / max(len(baseline.text), len(mutated.text), 1))

        # Do not label a generic 200 response as a vulnerability: many resources legitimately
        # share templates. Report only a candidate when there is a strong response-level signal.
        if baseline_status == 200 and mutated_status == 200 and baseline.text and mutated.text and baseline_shape and baseline_shape == mutated_shape and similarity >= 0.985:
            return [finding(
                context, self.name, self.category,
                "Object identifier mutation returned an unusually similar protected response",
                Severity.medium, 0.78,
                "The same authenticated identity received highly similar successful responses for two object identifiers. This is a verification candidate, not proof of unauthorized access.",
                "Verify the returned object belongs to the requested identity and add an explicit object-ownership check server-side.",
                parameter=parameter,
                evidence=[Evidence(kind="comparison", title="Same-session object mutation", data={
                    "baseline_status": baseline_status,
                    "mutated_status": mutated_status,
                    "baseline_value": "[operator-supplied baseline URL]",
                    "mutated_value": value,
                    "similarity": round(similarity, 4),
                    "baseline_fingerprint": body_fingerprint(baseline.text),
                    "mutated_fingerprint": body_fingerprint(mutated.text),
                })],
            )]
        if mutated_status in {401, 403, 404}:
            return [finding(
                context, self.name, self.category, "Object mutation was denied", Severity.info, 1.0,
                f"The alternate object identifier returned HTTP {mutated_status}; this is evidence of an authorization boundary rather than a finding.",
                "Keep server-side authorization checks and retest after changes.",
                parameter=parameter,
                evidence=[Evidence(kind="comparison", title="Access denied after object mutation", data={"mutated_status": mutated_status, "mutated_value": value})],
            )]
        return []

    def run(self, context: ScanContext):
        object_param = str(context.options.get("object_param", "")).strip()
        if object_param:
            return self._run_object_mutation(context)

        target = base_context(context)
        a = _parse_headers(str(context.options.get("identity_a_headers", "")))
        b = _parse_headers(str(context.options.get("identity_b_headers", "")))
        if not a or not b:
            return [finding(context, self.name, self.category, "Two test identities are required for comparison mode", Severity.info, 1.0, "Provide request headers for Identity A and Identity B, or switch to object-mutation mode with --object-param and --object-value.", "Capture authenticated headers/cookies from two dedicated test accounts.")]
        context_a = context.model_copy(update={"headers": a})
        context_b = context.model_copy(update={"headers": b})
        ra = request(context_a)
        rb = request(context_b)
        if not ra.ok or not rb.ok:
            return [finding(context, self.name, self.category, "Access-control comparison failed", Severity.info, 0.1, f"A={ra.error or ra.status_code}; B={rb.error or rb.status_code}", "Ensure both test identities can reach the same authorized resource.")]

        evidence_data = {
            "identity_a_status": ra.status_code,
            "identity_b_status": rb.status_code,
            "identity_a_length": len(ra.text),
            "identity_b_length": len(rb.text),
            "identity_a_fingerprint": body_fingerprint(ra.text),
            "identity_b_fingerprint": body_fingerprint(rb.text),
            "identity_a_json_shape": _json_shape(ra.text),
            "identity_b_json_shape": _json_shape(rb.text),
        }
        markers = [m.strip() for m in context.options.get("markers_a", []) if str(m).strip()]
        marker_hits = [marker for marker in markers if marker in rb.text]
        if ra.status_code == 200 and marker_hits:
            return [Finding(
                engine=self.name, category=self.category,
                title="Identity B response contains Identity A-specific marker(s)", severity=Severity.high, confidence=0.97,
                target=target, verification=VerificationLevel.corroborated,
                description="A marker supplied as unique to Identity A was observed in Identity B's response. This is strong evidence of a cross-account authorization failure when the marker is genuinely unique.",
                remediation="Enforce server-side authorization and object ownership checks for every protected resource.",
                evidence=[Evidence(kind="comparison", title="Cross-account marker leak", data={**evidence_data, "matched_markers": marker_hits})],
            )]

        same_status = ra.status_code == rb.status_code
        similarity = 1.0 - (abs(len(ra.text) - len(rb.text)) / max(len(ra.text), len(rb.text), 1))
        same_shape = _json_shape(ra.text) == _json_shape(rb.text) if _json_shape(ra.text) and _json_shape(rb.text) else False
        expected_b = int(context.options.get("identity_b_expected_status", 403))
        if same_status and similarity >= 0.98 and ra.status_code == 200 and ra.text and rb.text and body_fingerprint(ra.text) == body_fingerprint(rb.text):
            return [Finding(
                engine=self.name, category=self.category,
                title="Possible broken access control: both identities received an identical resource response", severity=Severity.high, confidence=0.93,
                target=target,
                description="The two operator-supplied identities produced identical successful resource bodies. Treat this as a verification candidate unless the resource is intentionally shared.",
                remediation="Enforce authorization and ownership checks on every protected resource.",
                evidence=[Evidence(kind="comparison", title="Identical identity responses", data={**evidence_data, "similarity": round(similarity, 4), "same_shape": same_shape, "expected_identity_b_status": expected_b})],
            )]
        if ra.status_code == 200 and rb.status_code != expected_b and same_shape and similarity >= 0.98:
            return [finding(
                context, self.name, self.category,
                "Possible broken access control: Identity B was not denied as expected", Severity.medium, 0.82,
                "Identity B received a response that was not the expected denial status and closely matched Identity A's response shape.",
                "Enforce server-side authorization and verify resource ownership before returning protected data.",
                evidence=[Evidence(kind="comparison", title="Unexpected access status", data={**evidence_data, "similarity": round(similarity, 4), "same_shape": same_shape, "expected_identity_b_status": expected_b})],
            )]
        return []
