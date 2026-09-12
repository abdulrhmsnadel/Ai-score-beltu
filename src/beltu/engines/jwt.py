from __future__ import annotations

import base64
import json
from datetime import datetime, timezone

from beltu.core.engine import Engine
from beltu.core.models import Evidence, Finding, ScanContext, Severity

from .common import base_context, finding


def _decode_segment(segment: str) -> dict:
    padded = segment + "=" * (-len(segment) % 4)
    data = json.loads(base64.urlsafe_b64decode(padded).decode("utf-8"))
    if not isinstance(data, dict):
        raise ValueError("JWT segment is not a JSON object")
    return data


class JwtEngine(Engine):
    name = "jwt"
    category = "JWT Security"
    description = "Locally analyzes an operator-supplied JWT header and claims without attempting forgery, cracking, or signature bypasses."

    @property
    def requires(self) -> list[str]:
        return ["Authorized target URL", "JWT captured from a test account or explicitly authorized request"]

    def run(self, context: ScanContext):
        target = base_context(context)
        token = str(context.options.get("token", "")).strip()
        if not token:
            return [finding(context, self.name, self.category, "JWT token is required", Severity.info, 1.0, "Provide a JWT captured from an authorized test flow. BelTu only inspects the supplied token.", "Capture a token from a dedicated test account/request.")]
        parts = token.split(".")
        if len(parts) != 3:
            return [finding(context, self.name, self.category, "Supplied token is not a JWT", Severity.info, 1.0, "A JWT must contain three dot-separated base64url segments.", "Supply a compact JWT token.")]
        try:
            header = _decode_segment(parts[0])
            claims = _decode_segment(parts[1])
            try:
                import jwt as pyjwt
                pyjwt.decode(token, options={"verify_signature": False, "verify_exp": False, "verify_aud": False, "verify_iss": False})
                parser = "PyJWT"
            except Exception:
                parser = "builtin"
        except Exception as exc:
            return [finding(context, self.name, self.category, "JWT decoding failed", Severity.info, 0.1, str(exc), "Verify that the supplied token is a valid compact JWT.")]

        findings: list[Finding] = []
        alg = str(header.get("alg", "")).upper()
        if alg in {"NONE", ""}:
            findings.append(finding(context, self.name, self.category, "JWT declares no usable signing algorithm", Severity.high, 0.99, f"JWT header alg={header.get('alg')!r}.", "Require an approved signing algorithm and reject unsigned tokens.", evidence=[Evidence(kind="jwt", title="JWT header", data={"alg": header.get("alg"), "typ": header.get("typ"), "parser": parser})]))
        if alg in {"HS256", "HS384", "HS512"}:
            findings.append(finding(context, self.name, self.category, "JWT uses an HMAC signing algorithm", Severity.info, 1.0, "HMAC-based JWTs can be appropriate when the shared secret is strong and securely managed.", "Document algorithm/key policy and prevent algorithm confusion across token verification paths.", evidence=[Evidence(kind="jwt", title="JWT header", data={"alg": alg})]))
        if "exp" not in claims:
            findings.append(finding(context, self.name, self.category, "JWT has no expiration claim", Severity.medium, 0.87, "The supplied JWT contains no exp claim.", "Use short-lived access tokens with explicit expiration and appropriate revocation/rotation controls."))
        else:
            try:
                exp = int(claims["exp"])
                remaining = (datetime.fromtimestamp(exp, tz=timezone.utc) - datetime.now(timezone.utc)).total_seconds()
                if remaining > 86400 * 30:
                    findings.append(finding(context, self.name, self.category, "JWT expiration is more than 30 days away", Severity.medium, 0.78, "The supplied token has a long remaining lifetime. Long-lived bearer tokens increase exposure if stolen.", "Prefer shorter access-token lifetimes and use refresh-token mechanisms for long sessions.", evidence=[Evidence(kind="jwt", title="JWT expiration", data={"remaining_days": round(remaining / 86400, 1)})]))
            except (TypeError, ValueError, OverflowError):
                findings.append(finding(context, self.name, self.category, "JWT exp claim is not a valid numeric timestamp", Severity.low, 0.93, "The exp claim could not be interpreted as a numeric timestamp.", "Emit and validate standard NumericDate claims."))
        for claim in ("iss", "aud"):
            if claim not in claims:
                findings.append(finding(context, self.name, self.category, f"JWT has no {claim} claim", Severity.low, 0.72, f"No {claim} claim was present. Whether this is required depends on the trust model.", f"Validate {claim} when multiple issuers/audiences or trust domains exist."))
        if not findings:
            findings.append(finding(context, self.name, self.category, "JWT basic posture observed", Severity.info, 1.0, "The supplied JWT passed the basic local structural checks in this engine.", "Review token policy against the application's actual trust model.", evidence=[Evidence(kind="jwt", title="JWT summary", data={"alg": alg, "claims_keys": sorted(claims.keys())})]))
        return findings
