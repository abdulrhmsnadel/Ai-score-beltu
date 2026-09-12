from __future__ import annotations

from dataclasses import asdict, dataclass
import json
import random
import string
from pathlib import Path
from typing import Iterable, Iterator
from urllib.parse import quote


@dataclass(frozen=True, slots=True)
class GuessCase:
    id: str
    engine: str
    family: str
    value: str
    rationale: str
    network_safe: bool = True


# Common names/roles used as object/resource identifiers in training systems and apps.
# These are NOT passwords. The corpus is intended for authorized object-ID/resource mutation.
COMMON_RESOURCE_NAMES = (
    "alice", "bob", "carlos", "david", "daniel", "emma", "james", "jane", "john", "julia",
    "maria", "mark", "mary", "michael", "mike", "oliver", "peter", "robert", "sarah", "steve",
    "thomas", "william", "anna", "charlie", "chris", "alex", "sam", "jack", "lucas", "noah",
    "admin", "administrator", "owner", "manager", "moderator", "operator", "editor", "viewer",
    "member", "support", "service", "system", "root", "guest", "user", "test", "demo", "qa", "dev",
    "profile", "account", "customer", "client", "staff", "employee", "sales", "billing", "security",
)

CASE_NAMES = tuple(dict.fromkeys(
    v for base in COMMON_RESOURCE_NAMES for v in (
        base, base.lower(), base.upper(), base.title(), base.swapcase()
    ) if 4 <= len(v) <= 15
))

COMMON_SAFE_VALUES = (
    "0", "1", "2", "3", "4", "5", "9", "10", "42", "99", "100", "101", "999", "1000",
    "9999", "10000", "99999", "100000", "999999", "2147483647", "-1", "-2", "-10",
    "0001", "0010", "0042", "000099", "01", "001", "00000001", "00000042",
    *COMMON_RESOURCE_NAMES,
    "me", "self", "public", "private", "null", "undefined", "none", "false", "true", "NaN",
)

ENGINE_FAMILIES: dict[str, tuple[tuple[str, tuple[str, ...], str], ...]] = {
    "access-control": (
        ("names", CASE_NAMES, "Common real-world names and application roles with case variants."),
        ("numeric", COMMON_SAFE_VALUES, "Common object identifiers and boundary values."),
        ("encoded", tuple(quote(v, safe="") for v in CASE_NAMES[:250]), "URL-encoded identifier variants."),
        ("suffix-prefix", tuple(
            f"{name}{n}" for name in CASE_NAMES[:250] for n in ("0", "1", "2", "10", "42", "99", "100", "404", "500")
            if 4 <= len(name) + len(n) <= 15
        ), "Common name-plus-number resource identifiers."),
    ),
    "cors": (("origin", ("https://beltu.invalid", "https://test-origin.invalid", "https://sub.beltu.invalid", "null"), "Controlled Origins."),),
    "open-redirect": (("destination", ("https://beltu.invalid/", "https://test-origin.invalid/path"), "Controlled external destinations."),),
    "ssrf": (("canary", ("https://beltu.invalid/canary/1", "https://test-origin.invalid/ssrf"), "Operator-controlled HTTPS canaries only."),),
    "csrf": (("token-field", ("csrf", "csrf_token", "_csrf", "token", "xsrf_token"), "Common token field names."), ("method", ("POST", "PUT", "PATCH", "DELETE"), "State-changing methods.")),
    "api": (("identifier", COMMON_SAFE_VALUES, "Common API identifier candidates."), ("key", ("id", "user_id", "account_id", "profile_id", "resource_id", "object_id"), "Object-reference parameter names.")),
    "authentication": (("session-cookie", ("session", "sid", "auth", "access_token", "refresh_token"), "Session key names."), ("flow", ("login", "logout", "verify", "activate", "reset", "mfa"), "Authentication flow labels.")),
    "misconfiguration": (("header", ("Server", "X-Powered-By", "X-Debug", "X-Trace", "X-Env", "Cache-Control"), "Common headers."),),
    "cryptography": (("tls", ("1.0", "1.1", "1.2", "1.3"), "TLS versions."), ("cookie", ("Secure", "HttpOnly", "SameSite"), "Cookie attributes.")),
    "integrity": (("resource", ("script", "stylesheet", "module", "preload"), "Resource types."), ("sri", ("integrity", "crossorigin", "referrerpolicy"), "Integrity attributes.")),
    "disclosure": (("marker", ("debug", "trace", "exception", "stack", "password", "api_key", "token", "secret"), "Redacted disclosure markers."),),
    "jwt": (("claim", ("alg", "typ", "exp", "nbf", "iat", "iss", "aud", "sub", "jti"), "JWT claim names."),),
}


def _smart_alnum_stream(seed: int = 1337) -> Iterator[str]:
    """Yield a deterministic, diverse 4..15-char alphanumeric candidate stream."""
    rng = random.Random(seed)
    letters = string.ascii_letters
    charset = letters + string.digits

    # Exhaustive pair coverage for the first block: A/a with every letter, mixed-case,
    # repeated-letter patterns, and digit interleaving. Then continue with seeded samples.
    pair_letters = string.ascii_lowercase
    for length in range(4, 16):
        for a in pair_letters:
            for b in pair_letters:
                templates = (
                    (a * max(1, length - 1)) + b,
                    (a + b) * ((length + 1) // 2),
                    a.upper() + b + a + ("0" * max(0, length - 3)),
                    a + b.upper() + "9" + ("1" * max(0, length - 3)),
                )
                for value in templates:
                    value = value[:length]
                    if 4 <= len(value) <= 15:
                        yield value

    # Unbounded deterministic sampling. This is what allows an offline million-case
    # corpus without pretending the 62^4..62^15 Cartesian space is being exhausted.
    while True:
        length = rng.randint(4, 15)
        mode = rng.randrange(6)
        if mode == 0:
            # Letters + digits interleaved.
            chars = [rng.choice(letters) for _ in range(length)]
            for idx in rng.sample(range(length), k=max(1, min(length // 3, 3))):
                chars[idx] = rng.choice(string.digits)
            value = "".join(chars)
        elif mode == 1:
            value = "".join(rng.choice(charset) for _ in range(length)).lower()
        elif mode == 2:
            value = "".join(rng.choice(charset) for _ in range(length)).upper()
        elif mode == 3:
            value = "".join(rng.choice(charset) for _ in range(length))
        elif mode == 4:
            base = rng.choice(COMMON_RESOURCE_NAMES)
            suffix = "".join(rng.choice(string.digits) for _ in range(max(1, min(4, 15 - len(base)))))
            value = (base[: max(1, 15 - len(suffix))] + suffix)[:15]
            if len(value) < 4:
                value = (value + "x000")[:4]
        else:
            # Alternating case pattern.
            chars = []
            for idx in range(length):
                ch = rng.choice(string.ascii_lowercase)
                chars.append(ch.upper() if idx % 2 else ch)
            value = "".join(chars)
        if 4 <= len(value) <= 15:
            yield value

def _numeric_permutation_stream(seed: int = 1337) -> Iterator[str]:
    """Yield integer IDs in a non-sequential deterministic permutation."""
    rng = random.Random(seed)
    anchors = ["0", "1", "2", "3", "4", "7", "9", "42", "99", "100", "101", "404", "500", "999", "1000", "9999", "10000"]
    for value in anchors:
        yield value
    # Pseudo-random numeric ranges, not 1..N enumeration.
    for width, limit in ((4, 10_000), (5, 100_000), (6, 1_000_000), (7, 10_000_000)):
        order = list(range(0, limit, max(1, limit // 997)))
        rng.shuffle(order)
        for n in order:
            yield f"{n:0{width}d}"


def iter_cases(engine: str | None = None, count: int = 10_000, seed: int = 1337) -> Iterator[GuessCase]:
    if count < 1:
        return
    if engine is not None and engine not in ENGINE_FAMILIES:
        raise ValueError(f"Unknown guess corpus engine: {engine}")

    engines = [engine] if engine else sorted(ENGINE_FAMILIES)
    rng = random.Random(seed)

    def unique_round_robin(per_engine: int, engine_name: str) -> Iterator[tuple[str, str, str]]:
        families = ENGINE_FAMILIES[engine_name]
        streams: list[Iterator[tuple[str, str, str]]] = []
        for family, values, rationale in families:
            values_list = list(values)
            rng.shuffle(values_list)
            streams.append(((family, value, rationale) for value in values_list))

        seen: set[str] = set()
        made = 0
        access_special = engine_name == "access-control"
        numeric_stream = _numeric_permutation_stream(seed + 11) if access_special else iter(())
        alpha_stream = _smart_alnum_stream(seed + 29) if access_special else iter(())
        names = list(CASE_NAMES)
        rng.shuffle(names)

        # Explicitly interleave names/case variants, numeric IDs, structured alnum, and family values.
        while made < per_engine:
            candidates: list[tuple[str, str, str]] = []
            if access_special and names:
                v = names.pop()
                candidates.append(("name", v, "Common real-world name or application role."))
            if access_special:
                try:
                    v = next(numeric_stream)
                    candidates.append(("numeric", v, "Non-sequential numeric object identifier candidate."))
                except StopIteration:
                    pass
                try:
                    v = next(alpha_stream)
                    candidates.append(("alnum", v, "Sampled 4..15-character alphanumeric candidate with mixed case/digits."))
                except StopIteration:
                    pass
            for stream in streams:
                try:
                    candidates.append(next(stream))
                except StopIteration:
                    continue
            rng.shuffle(candidates)
            additions = 0
            for family, value, rationale in candidates:
                if made >= per_engine:
                    break
                if value in seen:
                    continue
                if access_special and not (4 <= len(value) <= 15) and family not in {"numeric"}:
                    continue
                seen.add(value)
                made += 1
                additions += 1
                yield family, value, rationale
            if additions == 0 and not access_special:
                # Small finite policy vocabularies (e.g. CORS origins) can still be
                # expanded into deterministic test cases without network side effects.
                token = f"{engine_name[:6]}{made:08d}"
                if len(token) < 4:
                    token = (token + "x000")[:4]
                seen.add(token)
                made += 1
                yield "generated", token, "Deterministic repeated test case for the engine's finite vocabulary."

    if engine:
        items = unique_round_robin(count, engine)
        for i, (family, value, rationale) in enumerate(items, 1):
            yield GuessCase(f"{engine}-{i:07d}", engine, family, value, rationale)
        return

    per_engine = count // len(engines)
    remainder = count % len(engines)
    all_cases: list[GuessCase] = []
    for idx, engine_name in enumerate(engines):
        quota = per_engine + (1 if idx < remainder else 0)
        for family, value, rationale in unique_round_robin(quota, engine_name):
            all_cases.append(GuessCase("", engine_name, family, value, rationale))
    rng.shuffle(all_cases)
    for i, case in enumerate(all_cases[:count], 1):
        yield GuessCase(f"all-{i:07d}", case.engine, case.family, case.value, case.rationale, case.network_safe)


def generate_cases(engine: str | None = None, count: int = 10_000, seed: int = 1337) -> list[GuessCase]:
    return list(iter_cases(engine, count, seed))


def write_cases(path: Path, cases: Iterable[GuessCase]) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    count = 0
    with path.open("w", encoding="utf-8") as handle:
        for case in cases:
            handle.write(json.dumps(asdict(case), ensure_ascii=False) + "\n")
            count += 1
    return count
