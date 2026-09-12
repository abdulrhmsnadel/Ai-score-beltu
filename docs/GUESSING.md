# Guessing & controlled mutation

AI-SCORE-BELTU 1.4.0 includes a deterministic Guess/Fuzz layer for authorized testing. It is designed for object/resource identifiers, request-policy values, and other controlled mutation cases — not credential or password guessing.

## Generate 10,000 cases without making requests

```bash
beltu guess corpus --count 10000 -o beltu-guess-corpus.jsonl
```

For one engine:

```bash
beltu guess corpus --engine access-control --count 10000 -o access-control-10k.jsonl
```

Corpus files are JSONL and include a case ID, engine, family, value, rationale, and safety flag.

## Access-control object-ID guessing

The default strategy is mixed: common training identifiers (for example `carlos`, `admin`, `user`) and boundary values are tried before the sequential range. This makes small lab runs useful while still supporting large numeric ranges.


Use only with an explicitly allowlisted authorized target. A one-identity run mutates the query parameter while keeping the authenticated test session constant.

```bash
beltu guess access-control "https://lab.example/my-account?id=1" \
  -w lab.example \
  -A 'Cookie: session=REDACTED' \
  -P id \
  -n 10000 \
  --confirm-large-run \
  -M 'UNIQUE_TARGET_MARKER' \
  -x \
  -o access-control-guess.json \
  -r access-control-guess.html
```

The run is capped at 10,000 requests and requires `--confirm-large-run` above 1,000 requests. A minimum delay of 50ms is enforced.

Strong matches are reported as `corroborated` when an operator-supplied target-object marker appears after mutation. Similar successful responses without a marker are only `candidate` findings.

## What is intentionally not included

- Password or credential brute forcing.
- Internal-network SSRF target lists.
- XSS or SQL injection payload corpora.
- Unbounded request generation.

To regenerate bundled corpora: `python3 scripts/generate_guess_corpora.py`.


### Smart corpus (v1.4.0)
The access-control corpus is intentionally sampled rather than exhaustive. With ASCII letters in both cases plus digits (62 symbols), exhaustive enumeration from length 4 through 15 would require:

`62^4 + 62^5 + ... + 62^15 = 781,514,782,079,074,318,856,533,680` candidates.

BelTu therefore uses a deterministic million-case **offline** corpus made from common real-world names/roles, case variants, non-sequential numeric identifiers, structured letter patterns, and seeded alphanumeric samples of length 4–15. Network execution remains bounded to protect authorized labs and avoid accidental flooding.
