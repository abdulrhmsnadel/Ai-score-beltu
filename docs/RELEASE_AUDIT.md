# v1.4.0 release audit

## Verified locally
- Python source compiles successfully.
- 22 pytest tests pass.
- Shell scripts pass `bash -n`.
- CLI `-v`, `-e`, `-d`, `-i`, `-G`, scan help, guess help, and report help were smoke-tested.
- Same-session access-control object mutation was regression-tested; the Guess runner was unit-tested with a mocked HTTP boundary.
- JSON/HTML/SARIF/report redaction paths were regression-tested.

## Not claimed
- No third-party target was scanned during release verification.
- Ruff was not executable in this offline build environment; CI is configured to run it.
- A clean wheel install could not be performed here because build dependencies were unavailable offline.

## Smart guessing corpus
- Offline access-control stream was iterated through 1,000,000 candidates successfully without materializing the full corpus in memory.
- Candidates cover common names/roles, case variants, non-sequential numeric IDs, letter-pair patterns, digit interleaving, and seeded 4–15 character alphanumeric samples.
- Live access-control guessing remains capped at 10,000 requests per invocation.
