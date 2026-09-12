# AI-SCORE-BELTU
 
**AI-SCORE-BELTU v1.6.0** is a terminal-first, open-source framework for **authorized** web/API security assessment. It uses dedicated vulnerability engines, an explicit scope guard, structured evidence, deterministic credibility scoring, optional local AI triage, and machine-readable reporting.
 
> **Authorized use only.** Run BelTu only against systems you own or are explicitly permitted to test. The framework requires an explicit host allowlist for network testing. It does not include reconnaissance, XSS, or SQL Injection engines.
 
## Highlights
 
- 12 dedicated security engines
- Terminal-only workflow designed for Kali Linux and Ubuntu
- Explicit target allowlist before network requests
- Conservative request engine with timeouts, response-size limits, and retry handling
- Structured evidence and verification levels
- Deterministic risk + credibility scoring
- Optional local Ollama triage with redacted metadata
- JSON, HTML, and SARIF reports
- SQLite finding history
- Controlled Mailpit test-mail adapter
- OpenAPI JSON/YAML parsing
- `beltu` and `ai-score-beltu` commands
- Compact one-letter action mode
## Engines
 
| Command | Area | Main input |
|---|---|---|
| `ssrf` | SSRF | Target + operator-owned HTTPS canary |
| `csrf` | CSRF | Target HTML URL |
| `api` | API Security | API target + OpenAPI JSON/YAML |
| `access-control` | Broken Access Control | Two identities **or** one identity + object parameter/value |
| `authentication` | Authentication | Auth/login URL |
| `misconfiguration` | Security Misconfiguration | Target URL |
| `cryptography` | Cryptographic Failures | HTTPS target |
| `integrity` | Software & Data Integrity | HTML target |
| `disclosure` | Information Disclosure | Target URL |
| `cors` | CORS | Target + controlled Origin |
| `open-redirect` | Open Redirect | Redirect-like URL |
| `jwt` | JWT Security | Test JWT + authorized context |
 
## Install
 
### GitHub
 
```bash
git clone https://github.com/abdulrhmsnadel/AI-SCORE-BELTU.git
cd AI-SCORE-BELTU
chmod +x install.sh
./install.sh
```
 
For SSH:
 
```bash
git clone git@github.com:abdulrhmsnadel/AI-SCORE-BELTU.git
cd AI-SCORE-BELTU
./install.sh
```
 
Then:
 
```bash
beltu -v
beltu -d
beltu -e
```
 
If needed:
 
```bash
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc
source ~/.bashrc
```
 
## Fast terminal mode
 
```text
-h  help
-v  version
-d  doctor
-e  engines
-a  assess
-t  scan one engine
-f  findings
-g  report
-i  engine information
-s  scope check
-m  test mailbox
-I  AI triage
```
 
Common option shortcuts:
 
```text
-w  allowed host
-H  request header
-o  JSON output
-D  SQLite database
-r  HTML report
-S  SARIF report
-O  CORS Origin
-P  Context-specific option (CORS preflight method / Access-Control object parameter)
-V  Access-Control alternate object value
-N  Access-Control target-object marker
-R  Open-Redirect external marker URL
-k  JWT token
-c  SSRF canary URL
-C  SSRF canary host
-A  Identity A headers / single-session identity
-B  Identity B headers
-M  Identity A marker
-p  OpenAPI file/URL
-x  Show redacted terminal evidence
```
 
## Safe first run
 
```bash
beltu -s 'https://authorized.example' -w authorized.example
beltu -i access-control
beltu -i api
```
 
## PortSwigger Academy labs
 
Use only the lab URL assigned to you.
 
```bash
beltu -t cors 'https://YOUR-LAB.web-security-academy.net/account' \
  -w YOUR-LAB.web-security-academy.net \
  -O 'https://beltu.invalid'
```
 
```bash
beltu -t open-redirect 'https://YOUR-LAB.web-security-academy.net/login?next=/home' \
  -w YOUR-LAB.web-security-academy.net
```
 
Access-control comparison mode:
 
```bash
beltu -t access-control 'https://YOUR-LAB.web-security-academy.net/account/123' \
  -w YOUR-LAB.web-security-academy.net \
  -A $'Cookie: session_A' \
  -B $'Cookie: session_B' \
  -M 'UNIQUE_A_MARKER'
```
 
Same-session object mutation mode (useful for IDOR/BOLA-style training labs):
 
```bash
beltu -t access-control 'https://YOUR-LAB.web-security-academy.net/my-account?id=wiener' \
  -w YOUR-LAB.web-security-academy.net \
  -A $'Cookie: TEST_SESSION' \
  -P id -V carlos -N carlos -x
```
 
## Terminal evidence
 
Use `--details` (`-x`) when you want BelTu to explain what happened directly in the terminal after a scan. It prints the finding description, remediation, and redacted evidence while keeping the full machine-readable report on disk.
 
```bash
beltu -t cors "https://authorized.example/accountDetails" -w authorized.example -O "https://beltu.invalid" -H "Cookie: session=YOUR_TEST_SESSION" -x -o cors.json -r cors.html
```
 
`-x` only affects what's printed to the terminal; it never changes scanner logic. Use the HTML/JSON/SARIF output for full report storage.
 
## Reports
 
```bash
beltu -g -o report.json -r report.html -S report.sarif
```
 
Each report includes:
 
- finding severity
- verification status
- engine confidence
- structured evidence
- deterministic credibility
- risk score
- AI triage metadata
## AI triage
 
The baseline AI layer is local and deterministic; an Ollama provider is optional.
 
```bash
beltu -I
beltu ai status
beltu ai triage
```
 
For Ollama:
 
```bash
beltu ai triage --provider ollama --model llama3.2
```
 
BelTu only sends redacted finding metadata to the optional local model — never cookies, authorization headers, tokens, or raw secrets.
 
## Verification model
 
BelTu distinguishes:
 
```text
informational → candidate → corroborated → confirmed
```
 
High severity doesn't automatically mean high credibility. The credibility score factors in severity, engine confidence, verification level, and evidence quality together.
 
## Development
 
```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[dev]'
pytest -q
ruff check src tests
```
 
Dependency versions are pinned in `pyproject.toml`; see `docs/DEPENDENCY_BASELINE.md` for the current baseline and update policy.
 
## License
 
MIT.
 
## Guess / controlled mutation layer (v1.6.0)
 
Generate a deterministic 10,000-case corpus without making any network requests:
 
```bash
beltu guess corpus --count 10000 -o beltu-guess-corpus.jsonl
```
 
For authorized access-control/IDOR training labs, bounded object-ID guessing is available:
 
```bash
beltu guess access-control "https://LAB_HOST/my-account?id=1" \
  -w LAB_HOST \
  -A 'Cookie: session=YOUR_TEST_SESSION' \
  -P id -n 10000 --confirm-large-run \
  -M 'UNIQUE_TARGET_MARKER' -x \
  -o access-control-guess.json -r access-control-guess.html
```
 
See `docs/GUESSING.md`. Credential/password guessing is deliberately excluded.
 
## Smart guessing corpus
 
Generate up to 1,000,000 offline mutation cases for authorized object/resource testing:
 
```bash
beltu guess corpus --engine access-control --count 1000000 -o access-control-1m.jsonl
```
 
Network access-control guessing stays capped at 10,000 requests per invocation and never performs credential/password guessing.
 
## AI-native routing (v1.5+)
 
BelTu routes each engine to a task-specific AI backend rather than calling every model blindly:
 
```bash
beltu ai providers
beltu ai route access-control
beltu ai route cors
beltu ai triage --provider ensemble
beltu ai planner access-control
beltu ai burp --input burp-message.json --provider openai
```
 
Remote providers are opt-in. Configure API keys through environment variables — never commit them. Code Llama runs as a local Ollama model, scikit-learn handles duplicate/anomaly signals, PentestGPT is planner-only, and the Burp integration is a redacted message bridge.
 
### AI provider setup
 
```bash
# OpenAI GPT-4o
export BELTU_OPENAI_API_KEY='...'
 
# Anthropic Claude
export BELTU_ANTHROPIC_API_KEY='...'
export BELTU_ANTHROPIC_MODEL='claude-sonnet-4-6'
 
# Local Code Llama through Ollama (explicitly enable before auto-run)
export BELTU_CODELLAMA_ENABLED=1
export BELTU_CODELLAMA_MODEL='codellama:13b'
 
# Run configured providers automatically during scans
export BELTU_AI_AUTORUN=1
beltu ai providers
```
 
## AI stack
 
AI-SCORE-BELTU integrates with OpenAI GPT-4o, Anthropic Claude, DeepSeek-Coder-V2-compatible endpoints, Code Llama/Ollama, PentestGPT, Burp message analysis, scikit-learn, LangChain, LangGraph, Interactsh, and PyJWT — all bounded and opt-in. Remote AI never replaces deterministic verification; it only assists triage.
 
