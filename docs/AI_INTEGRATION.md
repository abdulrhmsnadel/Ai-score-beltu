# AI integration

AI-SCORE-BELTU keeps deterministic detection and evidence generation separate from AI triage. AI providers receive redacted metadata/evidence and cannot turn a candidate into a confirmed vulnerability by themselves.

## Providers

- OpenAI GPT-4o: broad finding adjudication and report synthesis.
- Claude adapter: independent second opinion. The default current model is `claude-sonnet-4-6`; retired Claude 3.5 identifiers are routed explicitly to a current model.
- DeepSeek-Coder-V2 adapter: OpenAI-compatible adapter. DeepSeek's current hosted API documents V4 model IDs, so `BELTU_DEEPSEEK_MODEL` is configurable for a compatibility endpoint rather than pretending Coder-V2 is a current hosted model.
- Code Llama: local-only through Ollama.
- PentestGPT: planner-only. BelTu never grants it target control.
- Burp bridge: redacted Burp message analysis.
- scikit-learn: local duplicate/anomaly signals only.
- PyJWT: local JWT parsing/validation helper.
- LangChain: composition layer for model/chain integration.
- LangGraph: bounded state graph for `sanitize -> ML -> providers -> consensus`.
- Interactsh: official client integration for OOB canary generation; BelTu wraps the documented client/JSONL interface rather than inventing a REST endpoint.

## Remote safety

Remote AI is opt-in. Run `beltu ai graph` for local orchestration, or `beltu ai graph --remote` when you have explicitly configured provider keys. API keys, cookies, authorization headers, and tokens are redacted before remote analysis.
