# 100-case regression report

- Test count: 100 parameterized engine/data vectors
- Execution: local deterministic HTTP fixture; no public targets; no API keys; no external network calls
- Coverage: CORS, CSRF, Authentication, Misconfiguration, Cryptography, Integrity, Information Disclosure, Open Redirect, JWT, API
- Result: 100 passed
- Full regression suite: 138 passed
- AI provider contract smoke tests: OpenAI, Anthropic, DeepSeek, Ollama; missing-key safety and Burp/Interactsh adapters verified without live credentials

This report validates code paths and contracts; it is not evidence that every production vulnerability class is fully covered.
