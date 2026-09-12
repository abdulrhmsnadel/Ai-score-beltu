# AI Engine Matrix

| Engine | Primary AI | Local ML | Burp context | PentestGPT planner |
|---|---|---|---|---|
| SSRF | GPT-4o | scikit-learn | optional | optional |
| CSRF | Claude | scikit-learn | optional | — |
| API | GPT-4o + Code Llama | scikit-learn | optional | optional |
| Access Control | GPT-4o + Claude | scikit-learn | optional | optional |
| Authentication | Claude + GPT-4o | scikit-learn | optional | optional |
| Misconfiguration | Code Llama + GPT-4o | scikit-learn | — | — |
| Cryptography | Code Llama + Claude | scikit-learn | — | — |
| Integrity | Code Llama + GPT-4o | scikit-learn | — | — |
| Disclosure | Code Llama + GPT-4o + Claude | scikit-learn | optional | — |
| CORS | GPT-4o + Claude | scikit-learn | optional | — |
| Open Redirect | Code Llama + GPT-4o | scikit-learn | optional | — |
| JWT | Code Llama + GPT-4o + Claude | scikit-learn | — | — |

The table is a routing policy, not a claim that all providers are always called. Credentials and local services determine which optional integrations are actually available.
