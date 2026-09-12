# Quality gates

BelTu treats a finding as useful only when its evidence chain is inspectable.

## Finding confidence

Engine confidence describes how strongly the engine's detector observed its signal.

## Verification

`informational`, `candidate`, `corroborated`, and `confirmed` are separate states. Only `confirmed` means the engine's own verification logic established the stated condition.

## Credibility score

The deterministic credibility score combines severity, engine confidence, verification state, and evidence quality. It is not a claim of exploitability and is intentionally independent from optional language-model output.

## AI

The AI layer ranks and explains findings. It does not silently promote a candidate to confirmed.
