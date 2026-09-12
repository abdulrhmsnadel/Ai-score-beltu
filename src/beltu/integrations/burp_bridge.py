from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from beltu.ai import build_prompt
from beltu.core.http import redact_data
from beltu.core.models import Finding
from beltu.ai_providers import openai_gpt4o, anthropic_claude, ollama_chat


def load_message(path: str | Path) -> dict[str, Any]:
    raw = Path(path).read_text(encoding="utf-8", errors="replace")
    try:
        value = json.loads(raw)
        return value if isinstance(value, dict) else {"raw": raw[:20000]}
    except json.JSONDecodeError:
        return {"raw": raw[:20000]}


def analyze_burp_message(message: dict[str, Any], provider: str = "openai") -> dict[str, Any]:
    safe = redact_data(message)
    prompt = "Analyze this Burp HTTP message for defensive security triage. Never invent proof. Return JSON.\n\n" + json.dumps(safe, ensure_ascii=False)[:30000]
    if provider == "openai":
        result = openai_gpt4o(prompt)
    elif provider == "anthropic":
        result = anthropic_claude(prompt)
    elif provider in {"codellama", "ollama"}:
        result = ollama_chat(prompt)
    else:
        return {"provider": provider, "ok": False, "error": "Use openai, anthropic, or codellama/ollama"}
    return {"provider": result.provider, "ok": result.ok, "data": result.data, "error": result.error}
