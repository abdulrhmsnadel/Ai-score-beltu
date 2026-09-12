from __future__ import annotations

from typing import Any

import httpx

from beltu.ai import build_prompt
from beltu.core.models import Finding


def ollama_chat(findings: list[Finding], *, model: str = "llama3.2", base_url: str = "http://127.0.0.1:11434", timeout: float = 60.0) -> dict[str, Any]:
    payload = {
        "model": model,
        "stream": False,
        "format": "json",
        "messages": [
            {"role": "system", "content": "Return valid JSON only. Never invent evidence or credentials."},
            {"role": "user", "content": build_prompt(findings)},
        ],
    }
    with httpx.Client(timeout=timeout) as client:
        response = client.post(base_url.rstrip("/") + "/api/chat", json=payload)
        response.raise_for_status()
        data = response.json()
    message = data.get("message", {}) if isinstance(data, dict) else {}
    content = message.get("content", "{}") if isinstance(message, dict) else "{}"
    try:
        import json
        return json.loads(content)
    except Exception:
        return {"raw": content}
