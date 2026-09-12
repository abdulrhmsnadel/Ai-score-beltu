from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from dataclasses import dataclass
from typing import Any

import httpx


@dataclass(slots=True)
class ProviderResult:
    provider: str
    ok: bool
    data: dict[str, Any]
    error: str | None = None
    latency_ms: float | None = None


def _json_from_text(text: str) -> dict[str, Any]:
    try:
        value = json.loads(text)
        return value if isinstance(value, dict) else {"value": value}
    except json.JSONDecodeError:
        # Recover a fenced JSON object when a model adds Markdown around it.
        match = re.search(r"```json\s*(\{.*?\})\s*```", text, flags=re.I | re.S)
        if match:
            try:
                value = json.loads(match.group(1))
                return value if isinstance(value, dict) else {"value": value}
            except json.JSONDecodeError:
                pass
        return {"raw": text[:12000]}


def _timed_post(url: str, *, headers: dict[str, str], json_body: dict[str, Any], timeout: float) -> tuple[dict[str, Any], float]:
    import time
    started = time.perf_counter()
    with httpx.Client(timeout=timeout) as client:
        response = client.post(url, headers=headers, json=json_body)
        response.raise_for_status()
        payload = response.json()
    return payload, (time.perf_counter() - started) * 1000


def openai_gpt4o(prompt: str, *, api_key: str | None = None, model: str = "gpt-4o", timeout: float = 60.0) -> ProviderResult:
    key = api_key or os.getenv("BELTU_OPENAI_API_KEY") or os.getenv("OPENAI_API_KEY")
    if not key:
        return ProviderResult("openai:gpt-4o", False, {}, "BELTU_OPENAI_API_KEY/OPENAI_API_KEY not set")
    payload = {
        "model": model,
        "temperature": 0.1,
        "messages": [
            {"role": "system", "content": "You are a defensive security triage reviewer. Use only supplied evidence. Never invent findings, secrets, credentials, or exploit proof. Return JSON."},
            {"role": "user", "content": prompt},
        ],
        "response_format": {"type": "json_object"},
    }
    try:
        data, latency = _timed_post("https://api.openai.com/v1/chat/completions", headers={"Authorization": f"Bearer {key}"}, json_body=payload, timeout=timeout)
        content = data.get("choices", [{}])[0].get("message", {}).get("content", "{}")
        return ProviderResult("openai:gpt-4o", True, _json_from_text(content), latency_ms=latency)
    except Exception as exc:
        return ProviderResult("openai:gpt-4o", False, {}, str(exc))


def _anthropic_model() -> tuple[str, str | None]:
    requested = os.getenv("BELTU_ANTHROPIC_MODEL", "claude-sonnet-4-6")
    legacy = {"claude-3-5-sonnet-20240620", "claude-3-5-sonnet"}
    if requested in legacy:
        return "claude-sonnet-4-6", "Requested Claude 3.5 Sonnet is retired; routed to claude-sonnet-4-6."
    return requested, None


def anthropic_claude(prompt: str, *, api_key: str | None = None, timeout: float = 60.0) -> ProviderResult:
    key = api_key or os.getenv("BELTU_ANTHROPIC_API_KEY") or os.getenv("ANTHROPIC_API_KEY")
    if not key:
        return ProviderResult("anthropic:claude", False, {}, "BELTU_ANTHROPIC_API_KEY/ANTHROPIC_API_KEY not set")
    model, note = _anthropic_model()
    payload = {
        "model": model,
        "max_tokens": 1800,
        "temperature": 0.1,
        "system": "You are a defensive security review assistant. Analyze only supplied evidence. Never invent evidence or secrets. Return JSON.",
        "messages": [{"role": "user", "content": prompt}],
    }
    try:
        data, latency = _timed_post("https://api.anthropic.com/v1/messages", headers={"x-api-key": key, "anthropic-version": "2023-06-01"}, json_body=payload, timeout=timeout)
        blocks = data.get("content", [])
        content = "".join(block.get("text", "") for block in blocks if isinstance(block, dict))
        parsed = _json_from_text(content)
        if note:
            parsed["compatibility_note"] = note
        return ProviderResult("anthropic:claude", True, parsed, latency_ms=latency)
    except Exception as exc:
        return ProviderResult("anthropic:claude", False, {}, str(exc))


def deepseek_coder_v2(prompt: str, *, api_key: str | None = None, model: str | None = None, base_url: str | None = None, timeout: float = 60.0) -> ProviderResult:
    """OpenAI-compatible DeepSeek adapter.

    DeepSeek's current public API exposes V4 model IDs; the model is configurable so an
    operator can point this adapter at an authorized compatibility endpoint that still
    serves DeepSeek-Coder-V2. No hardcoded claim is made that Coder-V2 remains a current
    hosted model.
    """
    key = api_key or os.getenv("BELTU_DEEPSEEK_API_KEY") or os.getenv("DEEPSEEK_API_KEY")
    if not key:
        return ProviderResult("deepseek-coder-v2", False, {}, "BELTU_DEEPSEEK_API_KEY/DEEPSEEK_API_KEY not set")
    model_name = model or os.getenv("BELTU_DEEPSEEK_MODEL", "deepseek-coder-v2")
    base = (base_url or os.getenv("BELTU_DEEPSEEK_BASE_URL", "https://api.deepseek.com")).rstrip("/")
    payload = {
        "model": model_name,
        "temperature": 0.1,
        "response_format": {"type": "json_object"},
        "messages": [
            {"role": "system", "content": "You are a defensive security/code review assistant. Use only supplied evidence. Return JSON. Never invent credentials, secrets, or exploit proof."},
            {"role": "user", "content": prompt},
        ],
    }
    try:
        data, latency = _timed_post(base + "/chat/completions", headers={"Authorization": f"Bearer {key}"}, json_body=payload, timeout=timeout)
        content = data.get("choices", [{}])[0].get("message", {}).get("content", "{}")
        return ProviderResult(f"deepseek:{model_name}", True, _json_from_text(content), latency_ms=latency)
    except Exception as exc:
        return ProviderResult(f"deepseek:{model_name}", False, {}, str(exc))


def ollama_chat(prompt: str, *, model: str | None = None, base_url: str | None = None, timeout: float = 60.0) -> ProviderResult:
    model_name = model or os.getenv("BELTU_CODELLAMA_MODEL", "codellama:13b")
    url = (base_url or os.getenv("BELTU_OLLAMA_URL", "http://127.0.0.1:11434")).rstrip("/")
    payload = {
        "model": model_name,
        "stream": False,
        "format": "json",
        "messages": [
            {"role": "system", "content": "You are a local code/HTTP semantic reviewer. Analyze only supplied defensive test evidence. Return JSON."},
            {"role": "user", "content": prompt},
        ],
    }
    try:
        data, latency = _timed_post(url + "/api/chat", headers={}, json_body=payload, timeout=timeout)
        content = data.get("message", {}).get("content", "{}") if isinstance(data, dict) else "{}"
        return ProviderResult(f"ollama:{model_name}", True, _json_from_text(content), latency_ms=latency)
    except Exception as exc:
        return ProviderResult(f"ollama:{model_name}", False, {}, str(exc))


def pentestgpt_plan(prompt: str, *, binary: str | None = None, timeout: float = 60.0) -> ProviderResult:
    """Planner-only adapter. It never grants the agent direct target control."""
    command = binary or os.getenv("BELTU_PENTESTGPT_BIN", "pentestgpt")
    if shutil.which(command) is None:
        return ProviderResult("pentestgpt", False, {}, "PentestGPT executable not found")
    try:
        proc = subprocess.run([command, "--help"], capture_output=True, text=True, timeout=5, check=False)
        if proc.returncode not in (0, 1, 2):
            return ProviderResult("pentestgpt", False, {}, "PentestGPT executable check failed")
        return ProviderResult("pentestgpt", True, {"available": True, "mode": "planner-only", "prompt_preview": prompt[:600]})
    except Exception as exc:
        return ProviderResult("pentestgpt", False, {}, str(exc))


def burp_bridge_status() -> ProviderResult:
    """Burp integration is file/extension driven; this reports the local adapter only."""
    return ProviderResult("burp-bridge", True, {"available": True, "mode": "redacted-message-adapter"})
