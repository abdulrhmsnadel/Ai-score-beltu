from __future__ import annotations

import os
import shutil
from typing import Any

from beltu.ai import analyze_finding, build_prompt
from beltu.ai_providers import anthropic_claude, deepseek_coder_v2, ollama_chat, openai_gpt4o, pentestgpt_plan
from beltu.core.models import Finding
from beltu.ml import semantic_signal


ENGINE_ROUTES: dict[str, tuple[str, ...]] = {
    "ssrf": ("deepseek-coder-v2", "gpt-4o", "claude", "pentestgpt", "interactsh", "sklearn", "burp"),
    "csrf": ("claude", "gpt-4o", "deepseek-coder-v2", "sklearn", "burp"),
    "api": ("deepseek-coder-v2", "gpt-4o", "claude", "langgraph", "langchain", "sklearn", "burp"),
    "access-control": ("gpt-4o", "deepseek-coder-v2", "claude", "pentestgpt", "langgraph", "sklearn", "burp"),
    "authentication": ("claude", "gpt-4o", "deepseek-coder-v2", "langgraph", "sklearn"),
    "misconfiguration": ("deepseek-coder-v2", "gpt-4o", "sklearn"),
    "cryptography": ("deepseek-coder-v2", "claude", "sklearn"),
    "integrity": ("deepseek-coder-v2", "gpt-4o", "sklearn"),
    "disclosure": ("deepseek-coder-v2", "gpt-4o", "claude", "sklearn", "burp"),
    "cors": ("gpt-4o", "claude", "deepseek-coder-v2", "sklearn", "burp"),
    "open-redirect": ("deepseek-coder-v2", "gpt-4o", "sklearn", "burp"),
    "jwt": ("deepseek-coder-v2", "gpt-4o", "claude", "pyjwt", "sklearn"),
}


def route_for_engine(engine: str) -> list[str]:
    return list(ENGINE_ROUTES.get(engine, ("gpt-4o", "claude", "deepseek-coder-v2", "sklearn", "burp", "pentestgpt")))


def configured_remote_providers() -> set[str]:
    providers: set[str] = set()
    if os.getenv("BELTU_OPENAI_API_KEY") or os.getenv("OPENAI_API_KEY"):
        providers.add("gpt-4o")
    if os.getenv("BELTU_ANTHROPIC_API_KEY") or os.getenv("ANTHROPIC_API_KEY"):
        providers.add("claude")
    if os.getenv("BELTU_DEEPSEEK_API_KEY") or os.getenv("DEEPSEEK_API_KEY"):
        providers.add("deepseek-coder-v2")
    if os.getenv("BELTU_CODELLAMA_ENABLED", "0") == "1":
        providers.add("codellama")
    if shutil.which(os.getenv("BELTU_PENTESTGPT_BIN", "pentestgpt")):
        providers.add("pentestgpt")
    return providers


def enrich_findings(findings: list[Finding], *, remote: bool = False, providers: list[str] | None = None, orchestrated: bool = False) -> list[Finding]:
    if not findings:
        return findings
    requested = {p.lower() for p in (providers or [])}
    ml = semantic_signal(findings)
    for finding in findings:
        local = analyze_finding(finding)
        route = route_for_engine(finding.engine)
        entry: dict[str, Any] = {
            "route": route,
            "local": local.as_dict(),
            "ml": ml if len(findings) > 1 else {"available": False, "reason": "single finding"},
            "providers_used": [],
            "provider_results": {},
        }
        if orchestrated:
            from beltu.ai_graph import run_graph
            graph_result = run_graph([finding], providers=list(requested) or None, allow_remote=remote)
            entry["orchestration"] = graph_result
            for name, value in graph_result.get("provider_results", {}).items():
                if value.get("ok"):
                    entry["providers_used"].append(name)
                    entry["provider_results"][name] = value
        elif remote or requested:
            prompt = build_prompt([finding])
            selected = requested or (configured_remote_providers() & set(route))
            selected -= {"burp", "sklearn", "langgraph", "langchain", "interactsh", "pyjwt"}
            if "gpt-4o" in selected:
                r = openai_gpt4o(prompt)
                entry["provider_results"]["gpt-4o"] = {"ok": r.ok, "data": r.data, "error": r.error, "latency_ms": r.latency_ms}
                if r.ok: entry["providers_used"].append("gpt-4o")
            if "claude" in selected:
                r = anthropic_claude(prompt)
                entry["provider_results"]["claude"] = {"ok": r.ok, "data": r.data, "error": r.error, "latency_ms": r.latency_ms}
                if r.ok: entry["providers_used"].append("claude")
            if "deepseek-coder-v2" in selected or "deepseek" in selected:
                r = deepseek_coder_v2(prompt)
                entry["provider_results"]["deepseek-coder-v2"] = {"ok": r.ok, "data": r.data, "error": r.error, "latency_ms": r.latency_ms}
                if r.ok: entry["providers_used"].append("deepseek-coder-v2")
            if "codellama" in selected:
                r = ollama_chat(prompt)
                entry["provider_results"]["codellama"] = {"ok": r.ok, "data": r.data, "error": r.error, "latency_ms": r.latency_ms}
                if r.ok: entry["providers_used"].append("codellama")
            if "pentestgpt" in selected:
                r = pentestgpt_plan(prompt)
                entry["provider_results"]["pentestgpt"] = {"ok": r.ok, "data": r.data, "error": r.error, "latency_ms": r.latency_ms}
                if r.ok: entry["providers_used"].append("pentestgpt")
        finding.ai = entry
    return findings
