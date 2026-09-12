from __future__ import annotations

from typing import Any

from beltu.ai import build_prompt
from beltu.ai_providers import (
    anthropic_claude,
    burp_bridge_status,
    deepseek_coder_v2,
    ollama_chat,
    openai_gpt4o,
    pentestgpt_plan,
)
from beltu.core.http import redact_data
from beltu.core.models import Finding


def _available() -> dict[str, bool]:
    import os
    import shutil
    return {
        "openai": bool(os.getenv("BELTU_OPENAI_API_KEY") or os.getenv("OPENAI_API_KEY")),
        "claude": bool(os.getenv("BELTU_ANTHROPIC_API_KEY") or os.getenv("ANTHROPIC_API_KEY")),
        "deepseek": bool(os.getenv("BELTU_DEEPSEEK_API_KEY") or os.getenv("DEEPSEEK_API_KEY")),
        "codellama": os.getenv("BELTU_CODELLAMA_ENABLED", "0") == "1",
        "pentestgpt": shutil.which(os.getenv("BELTU_PENTESTGPT_BIN", "pentestgpt")) is not None,
        "burp": True,
    }


def run_graph(findings: list[Finding], *, providers: list[str] | None = None, allow_remote: bool = False) -> dict[str, Any]:
    """Run a bounded AI review graph.

    LangGraph/LangChain are optional dependencies. When installed, this function uses a
    StateGraph with explicit nodes; otherwise it runs the same nodes sequentially so the
    core CLI remains dependency-light and deterministic.
    """
    safe_findings = [redact_data(f.model_dump(mode="json")) for f in findings[:100]]
    selected = [p.lower() for p in (providers or [])]
    state: dict[str, Any] = {"findings": safe_findings, "provider_results": {}, "steps": []}

    def sanitize(s: dict[str, Any]) -> dict[str, Any]:
        s["prompt"] = build_prompt(findings)
        s["steps"].append("sanitize")
        return s

    def local_ml(s: dict[str, Any]) -> dict[str, Any]:
        from beltu.ml import semantic_signal
        s["ml"] = semantic_signal(findings)
        s["steps"].append("local-ml")
        return s

    def remote(s: dict[str, Any]) -> dict[str, Any]:
        if not allow_remote and not selected:
            s["steps"].append("remote-skipped")
            return s
        avail = _available()
        wanted = selected or [name for name, ready in avail.items() if ready]
        for provider in wanted:
            if provider == "openai" and avail["openai"]:
                r = openai_gpt4o(s["prompt"])
            elif provider == "claude" and avail["claude"]:
                r = anthropic_claude(s["prompt"])
            elif provider == "deepseek" and avail["deepseek"]:
                r = deepseek_coder_v2(s["prompt"])
            elif provider in {"codellama", "ollama"} and avail["codellama"]:
                r = ollama_chat(s["prompt"])
            elif provider == "pentestgpt" and avail["pentestgpt"]:
                r = pentestgpt_plan(s["prompt"])
            elif provider == "burp":
                r = burp_bridge_status()
            else:
                continue
            s["provider_results"][provider] = {"ok": r.ok, "data": redact_data(r.data), "error": r.error, "latency_ms": r.latency_ms}
        s["steps"].append("remote")
        return s

    def consensus(s: dict[str, Any]) -> dict[str, Any]:
        votes = []
        for name, result in s["provider_results"].items():
            if result.get("ok"):
                data = result.get("data") or {}
                verdict = data.get("verdict") or data.get("summary") or data.get("assessment")
                if verdict:
                    votes.append({"provider": name, "signal": str(verdict)[:500]})
        s["consensus"] = {"provider_count": len(votes), "signals": votes[:20], "method": "evidence-first; provider agreement is advisory"}
        s["steps"].append("consensus")
        return s

    try:
        from langgraph.graph import END, START, StateGraph
        from langchain_core.runnables import RunnableLambda
        class State(dict[str, Any]):
            pass
        # LangChain composes the explicit transformation nodes; LangGraph provides stateful orchestration.
        sanitize_chain = RunnableLambda(sanitize)
        local_ml_chain = RunnableLambda(local_ml)
        remote_chain = RunnableLambda(remote)
        consensus_chain = RunnableLambda(consensus)
        graph = StateGraph(State)
        graph.add_node("sanitize", sanitize_chain)
        graph.add_node("local_ml", local_ml_chain)
        graph.add_node("remote", remote_chain)
        graph.add_node("consensus", consensus_chain)
        graph.add_edge(START, "sanitize")
        graph.add_edge("sanitize", "local_ml")
        graph.add_edge("local_ml", "remote")
        graph.add_edge("remote", "consensus")
        graph.add_edge("consensus", END)
        result = graph.compile().invoke(state)
        result["orchestrator"] = "langgraph"
        try:
            import langchain  # noqa: F401
            result["langchain_available"] = True
        except Exception:
            result["langchain_available"] = False
        return result
    except Exception:
        state = sanitize(state)
        state = local_ml(state)
        state = remote(state)
        state = consensus(state)
        state["orchestrator"] = "builtin-sequential-fallback"
        state["langchain_available"] = False
        return state
