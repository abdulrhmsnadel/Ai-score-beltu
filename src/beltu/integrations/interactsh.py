from __future__ import annotations

import json
import os
import shutil
import subprocess
from dataclasses import dataclass
from typing import Any


@dataclass(slots=True)
class Interaction:
    payload: str
    raw: dict[str, Any]


def client_available(binary: str | None = None) -> bool:
    return shutil.which(binary or os.getenv("BELTU_INTERACTSH_BIN", "interactsh-client")) is not None


def generate_payload(*, server: str | None = None, token: str | None = None, binary: str | None = None) -> str:
    """Generate one OOB payload using the official interactsh client.

    The official project exposes a Go client/CLI and JSONL interaction output; this adapter
    deliberately wraps that interface instead of inventing an undocumented REST endpoint.
    """
    command = binary or os.getenv("BELTU_INTERACTSH_BIN", "interactsh-client")
    if shutil.which(command) is None:
        raise RuntimeError("interactsh-client not found")
    args = [command, "-n", "1", "-ps"]
    if server:
        args += ["-server", server.rstrip("/")]
    if token:
        args += ["-token", token]
    try:
        proc = subprocess.run(args, capture_output=True, text=True, timeout=15, check=False)
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError("interactsh payload generation timed out") from exc
    if proc.returncode != 0:
        raise RuntimeError((proc.stderr or proc.stdout or "interactsh-client failed").strip()[:1000])
    for line in (proc.stdout or "").splitlines():
        line = line.strip()
        if ".oast." in line or line.startswith("http"):
            return line
    raise RuntimeError("interactsh-client did not return a payload")


def parse_jsonl(text: str) -> list[Interaction]:
    out: list[Interaction] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict):
            payload = str(value.get("full-id") or value.get("unique-id") or "")
            out.append(Interaction(payload=payload, raw=value))
    return out
