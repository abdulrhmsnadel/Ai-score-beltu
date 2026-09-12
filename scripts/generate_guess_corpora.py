#!/usr/bin/env python3
"""Regenerate the bundled deterministic 10,000-case sample corpora."""
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from beltu.guessing import generate_cases, write_cases  # noqa: E402

out = ROOT / "data" / "guessing"
out.mkdir(parents=True, exist_ok=True)
write_cases(out / "mixed-10000.jsonl", generate_cases(None, 10_000, seed=1337))
write_cases(out / "access-control-10000.jsonl", generate_cases("access-control", 10_000, seed=1337))
print("Generated mixed-10000.jsonl and access-control-10000.jsonl")
