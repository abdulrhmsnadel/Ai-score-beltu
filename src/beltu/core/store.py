from __future__ import annotations

import sqlite3
from pathlib import Path

from .models import Evidence, Finding
from .http import redact_data, redact_url


class FindingStore:
    def __init__(self, path: str | Path = "beltu.sqlite3") -> None:
        self.path = str(path)
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(self.path)

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS findings (
                    id TEXT PRIMARY KEY,
                    engine TEXT NOT NULL,
                    category TEXT NOT NULL,
                    title TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    confidence REAL NOT NULL,
                    target TEXT NOT NULL,
                    parameter TEXT,
                    status TEXT NOT NULL,
                    payload TEXT NOT NULL
                )
                """
            )

    def save(self, finding: Finding) -> None:
        safe = finding.model_copy(update={
            "target": redact_url(finding.target),
            "evidence": [Evidence(kind=e.kind, title=e.title, data=redact_data(e.data)) for e in finding.evidence],
            "ai": redact_data(finding.ai),
        })
        with self._connect() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO findings
                (id, engine, category, title, severity, confidence, target, parameter, status, payload)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    safe.id,
                    safe.engine,
                    safe.category,
                    safe.title,
                    safe.severity.value,
                    safe.confidence,
                    safe.target,
                    safe.parameter,
                    safe.status.value,
                    safe.model_dump_json(),
                ),
            )

    def all(self) -> list[Finding]:
        with self._connect() as conn:
            rows = conn.execute("SELECT payload FROM findings ORDER BY rowid DESC").fetchall()
        return [Finding.model_validate_json(row[0]) for row in rows]
