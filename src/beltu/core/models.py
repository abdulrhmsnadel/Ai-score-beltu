from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any
from uuid import uuid4

from beltu.version import VERSION
from pydantic import BaseModel, ConfigDict, Field, field_validator

def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class Severity(str, Enum):
    info = "info"
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class FindingStatus(str, Enum):
    new = "new"
    confirmed = "confirmed"
    false_positive = "false_positive"
    accepted = "accepted"
    fixed = "fixed"


class VerificationLevel(str, Enum):
    informational = "informational"
    candidate = "candidate"
    corroborated = "corroborated"
    confirmed = "confirmed"


class Evidence(BaseModel):
    model_config = ConfigDict(extra="forbid")
    kind: str
    title: str
    data: dict[str, Any] = Field(default_factory=dict)


class Finding(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid4()))
    engine: str
    category: str
    title: str
    severity: Severity
    confidence: float = Field(ge=0, le=1)
    target: str
    parameter: str | None = None
    description: str = ""
    remediation: str = ""
    status: FindingStatus = FindingStatus.new
    verification: VerificationLevel = VerificationLevel.candidate
    evidence: list[Evidence] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    cwe: list[str] = Field(default_factory=list)
    owasp: list[str] = Field(default_factory=list)
    scanner_version: str = VERSION
    duration_ms: float | None = Field(default=None, ge=0)
    requests_made: int = Field(default=0, ge=0)
    fingerprint: str | None = None
    ai: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=utc_now)

    @field_validator("confidence")
    @classmethod
    def clamp_confidence(cls, value: float) -> float:
        return round(float(value), 4)


class ScanContext(BaseModel):
    model_config = ConfigDict(extra="forbid")
    target: str
    allow_hosts: list[str] = Field(default_factory=list)
    timeout_seconds: float = Field(default=10, gt=0, le=120)
    max_body_bytes: int = Field(default=1_000_000, gt=1024, le=10_000_000)
    retries: int = Field(default=1, ge=0, le=5)
    retry_statuses: set[int] = Field(default_factory=lambda: {429, 500, 502, 503, 504})
    user_agent: str = f"AI-SCORE-BELTU/{VERSION}"
    follow_redirects: bool = False
    verify_tls: bool = True
    headers: dict[str, str] = Field(default_factory=dict)
    options: dict[str, Any] = Field(default_factory=dict)
    metadata: dict[str, Any] = Field(default_factory=dict)
