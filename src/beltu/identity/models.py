from __future__ import annotations

from enum import Enum
from pydantic import BaseModel, Field


class IdentityRole(str, Enum):
    user = "user"
    admin = "admin"
    custom = "custom"


class TestIdentity(BaseModel):
    name: str
    email: str
    role: IdentityRole = IdentityRole.user
    provider: str = "manual"
    metadata: dict[str, str] = Field(default_factory=dict)
