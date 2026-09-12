from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterable

from .models import Finding, ScanContext


class Engine(ABC):
    name: str = "base"
    category: str = "generic"
    description: str = ""

    @property
    def requires(self) -> list[str]:
        return ["Authorized target", "Explicit scope"]

    @abstractmethod
    def run(self, context: ScanContext) -> Iterable[Finding]:
        raise NotImplementedError
