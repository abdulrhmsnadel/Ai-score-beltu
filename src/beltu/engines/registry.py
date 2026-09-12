from __future__ import annotations

from beltu.core.engine import Engine
from .access_control import AccessControlEngine
from .api import ApiEngine
from .auth import AuthenticationEngine
from .cors import CorsEngine
from .crypto import CryptoEngine
from .csrf import CsrfEngine
from .disclosure import DisclosureEngine
from .integrity import IntegrityEngine
from .jwt import JwtEngine
from .misconfig import MisconfigEngine
from .open_redirect import OpenRedirectEngine
from .ssrf import SsrfEngine

ENGINE_MAP: dict[str, type[Engine]] = {
    "ssrf": SsrfEngine,
    "csrf": CsrfEngine,
    "api": ApiEngine,
    "access-control": AccessControlEngine,
    "authentication": AuthenticationEngine,
    "misconfiguration": MisconfigEngine,
    "cryptography": CryptoEngine,
    "integrity": IntegrityEngine,
    "disclosure": DisclosureEngine,
    "cors": CorsEngine,
    "open-redirect": OpenRedirectEngine,
    "jwt": JwtEngine,
}


def get_engine(name: str) -> Engine:
    try:
        return ENGINE_MAP[name.lower()]()
    except KeyError as exc:
        supported = ", ".join(sorted(ENGINE_MAP))
        raise ValueError(f"Unknown engine '{name}'. Supported: {supported}") from exc
