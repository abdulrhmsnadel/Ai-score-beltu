# Dependency baseline

This release intentionally pins its runtime and development dependencies for reproducible installs.

| Package | Pinned release | Status checked |
|---|---:|---|
| HTTPX | 0.28.1 | Stable release |
| Typer | 0.26.6 | Stable release |
| Rich | 15.0.0 | Stable release |
| Pydantic | 2.13.5 | Stable release |
| PyYAML | 6.0.3 | Stable release |
| pytest | 9.1.1 | Development/test |
| Ruff | 0.16.7 | Development/lint |
| Hatchling | 1.32.0 | Build backend |

Pre-release versions are not used just because they are newer. Reproducibility and stability take priority over adopting an unreleased development version.

The optional local Ollama provider was checked against the current Ollama release line; v0.34.0 was the latest release observed on September 9, 2026.
