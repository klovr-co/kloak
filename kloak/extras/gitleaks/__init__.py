"""GitLeaks secrets detection (kloak[gitleaks])."""

from __future__ import annotations

from presidio_analyzer import PatternRecognizer

from kloak.extras.gitleaks.cache import get_toml
from kloak.extras.gitleaks.loader import load_gitleaks_recognizers


def get_recognizers() -> list[PatternRecognizer]:
    """Load GitLeaks rules and return as Presidio recognizers."""
    toml_data = get_toml()
    return load_gitleaks_recognizers(toml_data)


__all__ = ["get_recognizers"]
