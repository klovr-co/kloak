"""Kloak your data before it touches AI. Local-first PII & secrets redaction."""

from __future__ import annotations

from threading import Lock

from kloak.engine import KloakEngine
from kloak.types import EntityMatch, RedactResult

__all__ = [
    "redact",
    "backend",
    "KloakEngine",
    "RedactResult",
    "EntityMatch",
]

_default_engine: KloakEngine | None = None
_engine_lock = Lock()


def _get_engine() -> KloakEngine:
    global _default_engine
    if _default_engine is not None:
        return _default_engine
    with _engine_lock:
        if _default_engine is None:
            _default_engine = KloakEngine()
    return _default_engine


def redact(
    text: str,
    *,
    language: str | None = None,
    include: list[str] | None = None,
    exclude: list[str] | None = None,
) -> RedactResult:
    """Redact PII and secrets from text.

    Args:
        text: Input text to redact.
        language: Language code (default: "en").
        include: Only redact these entity types. Takes priority over exclude.
        exclude: Skip these entity types.

    Returns:
        RedactResult with redacted text and detected entities.

    Example:
        >>> import kloak
        >>> result = kloak.redact("Email me at ahmad@mail.com")
        >>> result.text
        'Email me at <EMAIL_ADDRESS>'
    """
    return _get_engine().redact(text, language=language, include=include, exclude=exclude)


# Module-level property via __getattr__
def __getattr__(name: str):
    if name == "backend":
        return _get_engine().backend
    raise AttributeError(f"module 'kloak' has no attribute {name}")
