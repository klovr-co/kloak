"""Kloak your data before it touches AI. Local-first PII & secrets redaction."""

from __future__ import annotations

from threading import Lock

from kloak.engine import KloakEngine
from kloak.types import EntityMatch, RedactResult, TokenizeResult

__all__ = [
    "redact",
    "tokenize",
    "deanonymize",
    "backend",
    "KloakEngine",
    "RedactResult",
    "TokenizeResult",
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


def tokenize(
    text: str,
    *,
    language: str | None = None,
    include: list[str] | None = None,
    exclude: list[str] | None = None,
) -> TokenizeResult:
    """Tokenize PII with numbered placeholders for reversible redaction.

    Args:
        text: Input text to tokenize.
        language: Language code (default: "en").
        include: Only tokenize these entity types. Takes priority over exclude.
        exclude: Skip these entity types.

    Returns:
        TokenizeResult with tokenized text, mapping, and detected entities.

    Example:
        >>> import kloak
        >>> result = kloak.tokenize("Email ahmad@mail.com")
        >>> result.text
        'Email <EMAIL_ADDRESS_1>'
        >>> result.mapping
        {'<EMAIL_ADDRESS_1>': 'ahmad@mail.com'}
    """
    return _get_engine().tokenize(text, language=language, include=include, exclude=exclude)


def deanonymize(text: str, mapping: dict[str, str]) -> str:
    """Replace tokens with original values using a mapping from tokenize().

    Args:
        text: Text containing tokens (e.g. from LLM response).
        mapping: Token-to-original mapping from TokenizeResult.mapping.

    Returns:
        Text with tokens replaced by original values.

    Example:
        >>> import kloak
        >>> result = kloak.tokenize("Email ahmad@mail.com")
        >>> kloak.deanonymize(result.text, result.mapping)
        'Email ahmad@mail.com'
    """
    return KloakEngine.deanonymize(text, mapping)


# Module-level property via __getattr__
def __getattr__(name: str):
    if name == "backend":
        return _get_engine().backend
    raise AttributeError(f"module 'kloak' has no attribute {name}")
