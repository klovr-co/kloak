from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from presidio_analyzer import RecognizerResult


@dataclass(frozen=True)
class EntityMatch:
    """A detected entity in the original text."""

    type: str
    start: int
    end: int
    score: float

    @classmethod
    def from_presidio(cls, result: RecognizerResult) -> EntityMatch:
        return cls(
            type=result.entity_type,
            start=result.start,
            end=result.end,
            score=result.score,
        )


@dataclass(frozen=True)
class RedactResult:
    """Result of a redact() call."""

    text: str
    entities: list[EntityMatch]


@dataclass(frozen=True)
class TokenizeResult:
    """Result of a tokenize() call — reversible redaction with numbered tokens."""

    text: str
    mapping: dict[str, str]
    entities: list[EntityMatch]
