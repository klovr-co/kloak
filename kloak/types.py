from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
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

    def to_json(self, path: str | None = None) -> str | None:
        """Write mapping to JSON file, or return JSON string if no path."""
        data = json.dumps(self.mapping, indent=2, ensure_ascii=False)
        if path is None:
            return data
        Path(path).write_text(data, encoding="utf-8")
        return None

    @classmethod
    def load_mapping(cls, path: str) -> dict[str, str]:
        """Load mapping dict from JSON file."""
        return json.loads(Path(path).read_text(encoding="utf-8"))
