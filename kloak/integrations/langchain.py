"""LangChain integration — DocumentTransformer + LangSmith trace masking."""

from __future__ import annotations

from collections.abc import Sequence
from copy import deepcopy
from typing import Any

try:
    from langchain_core.documents import Document
    from langchain_core.documents.transformers import BaseDocumentTransformer
except ImportError as exc:
    raise ImportError(
        "langchain-core is required for LangChain integration. "
        "Install it with: pip install kloak[langchain]"
    ) from exc

from kloak.config import DEFAULT_LANGUAGE, DEFAULT_SCORE_THRESHOLD
from kloak.engine import KloakEngine


class KloakAnonymizer(BaseDocumentTransformer):
    """Document transformer that redacts PII using kloak.

    Drop-in replacement for langchain_experimental's PresidioAnonymizer.
    Auto-detects installed kloak extras (malaysian, gitleaks, nlp).

    Args:
        mode: Redaction mode. Only ``"redact"`` is supported currently.
        language: Language code for analysis.
        score_threshold: Minimum confidence score to redact an entity.
        include: Entity types to redact (allowlist). Mutually exclusive priority over exclude.
        exclude: Entity types to skip (blocklist).
    """

    def __init__(
        self,
        *,
        mode: str = "redact",
        language: str = DEFAULT_LANGUAGE,
        score_threshold: float = DEFAULT_SCORE_THRESHOLD,
        include: list[str] | None = None,
        exclude: list[str] | None = None,
    ) -> None:
        if mode != "redact":
            raise ValueError(f"Unsupported mode: {mode!r}. Only 'redact' is currently supported.")
        self._mode = mode
        self._engine = KloakEngine(language=language, score_threshold=score_threshold)
        self._include = include
        self._exclude = exclude

    def transform_documents(
        self, documents: Sequence[Document], **kwargs: Any
    ) -> Sequence[Document]:
        """Redact PII from document contents. Metadata is preserved."""
        result = []
        for doc in documents:
            redacted = self._engine.redact(
                doc.page_content, include=self._include, exclude=self._exclude
            )
            result.append(Document(page_content=redacted.text, metadata=deepcopy(doc.metadata)))
        return result


class KloakLangSmith:
    """LangSmith-compatible anonymizer for trace masking.

    Usage::

        from langsmith import Client
        client = Client(anonymizer=KloakLangSmith())

    Also works with the older API::

        client = Client(hide_inputs=KloakLangSmith(), hide_outputs=KloakLangSmith())

    Args:
        language: Language code for analysis.
        score_threshold: Minimum confidence score to redact an entity.
        include: Entity types to redact (allowlist).
        exclude: Entity types to skip (blocklist).
        max_depth: Optional recursion limit when walking nested structures.
            ``None`` (default) means no explicit depth limit.
    """

    def __init__(
        self,
        *,
        language: str = DEFAULT_LANGUAGE,
        score_threshold: float = DEFAULT_SCORE_THRESHOLD,
        include: list[str] | None = None,
        exclude: list[str] | None = None,
        max_depth: int | None = None,
    ) -> None:
        self._engine = KloakEngine(language=language, score_threshold=score_threshold)
        self._include = include
        self._exclude = exclude
        self._max_depth = max_depth

    def __call__(self, data: Any) -> Any:
        """Walk a LangSmith data dict and redact string content."""
        return self._walk(data, depth=self._max_depth, seen=set())

    def _redact_text(self, text: str) -> str:
        if not text or not text.strip():
            return text
        return self._engine.redact(text, include=self._include, exclude=self._exclude).text

    def _walk(self, data: Any, *, depth: int | None, seen: set[int]) -> Any:
        if isinstance(data, str):
            return self._redact_text(data)
        if depth is not None and depth <= 0:
            return data
        if isinstance(data, dict):
            obj_id = id(data)
            if obj_id in seen:
                return data
            seen.add(obj_id)
            try:
                next_depth = None if depth is None else depth - 1
                return {k: self._walk(v, depth=next_depth, seen=seen) for k, v in data.items()}
            finally:
                seen.remove(obj_id)
        if isinstance(data, list):
            obj_id = id(data)
            if obj_id in seen:
                return data
            seen.add(obj_id)
            try:
                next_depth = None if depth is None else depth - 1
                return [self._walk(item, depth=next_depth, seen=seen) for item in data]
            finally:
                seen.remove(obj_id)
        return data
