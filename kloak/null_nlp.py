"""Null NLP engine for regex-only mode. No NER, no spaCy dependency."""

from __future__ import annotations

from collections.abc import Iterator

from presidio_analyzer.nlp_engine import NlpArtifacts, NlpEngine


class NullNlpEngine(NlpEngine):
    """Minimal NLP engine that provides no NER. Enables regex-only operation."""

    def __init__(self) -> None:
        self._loaded = True

    def load(self) -> None:
        self._loaded = True

    def is_loaded(self) -> bool:
        return self._loaded

    def process_text(self, text: str, language: str) -> NlpArtifacts:
        return NlpArtifacts(
            entities=[],
            tokens=None,
            tokens_indices=[],
            lemmas=[],
            nlp_engine=self,
            language=language,
            scores=[],
        )

    def process_batch(
        self,
        texts: list[str],
        language: str,
        **kwargs,
    ) -> Iterator[tuple[str, NlpArtifacts]]:
        for text in texts:
            yield text, self.process_text(text, language)

    def is_stopword(self, word: str, language: str) -> bool:
        return False

    def is_punct(self, word: str, language: str) -> bool:
        return False

    def get_supported_entities(self) -> list[str]:
        return []

    def get_supported_languages(self) -> list[str]:
        return ["en"]
