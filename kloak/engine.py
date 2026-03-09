"""Core redaction engine wrapping Presidio."""

from __future__ import annotations

import logging
from importlib import import_module
from threading import Lock

from presidio_analyzer import AnalyzerEngine, RecognizerRegistry, RecognizerResult
from presidio_anonymizer import AnonymizerEngine

from kloak.config import DEFAULT_LANGUAGE, DEFAULT_SCORE_THRESHOLD
from kloak.nlp_backend import detect_backend
from kloak.types import EntityMatch, RedactResult, TokenizeResult

logger = logging.getLogger("kloak")


class KloakEngine:
    """Main kloak engine. Wraps Presidio with auto-detected NLP backend."""

    def __init__(
        self,
        *,
        language: str = DEFAULT_LANGUAGE,
        score_threshold: float = DEFAULT_SCORE_THRESHOLD,
    ) -> None:
        self._analyzer: AnalyzerEngine | None = None
        self._anonymizer: AnonymizerEngine | None = None
        self._language = language
        self._score_threshold = score_threshold
        self._backend: str | None = None
        self._init_lock = Lock()

    @property
    def backend(self) -> str:
        """Return the active NLP backend name."""
        self._ensure_initialized()
        assert self._backend is not None
        return self._backend

    def _ensure_initialized(self) -> None:
        if self._analyzer is not None:
            return
        with self._init_lock:
            if self._analyzer is not None:
                return

            nlp_engine, self._backend = detect_backend()

            registry = RecognizerRegistry()
            registry.load_predefined_recognizers(nlp_engine=nlp_engine)

            self._load_extras(registry)

            self._analyzer = AnalyzerEngine(
                nlp_engine=nlp_engine,
                registry=registry,
                supported_languages=[self._language],
            )
            self._anonymizer = AnonymizerEngine()

    def _load_extras(self, registry: RecognizerRegistry) -> None:
        """Load optional extras without hiding internal errors."""
        self._load_optional_extra(registry, "kloak.extras.malaysian", "Malaysian")
        self._load_optional_extra(registry, "kloak.extras.gitleaks", "GitLeaks")

    def _load_optional_extra(
        self,
        registry: RecognizerRegistry,
        module_name: str,
        label: str,
    ) -> None:
        try:
            module = import_module(module_name)
        except ModuleNotFoundError as exc:
            if exc.name == module_name:
                logger.debug("Extra not installed: %s", label)
                return
            logger.exception("Failed to import extra %s", label)
            return

        try:
            for recognizer in module.get_recognizers():
                registry.add_recognizer(recognizer)
            logger.debug("Loaded %s extra", label)
        except Exception:
            logger.exception("Failed to initialize extra %s", label)

    def _resolve_entities(
        self,
        include: list[str] | None,
        exclude: list[str] | None,
    ) -> list[str] | None:
        """Resolve include/exclude to entity types for Presidio, with validation."""
        self._ensure_initialized()
        all_entities = set(self._analyzer.get_supported_entities(language=self._language))

        def validate(values: list[str]) -> None:
            unknown = sorted(set(values) - all_entities)
            if unknown:
                raise ValueError(f"Unknown entity types: {', '.join(unknown)}")

        if include is not None:
            validate(include)
            return include
        if exclude is not None:
            validate(exclude)
            all_entities = self._analyzer.get_supported_entities(language=self._language)
            return [e for e in all_entities if e not in exclude]
        return None

    def redact(
        self,
        text: str,
        *,
        language: str | None = None,
        include: list[str] | None = None,
        exclude: list[str] | None = None,
    ) -> RedactResult:
        """Redact PII from text. Returns RedactResult with redacted text and entity list."""
        self._ensure_initialized()
        lang = language or self._language
        entities = self._resolve_entities(include, exclude)

        # Short-circuit: explicit empty include means "redact nothing"
        if entities is not None and len(entities) == 0:
            return RedactResult(text=text, entities=[])

        analyzer_results = self._analyzer.analyze(
            text=text,
            language=lang,
            entities=entities,
            score_threshold=self._score_threshold,
        )

        anonymizer_result = self._anonymizer.anonymize(
            text=text,
            analyzer_results=analyzer_results,
        )

        return RedactResult(
            text=anonymizer_result.text,
            entities=[EntityMatch.from_presidio(r) for r in analyzer_results],
        )

    @staticmethod
    def _resolve_overlaps(
        results: list[RecognizerResult],
    ) -> list[RecognizerResult]:
        """Remove overlapping entities, keeping the highest-score (longest span) one."""
        kept: list[RecognizerResult] = []
        for r in results:
            overlapping = [k for k in kept if k.start < r.end and r.start < k.end]
            if not overlapping:
                kept.append(r)
                continue
            # Compare against the worst overlapping entity
            weakest = min(overlapping, key=lambda k: (k.score, k.end - k.start))
            if (r.score, r.end - r.start) > (weakest.score, weakest.end - weakest.start):
                for k in overlapping:
                    kept.remove(k)
                kept.append(r)
        return sorted(kept, key=lambda r: r.start)

    def tokenize(
        self,
        text: str,
        *,
        language: str | None = None,
        include: list[str] | None = None,
        exclude: list[str] | None = None,
    ) -> TokenizeResult:
        """Tokenize PII with numbered placeholders. Returns TokenizeResult with mapping."""
        self._ensure_initialized()
        lang = language or self._language
        entities = self._resolve_entities(include, exclude)

        if entities is not None and len(entities) == 0:
            return TokenizeResult(text=text, mapping={}, entities=[])

        analyzer_results = self._analyzer.analyze(
            text=text,
            language=lang,
            entities=entities,
            score_threshold=self._score_threshold,
        )

        if not analyzer_results:
            return TokenizeResult(text=text, mapping={}, entities=[])

        # Resolve overlapping entities: keep highest-score (longest span as tiebreaker)
        # Sort by start position (left-to-right) for consistent numbering
        sorted_results = self._resolve_overlaps(
            sorted(analyzer_results, key=lambda r: r.start)
        )

        # Assign per-type counters
        type_counters: dict[str, int] = {}
        token_assignments: list[tuple[RecognizerResult, str]] = []
        for r in sorted_results:
            count = type_counters.get(r.entity_type, 0) + 1
            type_counters[r.entity_type] = count
            token = f"<{r.entity_type}_{count}>"
            token_assignments.append((r, token))

        # Build mapping and replace text (process right-to-left to preserve positions)
        mapping: dict[str, str] = {}
        result_text = text
        for r, token in reversed(token_assignments):
            mapping[token] = text[r.start : r.end]
            result_text = result_text[: r.start] + token + result_text[r.end :]

        return TokenizeResult(
            text=result_text,
            mapping=mapping,
            entities=[EntityMatch.from_presidio(r) for r in sorted_results],
        )
