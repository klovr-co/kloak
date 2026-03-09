# Phase 1.0 Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Ship `kloak.redact()` with Malaysian PII detection, GitLeaks secrets detection, NLP auto-detection, and CI.

**Architecture:** Thin Presidio wrapper. `KloakEngine` configures `AnalyzerEngine` + `AnonymizerEngine`, auto-detects spaCy or falls back to `NullNlpEngine` for regex-only mode. Extras are loaded via guarded optional imports (missing extra is skipped; internal failures are logged). Flat package layout (`kloak/` at root).

**Tech Stack:** Python 3.11+, Presidio, spaCy (optional), httpx (gitleaks), hatchling build, uv, pytest, ruff, GitHub Actions.

**Design doc:** `docs/plans/2026-03-09-phase1-design.md`

### Required Hardening Overrides (apply across all tasks)

These rules override any conflicting snippet below:

1. `KLOAK_NLP_BACKEND` contract is explicit:
   - `regex` forces regex-only
   - `spacy` is strict and raises if spaCy/model is unavailable
   - `auto` prefers spaCy and falls back to regex-only
2. Lazy initialization must be thread-safe:
   - `KloakEngine._ensure_initialized()` uses an init lock
   - module-level default engine getter is lock-protected
3. `include`/`exclude` must validate entity names:
   - unknown values raise `ValueError` (never silent no-op)
4. Extra loading must not swallow internal failures:
   - only skip genuinely missing optional module
   - log exception for import/runtime failures inside extras
5. GitLeaks cache must handle parse failures:
   - corrupt TOML is treated as fetch/cache failure and enters fallback flow
6. GitLeaks default source should be pinned (tag or commit), not a moving branch URL

---

### Task 1: Project Scaffolding

**Files:**
- Create: `pyproject.toml`
- Create: `kloak/__init__.py` (empty placeholder)
- Create: `kloak/extras/__init__.py` (empty)
- Create: `kloak/extras/malaysian/__init__.py` (empty)
- Create: `kloak/extras/gitleaks/__init__.py` (empty)
- Create: `tests/__init__.py` (empty)
- Create: `tests/conftest.py` (empty)

**Step 1: Create `pyproject.toml`**

```toml
[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[project]
name = "kloak"
version = "0.1.0"
description = "Kloak your data before it touches AI. Local-first PII & secrets redaction."
readme = "README.md"
license = "Apache-2.0"
requires-python = ">=3.11"
authors = [{ name = "Klovr", email = "hello@klovr.co" }]
classifiers = [
    "Development Status :: 3 - Alpha",
    "Intended Audience :: Developers",
    "License :: OSI Approved :: Apache Software License",
    "Programming Language :: Python :: 3.11",
    "Programming Language :: Python :: 3.12",
    "Programming Language :: Python :: 3.13",
    "Topic :: Security",
    "Topic :: Software Development :: Libraries :: Python Modules",
]

dependencies = [
    "presidio-analyzer>=2.2",
    "presidio-anonymizer>=2.2",
]

[project.optional-dependencies]
nlp = ["spacy>=3.7", "en-core-web-sm>=3.7"]
my = []  # marker extra (recognizers ship in core package)
gitleaks = ["httpx>=0.27"]
dev = ["pytest>=8.0", "pytest-cov", "ruff"]

[project.urls]
Homepage = "https://github.com/klovr/kloak"
Repository = "https://github.com/klovr/kloak"

[tool.ruff]
target-version = "py311"
line-length = 99

[tool.ruff.lint]
select = ["E", "F", "I", "UP"]

[tool.pytest.ini_options]
testpaths = ["tests"]
```

**Step 2: Create directory structure with empty `__init__.py` files**

```bash
mkdir -p kloak/extras/malaysian kloak/extras/gitleaks tests
touch kloak/__init__.py kloak/extras/__init__.py kloak/extras/malaysian/__init__.py kloak/extras/gitleaks/__init__.py tests/__init__.py tests/conftest.py
```

**Step 3: Init uv and install dev deps**

```bash
uv sync --extra dev --extra my --extra gitleaks
```

**Step 4: Verify setup**

Run: `uv run python -c "import kloak; print('ok')"`
Expected: `ok`

**Step 5: Commit**

```bash
git add pyproject.toml kloak/ tests/ uv.lock
git commit -m "chore: scaffold project structure with pyproject.toml"
```

---

### Task 2: Types

**Files:**
- Create: `kloak/types.py`
- Create: `tests/test_types.py`

**Step 1: Write the failing test**

```python
# tests/test_types.py
from kloak.types import EntityMatch, RedactResult


def test_entity_match_is_frozen():
    e = EntityMatch(type="EMAIL_ADDRESS", start=0, end=5, score=0.85)
    assert e.type == "EMAIL_ADDRESS"
    assert e.start == 0
    assert e.end == 5
    assert e.score == 0.85


def test_entity_match_from_presidio():
    from presidio_analyzer import RecognizerResult

    pr = RecognizerResult(entity_type="PERSON", start=10, end=15, score=0.9)
    e = EntityMatch.from_presidio(pr)
    assert e.type == "PERSON"
    assert e.start == 10
    assert e.end == 15
    assert e.score == 0.9


def test_redact_result():
    r = RedactResult(
        text="Hello <PERSON>",
        entities=[EntityMatch(type="PERSON", start=6, end=11, score=0.85)],
    )
    assert r.text == "Hello <PERSON>"
    assert len(r.entities) == 1
```

**Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_types.py -v`
Expected: FAIL — `ModuleNotFoundError` or `ImportError`

**Step 3: Write minimal implementation**

```python
# kloak/types.py
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
```

**Step 4: Run test to verify it passes**

Run: `uv run pytest tests/test_types.py -v`
Expected: PASS (3 tests)

**Step 5: Commit**

```bash
git add kloak/types.py tests/test_types.py
git commit -m "feat: add RedactResult and EntityMatch types"
```

---

### Task 3: Config

**Files:**
- Create: `kloak/config.py`

**Step 1: Write implementation** (no test needed — pure config constants)

```python
# kloak/config.py
from __future__ import annotations

import os
from pathlib import Path

# NLP backend
NLP_BACKEND = os.environ.get("KLOAK_NLP_BACKEND", "auto")
SPACY_MODEL = os.environ.get("KLOAK_SPACY_MODEL", "")

# GitLeaks
GITLEAKS_URL = os.environ.get(
    "KLOAK_GITLEAKS_URL",
    "<PINNED_TAG_OR_COMMIT_URL>",
)
GITLEAKS_CACHE_PATH = Path(
    os.environ.get("KLOAK_GITLEAKS_CACHE_PATH", "~/.kloak/gitleaks_rules.toml")
).expanduser()
SECRETS_REFRESH_HOURS = int(os.environ.get("KLOAK_SECRETS_REFRESH_HOURS", "168"))

# Engine defaults
DEFAULT_LANGUAGE = "en"
DEFAULT_SCORE_THRESHOLD = 0.35
```

**Step 2: Commit**

```bash
git add kloak/config.py
git commit -m "feat: add config module with env var defaults"
```

---

### Task 4: NullNlpEngine

**Files:**
- Create: `kloak/null_nlp.py`
- Create: `tests/test_null_nlp.py`

**Step 1: Write the failing test**

```python
# tests/test_null_nlp.py
from kloak.null_nlp import NullNlpEngine


def test_null_engine_loads():
    engine = NullNlpEngine()
    assert engine.is_loaded()


def test_null_engine_returns_empty_artifacts():
    engine = NullNlpEngine()
    artifacts = engine.process_text("Hello world", "en")
    assert artifacts.entities == []
    assert artifacts.language == "en"


def test_null_engine_supported_languages():
    engine = NullNlpEngine()
    assert "en" in engine.get_supported_languages()


def test_null_engine_no_ner_entities():
    engine = NullNlpEngine()
    assert engine.get_supported_entities() == []
```

**Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_null_nlp.py -v`
Expected: FAIL

**Step 3: Write minimal implementation**

```python
# kloak/null_nlp.py
"""Null NLP engine for regex-only mode. No NER, no spaCy dependency."""

from __future__ import annotations

from typing import Iterator

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
```

**Step 4: Run test to verify it passes**

Run: `uv run pytest tests/test_null_nlp.py -v`
Expected: PASS (4 tests)

**Step 5: Commit**

```bash
git add kloak/null_nlp.py tests/test_null_nlp.py
git commit -m "feat: add NullNlpEngine for regex-only mode"
```

---

### Task 5: NLP Backend Detection

**Files:**
- Create: `kloak/nlp_backend.py`
- Create: `tests/test_nlp_backend.py`

**Step 1: Write the failing test**

```python
# tests/test_nlp_backend.py
import pytest

from kloak.nlp_backend import detect_backend
from kloak.null_nlp import NullNlpEngine


def test_detect_backend_regex_forced(monkeypatch):
    monkeypatch.setenv("KLOAK_NLP_BACKEND", "regex")
    engine, name = detect_backend()
    assert isinstance(engine, NullNlpEngine)
    assert name == "regex-only"


def test_detect_backend_auto_no_spacy(monkeypatch):
    """When spaCy is not importable, falls back to regex-only."""
    monkeypatch.setenv("KLOAK_NLP_BACKEND", "auto")
    # Hide spacy from import system
    import sys

    real_import = __builtins__.__import__ if hasattr(__builtins__, "__import__") else __import__

    def mock_import(name, *args, **kwargs):
        if name == "spacy":
            raise ImportError("mocked")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr("builtins.__import__", mock_import)
    engine, name = detect_backend()
    assert isinstance(engine, NullNlpEngine)
    assert name == "regex-only"


def test_detect_backend_spacy_forced_no_spacy(monkeypatch):
    """Strict mode: if forced spaCy is unavailable, raise instead of silent fallback."""
    monkeypatch.setenv("KLOAK_NLP_BACKEND", "spacy")

    real_import = __builtins__.__import__ if hasattr(__builtins__, "__import__") else __import__

    def mock_import(name, *args, **kwargs):
        if name == "spacy":
            raise ImportError("mocked")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr("builtins.__import__", mock_import)
    with pytest.raises(RuntimeError):
        detect_backend()
```

**Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_nlp_backend.py -v`
Expected: FAIL

**Step 3: Write minimal implementation**

```python
# kloak/nlp_backend.py
"""Auto-detect the best available NLP backend."""

from __future__ import annotations

import logging
import os

from presidio_analyzer.nlp_engine import NlpEngine

from kloak.null_nlp import NullNlpEngine

logger = logging.getLogger("kloak")

_MODEL_PRIORITY = ["en_core_web_lg", "en_core_web_sm"]


def detect_backend() -> tuple[NlpEngine, str]:
    """Detect the best available NLP backend.

    Returns (engine, backend_name) where backend_name is one of:
    - "spacy:<model_name>"
    - "regex-only"
    """
    env = os.environ.get("KLOAK_NLP_BACKEND", "auto")
    if env not in {"auto", "spacy", "regex"}:
        raise ValueError("KLOAK_NLP_BACKEND must be one of: auto, spacy, regex")

    if env == "regex":
        return NullNlpEngine(), "regex-only"

    model_override = os.environ.get("KLOAK_SPACY_MODEL", "")
    models_to_try = [model_override] if model_override else _MODEL_PRIORITY

    try:
        import spacy
        from presidio_analyzer.nlp_engine import SpacyNlpEngine

        for model in models_to_try:
            if spacy.util.is_package(model):
                engine = SpacyNlpEngine(
                    models=[{"lang_code": "en", "model_name": model}],
                )
                engine.load()
                return engine, f"spacy:{model}"
    except ImportError:
        if env == "spacy":
            raise RuntimeError("spaCy backend forced but spaCy is not installed") from None

    if env == "spacy":
        model_list = ", ".join(models_to_try)
        raise RuntimeError(f"spaCy backend forced but no model is installed ({model_list})")

    logger.info("No spaCy model found. Running in regex-only mode.")
    return NullNlpEngine(), "regex-only"
```

**Step 4: Run test to verify it passes**

Run: `uv run pytest tests/test_nlp_backend.py -v`
Expected: PASS (3 tests)

**Step 5: Commit**

```bash
git add kloak/nlp_backend.py tests/test_nlp_backend.py
git commit -m "feat: add NLP backend auto-detection"
```

---

### Task 6: KloakEngine

**Files:**
- Create: `kloak/engine.py`
- Create: `tests/test_core.py`

**Step 1: Write the failing test**

```python
# tests/test_core.py
import os

import pytest


@pytest.fixture(autouse=True)
def force_regex_mode(monkeypatch):
    """Force regex-only mode for core tests — no spaCy dependency."""
    monkeypatch.setenv("KLOAK_NLP_BACKEND", "regex")


class TestRedactBuiltins:
    """Test redaction of Presidio built-in regex entities."""

    def test_redact_email(self):
        from kloak.engine import KloakEngine

        engine = KloakEngine()
        result = engine.redact("Contact me at ahmad@mail.com")
        assert "<EMAIL_ADDRESS>" in result.text
        assert "ahmad@mail.com" not in result.text
        assert any(e.type == "EMAIL_ADDRESS" for e in result.entities)

    def test_redact_phone(self):
        from kloak.engine import KloakEngine

        engine = KloakEngine()
        result = engine.redact("Call 555-123-4567 now")
        assert "555-123-4567" not in result.text

    def test_redact_ip_address(self):
        from kloak.engine import KloakEngine

        engine = KloakEngine()
        result = engine.redact("Server at 192.168.1.1 is down")
        assert "192.168.1.1" not in result.text

    def test_redact_url(self):
        from kloak.engine import KloakEngine

        engine = KloakEngine()
        result = engine.redact("Visit https://secret.example.com/admin")
        assert "secret.example.com" not in result.text

    def test_redact_credit_card(self):
        from kloak.engine import KloakEngine

        engine = KloakEngine()
        result = engine.redact("Card number 4111111111111111")
        assert "4111111111111111" not in result.text

    def test_no_pii_unchanged(self):
        from kloak.engine import KloakEngine

        engine = KloakEngine()
        text = "The weather is nice today"
        result = engine.redact(text)
        assert result.text == text
        assert result.entities == []

    def test_redact_result_type(self):
        from kloak.engine import KloakEngine
        from kloak.types import RedactResult

        engine = KloakEngine()
        result = engine.redact("Email: test@example.com")
        assert isinstance(result, RedactResult)

    def test_entity_positions_reference_original_text(self):
        from kloak.engine import KloakEngine

        engine = KloakEngine()
        text = "Email: ahmad@mail.com"
        result = engine.redact(text)
        entity = next(e for e in result.entities if e.type == "EMAIL_ADDRESS")
        assert text[entity.start : entity.end] == "ahmad@mail.com"


class TestBackendProperty:
    def test_backend_regex_only(self):
        from kloak.engine import KloakEngine

        engine = KloakEngine()
        engine._ensure_initialized()
        assert engine.backend == "regex-only"
```

**Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_core.py -v`
Expected: FAIL

**Step 3: Write minimal implementation**

```python
# kloak/engine.py
"""Core redaction engine wrapping Presidio."""

from __future__ import annotations

import logging
from importlib import import_module
from threading import Lock

from presidio_analyzer import AnalyzerEngine, RecognizerRegistry
from presidio_anonymizer import AnonymizerEngine

from kloak.config import DEFAULT_LANGUAGE, DEFAULT_SCORE_THRESHOLD
from kloak.nlp_backend import detect_backend
from kloak.types import EntityMatch, RedactResult

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
```

**Step 4: Run test to verify it passes**

Run: `uv run pytest tests/test_core.py -v`
Expected: PASS (9 tests)

**Step 5: Commit**

```bash
git add kloak/engine.py tests/test_core.py
git commit -m "feat: add KloakEngine with redact() and auto NLP detection"
```

---

### Task 7: Public API (`__init__.py`)

**Files:**
- Modify: `kloak/__init__.py`
- Create: `tests/test_api.py`

**Step 1: Write the failing test**

```python
# tests/test_api.py
import os

import pytest


@pytest.fixture(autouse=True)
def force_regex_mode(monkeypatch):
    monkeypatch.setenv("KLOAK_NLP_BACKEND", "regex")


def test_module_level_redact():
    import kloak

    result = kloak.redact("Email: ahmad@mail.com")
    assert "<EMAIL_ADDRESS>" in result.text


def test_module_level_backend():
    import kloak

    # Force init by calling redact
    kloak.redact("test")
    assert kloak.backend in ("regex-only", "spacy:en_core_web_sm", "spacy:en_core_web_lg")


def test_public_exports():
    import kloak

    assert hasattr(kloak, "redact")
    assert hasattr(kloak, "backend")
    assert hasattr(kloak, "KloakEngine")
    assert hasattr(kloak, "RedactResult")
    assert hasattr(kloak, "EntityMatch")
```

**Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_api.py -v`
Expected: FAIL

**Step 3: Write implementation**

```python
# kloak/__init__.py
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
```

**Step 4: Run test to verify it passes**

Run: `uv run pytest tests/test_api.py -v`
Expected: PASS (3 tests)

**Step 5: Commit**

```bash
git add kloak/__init__.py tests/test_api.py
git commit -m "feat: add module-level redact() and backend public API"
```

---

### Task 8: Include/Exclude Filtering

**Files:**
- Create: `tests/test_include_exclude.py`

**Step 1: Write the tests** (implementation already exists in engine.py)

```python
# tests/test_include_exclude.py
import os

import pytest

from kloak.engine import KloakEngine


@pytest.fixture(autouse=True)
def force_regex_mode(monkeypatch):
    monkeypatch.setenv("KLOAK_NLP_BACKEND", "regex")


@pytest.fixture
def engine():
    return KloakEngine()


class TestInclude:
    def test_include_only_email(self, engine):
        text = "Email ahmad@mail.com, IP 192.168.1.1"
        result = engine.redact(text, include=["EMAIL_ADDRESS"])
        assert "<EMAIL_ADDRESS>" in result.text
        assert "192.168.1.1" in result.text  # IP not redacted

    def test_include_empty_list_redacts_nothing(self, engine):
        text = "Email ahmad@mail.com"
        result = engine.redact(text, include=[])
        assert result.text == text


class TestExclude:
    def test_exclude_email(self, engine):
        text = "Email ahmad@mail.com, IP 192.168.1.1"
        result = engine.redact(text, exclude=["EMAIL_ADDRESS"])
        assert "ahmad@mail.com" in result.text  # email kept
        assert "192.168.1.1" not in result.text  # IP redacted

    def test_exclude_empty_list_redacts_all(self, engine):
        text = "Email ahmad@mail.com"
        result = engine.redact(text, exclude=[])
        assert "<EMAIL_ADDRESS>" in result.text


class TestIncludeExcludePriority:
    def test_include_takes_priority(self, engine):
        text = "Email ahmad@mail.com, IP 192.168.1.1"
        result = engine.redact(text, include=["EMAIL_ADDRESS"], exclude=["EMAIL_ADDRESS"])
        # include wins — email IS redacted despite being in exclude
        assert "<EMAIL_ADDRESS>" in result.text


class TestValidation:
    def test_unknown_include_raises(self, engine):
        with pytest.raises(ValueError):
            engine.redact("Email ahmad@mail.com", include=["EMAIL"])
```

**Step 2: Run tests**

Run: `uv run pytest tests/test_include_exclude.py -v`
Expected: PASS (6 tests)

**Step 3: Commit**

```bash
git add tests/test_include_exclude.py
git commit -m "test: add include/exclude filtering tests"
```

---

### Task 9: MyKad Validator

**Files:**
- Create: `kloak/extras/malaysian/mykad.py`
- Create: `tests/test_mykad_validation.py`

**Step 1: Write the failing tests**

```python
# tests/test_mykad_validation.py
import pytest

from kloak.extras.malaysian.mykad import validate_mykad

# --- All 58 valid state/place-of-birth codes ---
VALID_STATE_CODES = [
    # Malaysian states
    "01", "02", "03", "04", "05", "06", "07", "08", "09", "10", "11", "12", "13", "14", "15", "16",
    # Extended state codes
    "21", "22", "23", "24", "25", "26", "27", "28", "29", "30", "31", "32", "33", "34", "35",
    "36", "37", "38", "39", "40", "41", "42", "43", "44", "45", "46", "47", "48", "49", "50",
    "51", "52", "53", "54", "55", "56", "57", "58", "59",
    # Foreign country codes
    "60", "61", "62", "63", "64", "65", "66", "67", "68",
    "71", "74", "75", "76", "77", "78", "79",
    "82", "83", "84", "85", "86", "87", "88", "89", "90", "91", "92", "93",
]

INVALID_STATE_CODES = [
    "00", "17", "18", "19", "20", "69", "70", "72", "73", "80", "81",
    "94", "95", "96", "97", "98", "99",
]


class TestValidStateCodes:
    @pytest.mark.parametrize("code", VALID_STATE_CODES)
    def test_valid_state_code(self, code):
        ic = f"880101{code}1234"
        assert validate_mykad(ic), f"State code {code} should be valid"


class TestInvalidStateCodes:
    @pytest.mark.parametrize("code", INVALID_STATE_CODES)
    def test_invalid_state_code(self, code):
        ic = f"880101{code}1234"
        assert not validate_mykad(ic), f"State code {code} should be invalid"


class TestValidDates:
    @pytest.mark.parametrize("date_part,desc", [
        ("880101", "Jan 1 1988"),
        ("960531", "May 31 1996"),
        ("000229", "Feb 29 2000 — leap year"),
        ("040229", "Feb 29 2004 — leap year"),
        ("251231", "Dec 31 2025"),
        ("010101", "Jan 1 2001"),
    ])
    def test_valid_date(self, date_part, desc):
        ic = f"{date_part}011234"
        assert validate_mykad(ic), f"Date {desc} should be valid"


class TestInvalidDates:
    @pytest.mark.parametrize("date_part,desc", [
        ("881301", "month 13"),
        ("880230", "Feb 30"),
        ("880000", "month 0"),
        ("880100", "day 0"),
        ("880132", "Jan 32"),
        ("890229", "Feb 29 non-leap 1989"),
        ("000631", "Jun 31"),
    ])
    def test_invalid_date(self, date_part, desc):
        ic = f"{date_part}011234"
        assert not validate_mykad(ic), f"Date {desc} should be invalid"


class TestFormat:
    def test_with_dashes(self):
        assert validate_mykad("880101-01-1234")

    def test_without_dashes(self):
        assert validate_mykad("880101011234")

    def test_wrong_length_short(self):
        assert not validate_mykad("88010101123")

    def test_wrong_length_long(self):
        assert not validate_mykad("8801010112345")

    def test_non_numeric(self):
        assert not validate_mykad("88010A011234")

    def test_empty_string(self):
        assert not validate_mykad("")
```

**Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_mykad_validation.py -v`
Expected: FAIL

**Step 3: Write minimal implementation**

```python
# kloak/extras/malaysian/mykad.py
"""MyKad (Malaysian IC) validation — date + state/place-of-birth codes."""

from __future__ import annotations

import calendar

VALID_PB_CODES: frozenset[int] = frozenset(
    list(range(1, 17))           # 01-16: Malaysian states
    + list(range(21, 60))        # 21-59: extended state codes
    + list(range(60, 69))        # 60-68: ASEAN countries
    + [71]                       # UK
    + list(range(74, 80))        # 74-79: Asian countries
    + [82]                       # unknown state
    + list(range(83, 94))        # 83-93: regions/continents
)


def validate_mykad(value: str) -> bool:
    """Validate a MyKad IC number beyond regex.

    Checks:
    1. Exactly 12 digits (dashes stripped)
    2. Valid calendar date (YYMMDD)
    3. Valid state/place-of-birth code (positions 7-8)
    """
    digits = value.replace("-", "")

    if len(digits) != 12:
        return False

    if not digits.isdigit():
        return False

    # Parse date
    yy = int(digits[0:2])
    mm = int(digits[2:4])
    dd = int(digits[4:6])

    if mm < 1 or mm > 12:
        return False

    # Determine full year (assume age < 100)
    # 2000-based for 00-25, 1900-based for 26-99 (as of 2026)
    year = 2000 + yy if yy <= 25 else 1900 + yy

    max_day = calendar.monthrange(year, mm)[1]
    if dd < 1 or dd > max_day:
        return False

    # Validate state/place-of-birth code
    pb = int(digits[6:8])
    if pb not in VALID_PB_CODES:
        return False

    return True
```

**Step 4: Run test to verify it passes**

Run: `uv run pytest tests/test_mykad_validation.py -v`
Expected: PASS (all parametrized tests)

**Step 5: Commit**

```bash
git add kloak/extras/malaysian/mykad.py tests/test_mykad_validation.py
git commit -m "feat(extras/my): add MyKad validator with date and state code checks"
```

---

### Task 10: Malaysian Recognizers

**Files:**
- Create: `kloak/extras/malaysian/recognizers.py`
- Modify: `kloak/extras/malaysian/__init__.py`
- Create: `kloak/extras/malaysian/test_fixtures.json`
- Create: `tests/test_malaysian.py`

**Step 1: Write the failing tests**

```python
# tests/test_malaysian.py
import json
import os
from pathlib import Path

import pytest

from kloak.engine import KloakEngine


@pytest.fixture(autouse=True)
def force_regex_mode(monkeypatch):
    monkeypatch.setenv("KLOAK_NLP_BACKEND", "regex")


@pytest.fixture
def engine():
    return KloakEngine()


class TestMyKadRedaction:
    def test_mykad_with_dashes(self, engine):
        result = engine.redact("IC saya 880101-01-1234")
        assert "<MY_IC>" in result.text
        assert "880101-01-1234" not in result.text

    def test_mykad_without_dashes(self, engine):
        result = engine.redact("IC number: 880101011234")
        assert "<MY_IC>" in result.text

    def test_invalid_mykad_not_redacted(self, engine):
        # Invalid state code 00
        result = engine.redact("Number 880101001234")
        assert "MY_IC" not in result.text or result.entities == []


class TestMyMobile:
    def test_mobile_with_plus60(self, engine):
        result = engine.redact("Call +60121234567")
        assert "+60121234567" not in result.text

    def test_mobile_with_zero(self, engine):
        result = engine.redact("Nombor 012-3456789")
        assert "012-3456789" not in result.text

    def test_mobile_019(self, engine):
        result = engine.redact("Phone 019-1234567")
        assert "019-1234567" not in result.text


class TestMyLandline:
    def test_kl_landline(self, engine):
        result = engine.redact("Office 03-12345678")
        assert "03-12345678" not in result.text

    def test_state_landline(self, engine):
        result = engine.redact("Call 04-1234567")
        assert "04-1234567" not in result.text


class TestMySSM:
    def test_ssm_registration(self, engine):
        result = engine.redact("SSM registration 1234567-A")
        assert "1234567-A" not in result.text


class TestMyBankAccount:
    def test_maybank_with_context(self, engine):
        result = engine.redact("Maybank account 112233445566")
        assert "112233445566" not in result.text

    def test_digits_without_context_not_matched(self, engine):
        """12 random digits without banking context should NOT be redacted as bank account."""
        result = engine.redact("Reference number 112233445566")
        # Should NOT match — no banking context words
        has_bank = any(e.type == "MY_BANK_ACCOUNT" for e in result.entities)
        assert not has_bank
```

**Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_malaysian.py -v`
Expected: FAIL

**Step 3: Write implementation**

```python
# kloak/extras/malaysian/recognizers.py
"""Malaysian PII recognizers — MyKad, phone, landline, SSM, bank accounts."""

from __future__ import annotations

from presidio_analyzer import Pattern, PatternRecognizer

from kloak.extras.malaysian.mykad import validate_mykad


class MyKadRecognizer(PatternRecognizer):
    """Malaysian IC (MyKad) recognizer with date + state code validation."""

    def __init__(self) -> None:
        patterns = [
            Pattern(
                name="mykad_with_dashes",
                regex=r"\b\d{6}-\d{2}-\d{4}\b",
                score=0.4,
            ),
            Pattern(
                name="mykad_without_dashes",
                regex=r"\b\d{12}\b",
                score=0.1,
            ),
        ]
        super().__init__(
            supported_entity="MY_IC",
            name="MyKad IC Recognizer",
            patterns=patterns,
            context=["ic", "mykad", "kad pengenalan", "nric", "identity card", "no kp"],
        )

    def validate_result(self, pattern_text: str) -> bool | None:
        return validate_mykad(pattern_text)


def _my_mobile_recognizer() -> PatternRecognizer:
    return PatternRecognizer(
        supported_entity="MY_MOBILE",
        name="Malaysian Mobile Recognizer",
        patterns=[
            Pattern(
                name="my_mobile_plus60",
                regex=r"\b\+?601[0-9]-?\d{7,8}\b",
                score=0.85,
            ),
            Pattern(
                name="my_mobile_zero",
                regex=r"\b01[0-9]-?\d{7,8}\b",
                score=0.75,
            ),
        ],
        context=["phone", "mobile", "telefon", "nombor", "call", "whatsapp"],
    )


def _my_landline_recognizer() -> PatternRecognizer:
    return PatternRecognizer(
        supported_entity="MY_LANDLINE",
        name="Malaysian Landline Recognizer",
        patterns=[
            Pattern(
                name="my_landline_plus60",
                regex=r"\b\+?60[3-9]-?\d{7,8}\b",
                score=0.7,
            ),
            Pattern(
                name="my_landline_zero",
                regex=r"\b0[3-9]-?\d{7,8}\b",
                score=0.6,
            ),
        ],
        context=["phone", "office", "landline", "telefon", "pejabat"],
    )


def _my_ssm_recognizer() -> PatternRecognizer:
    return PatternRecognizer(
        supported_entity="MY_SSM",
        name="Malaysian SSM Registration Recognizer",
        patterns=[
            Pattern(
                name="my_ssm",
                regex=r"\b\d{6,7}-[A-Z]\b",
                score=0.6,
            ),
        ],
        context=["ssm", "registration", "company", "syarikat", "pendaftaran"],
    )


def _my_bank_account_recognizer() -> PatternRecognizer:
    return PatternRecognizer(
        supported_entity="MY_BANK_ACCOUNT",
        name="Malaysian Bank Account Recognizer",
        patterns=[
            Pattern(name="maybank_12", regex=r"\b\d{12}\b", score=0.3),
            Pattern(name="cimb_10", regex=r"\b\d{10}\b", score=0.3),
            Pattern(name="cimb_rhb_14", regex=r"\b\d{14}\b", score=0.3),
            Pattern(name="hlb_11", regex=r"\b\d{11}\b", score=0.3),
            Pattern(name="ambank_13", regex=r"\b\d{13}\b", score=0.3),
            Pattern(name="pub_bank_15", regex=r"\b\d{15}\b", score=0.3),
        ],
        context=[
            "account", "akaun", "bank", "maybank", "cimb", "public bank",
            "rhb", "hong leong", "ambank", "transfer", "deposit",
        ],
    )


def get_recognizers() -> list[PatternRecognizer]:
    """Return all Malaysian PII recognizers."""
    return [
        MyKadRecognizer(),
        _my_mobile_recognizer(),
        _my_landline_recognizer(),
        _my_ssm_recognizer(),
        _my_bank_account_recognizer(),
    ]
```

```python
# kloak/extras/malaysian/__init__.py
"""Malaysian PII recognizers (kloak[my])."""

from kloak.extras.malaysian.recognizers import get_recognizers

__all__ = ["get_recognizers"]
```

```json
// kloak/extras/malaysian/test_fixtures.json
[
    {
        "input": "IC saya 880101-01-1234",
        "expected_entities": ["MY_IC"],
        "language": "en"
    },
    {
        "input": "Call me at +60121234567",
        "expected_entities": ["MY_MOBILE"],
        "language": "en"
    },
    {
        "input": "Office number 03-12345678",
        "expected_entities": ["MY_LANDLINE"],
        "language": "en"
    },
    {
        "input": "SSM registration 1234567-A",
        "expected_entities": ["MY_SSM"],
        "language": "en"
    },
    {
        "input": "Maybank account 112233445566",
        "expected_entities": ["MY_BANK_ACCOUNT"],
        "language": "en"
    }
]
```

**Step 4: Run test to verify it passes**

Run: `uv run pytest tests/test_malaysian.py -v`
Expected: PASS

Note: some tests may need pattern tuning. If `validate_result` signature differs in current Presidio version, check Presidio docs and adjust. The `validate_result` method receives the matched text and should return `True` (valid), `False` (invalid), or `None` (defer to score).

**Step 5: Commit**

```bash
git add kloak/extras/malaysian/ tests/test_malaysian.py
git commit -m "feat(extras/my): add Malaysian recognizers — MyKad, phone, landline, SSM, bank"
```

---

### Task 11: GitLeaks Cache

**Files:**
- Create: `kloak/extras/gitleaks/cache.py`
- Create: `tests/test_gitleaks.py` (cache tests only first)

**Step 1: Write the failing tests**

```python
# tests/test_gitleaks.py
import time
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

from kloak.extras.gitleaks.cache import get_toml


SAMPLE_TOML = """
title = "gitleaks config"

[[rules]]
id = "openai-api-key"
description = "OpenAI API Key"
regex = '''sk-[a-zA-Z0-9]{20,}'''
keywords = ["sk-"]

[[rules]]
id = "aws-access-key"
description = "AWS Access Key"
regex = '''AKIA[0-9A-Z]{16}'''
keywords = ["AKIA"]
"""


class TestCache:
    def test_fresh_cache_used(self, tmp_path):
        cache_file = tmp_path / "rules.toml"
        cache_file.write_text(SAMPLE_TOML)

        result = get_toml(cache_path=cache_file, refresh_hours=168)
        assert "rules" in result
        assert len(result["rules"]) == 2

    def test_stale_cache_triggers_fetch(self, tmp_path):
        cache_file = tmp_path / "rules.toml"
        cache_file.write_text(SAMPLE_TOML)
        # Make file old
        old_time = time.time() - (200 * 3600)
        import os
        os.utime(cache_file, (old_time, old_time))

        with patch("kloak.extras.gitleaks.cache._fetch_toml") as mock_fetch:
            mock_fetch.return_value = SAMPLE_TOML
            result = get_toml(cache_path=cache_file, refresh_hours=168)
            mock_fetch.assert_called_once()

    def test_fetch_failure_uses_stale_cache(self, tmp_path):
        cache_file = tmp_path / "rules.toml"
        cache_file.write_text(SAMPLE_TOML)
        old_time = time.time() - (200 * 3600)
        import os
        os.utime(cache_file, (old_time, old_time))

        with patch("kloak.extras.gitleaks.cache._fetch_toml") as mock_fetch:
            mock_fetch.side_effect = Exception("network error")
            result = get_toml(cache_path=cache_file, refresh_hours=168)
            assert len(result["rules"]) == 2  # stale cache used

    def test_no_cache_no_network_returns_empty(self, tmp_path):
        cache_file = tmp_path / "nonexistent.toml"

        with patch("kloak.extras.gitleaks.cache._fetch_toml") as mock_fetch:
            mock_fetch.side_effect = Exception("network error")
            result = get_toml(cache_path=cache_file, refresh_hours=168)
            assert result.get("rules", []) == []

    def test_corrupt_cache_falls_back_to_fetch(self, tmp_path):
        cache_file = tmp_path / "rules.toml"
        cache_file.write_text("not-valid-toml = [")

        with patch("kloak.extras.gitleaks.cache._fetch_toml") as mock_fetch:
            mock_fetch.return_value = SAMPLE_TOML
            result = get_toml(cache_path=cache_file, refresh_hours=168)
            assert len(result["rules"]) == 2
```

**Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_gitleaks.py -v`
Expected: FAIL

**Step 3: Write implementation**

```python
# kloak/extras/gitleaks/cache.py
"""GitLeaks TOML cache — fetch, store, fallback."""

from __future__ import annotations

import logging
import time
import tomllib
from pathlib import Path

from kloak.config import GITLEAKS_CACHE_PATH, GITLEAKS_URL, SECRETS_REFRESH_HOURS

logger = logging.getLogger("kloak")


def _fetch_toml(url: str) -> str:
    """Fetch GitLeaks TOML from URL."""
    import httpx

    response = httpx.get(url, timeout=30, follow_redirects=True)
    response.raise_for_status()
    return response.text


def _is_cache_fresh(cache_path: Path, refresh_hours: int) -> bool:
    if not cache_path.exists():
        return False
    age_hours = (time.time() - cache_path.stat().st_mtime) / 3600
    return age_hours < refresh_hours


def _parse_toml(raw: str, source: str) -> dict:
    try:
        return tomllib.loads(raw)
    except tomllib.TOMLDecodeError as exc:
        raise ValueError(f"Invalid TOML from {source}: {exc}") from exc


def get_toml(
    *,
    cache_path: Path = GITLEAKS_CACHE_PATH,
    refresh_hours: int = SECRETS_REFRESH_HOURS,
    url: str = GITLEAKS_URL,
) -> dict:
    """Get GitLeaks TOML config. Cache-first with resilient fallback.

    1. Cache fresh → use cached
    2. Cache stale/missing → fetch from URL → write cache
    3. Fetch fails + stale cache → use stale (log warning)
    4. Fetch fails + no cache → return empty (log error)
    """
    # Fresh cache — use it
    if _is_cache_fresh(cache_path, refresh_hours):
        try:
            return _parse_toml(cache_path.read_text(), str(cache_path))
        except ValueError as exc:
            logger.warning("Cache parse failed (%s), refreshing from source.", exc)

    # Try to fetch
    try:
        raw = _fetch_toml(url)
        cache_path.parent.mkdir(parents=True, exist_ok=True)
        cache_path.write_text(raw)
        return _parse_toml(raw, url)
    except Exception as e:
        if cache_path.exists():
            logger.warning("Failed to refresh GitLeaks rules (%s). Using stale cache.", e)
            try:
                return _parse_toml(cache_path.read_text(), str(cache_path))
            except ValueError as exc:
                logger.error("Stale cache parse failed: %s", exc)
                return {"rules": []}
        else:
            logger.error("Failed to fetch GitLeaks rules and no cache exists: %s", e)
            return {"rules": []}
```

**Step 4: Run test to verify it passes**

Run: `uv run pytest tests/test_gitleaks.py -v`
Expected: PASS (5 tests)

**Step 5: Commit**

```bash
git add kloak/extras/gitleaks/cache.py tests/test_gitleaks.py
git commit -m "feat(extras/gitleaks): add TOML cache with resilient fallback"
```

---

### Task 12: GitLeaks Loader

**Files:**
- Create: `kloak/extras/gitleaks/loader.py`
- Modify: `kloak/extras/gitleaks/__init__.py`
- Modify: `tests/test_gitleaks.py` (add loader tests)

**Step 1: Add failing tests to `tests/test_gitleaks.py`**

```python
# Append to tests/test_gitleaks.py

from kloak.extras.gitleaks.loader import load_gitleaks_recognizers


SAMPLE_TOML_DICT = {
    "rules": [
        {
            "id": "openai-api-key",
            "description": "OpenAI API Key",
            "regex": r"sk-[a-zA-Z0-9]{20,}",
            "keywords": ["sk-"],
        },
        {
            "id": "aws-access-key",
            "description": "AWS Access Key",
            "regex": r"AKIA[0-9A-Z]{16}",
            "keywords": ["AKIA"],
        },
    ],
}


class TestLoader:
    def test_load_creates_recognizers(self):
        recognizers = load_gitleaks_recognizers(SAMPLE_TOML_DICT)
        assert len(recognizers) == 2

    def test_recognizer_entity_names_uppercased(self):
        recognizers = load_gitleaks_recognizers(SAMPLE_TOML_DICT)
        entities = {r.supported_entities[0] for r in recognizers}
        assert "OPENAI_API_KEY" in entities
        assert "AWS_ACCESS_KEY" in entities

    def test_incompatible_regex_skipped(self):
        toml_data = {
            "rules": [
                {
                    "id": "good-rule",
                    "regex": r"sk-[a-zA-Z0-9]+",
                },
                {
                    "id": "bad-rule",
                    "regex": r"(?!invalid(?P<broken)",  # broken regex
                },
            ],
        }
        recognizers = load_gitleaks_recognizers(toml_data)
        assert len(recognizers) == 1

    def test_empty_rules(self):
        recognizers = load_gitleaks_recognizers({"rules": []})
        assert recognizers == []

    def test_missing_rules_key(self):
        recognizers = load_gitleaks_recognizers({})
        assert recognizers == []


class TestEndToEnd:
    def test_gitleaks_redacts_openai_key(self, tmp_path):
        import os

        os.environ["KLOAK_NLP_BACKEND"] = "regex"

        cache_file = tmp_path / "rules.toml"
        cache_file.write_text(SAMPLE_TOML)

        with patch("kloak.extras.gitleaks.cache.GITLEAKS_CACHE_PATH", cache_file), \
             patch("kloak.extras.gitleaks.cache.SECRETS_REFRESH_HOURS", 168):
            from kloak.engine import KloakEngine

            engine = KloakEngine()
            result = engine.redact("My key is sk-abcdefghijklmnopqrstuvwxyz")
            # Should detect the OpenAI key pattern
            assert "sk-abcdefghijklmnopqrstuvwxyz" not in result.text
```

**Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_gitleaks.py::TestLoader -v`
Expected: FAIL

**Step 3: Write implementation**

```python
# kloak/extras/gitleaks/loader.py
"""Parse GitLeaks TOML rules into Presidio recognizers."""

from __future__ import annotations

import logging
import re

from presidio_analyzer import Pattern, PatternRecognizer

logger = logging.getLogger("kloak")


def _normalize_entity_name(rule_id: str) -> str:
    """Convert 'openai-api-key' → 'OPENAI_API_KEY'."""
    return rule_id.replace("-", "_").upper()


def load_gitleaks_recognizers(toml_data: dict) -> list[PatternRecognizer]:
    """Convert GitLeaks TOML rules to Presidio PatternRecognizer list.

    Skips rules with incompatible regex (logs warning, never crashes).
    """
    recognizers: list[PatternRecognizer] = []

    for rule in toml_data.get("rules", []):
        rule_id = rule.get("id", "")
        regex = rule.get("regex", "")

        if not rule_id or not regex:
            continue

        # Validate regex compiles in Python
        try:
            re.compile(regex)
        except re.error:
            logger.warning("Skipping GitLeaks rule '%s': incompatible regex", rule_id)
            continue

        entity_name = _normalize_entity_name(rule_id)

        recognizers.append(
            PatternRecognizer(
                supported_entity=entity_name,
                name=rule.get("description", rule_id),
                patterns=[Pattern(name=rule_id, regex=regex, score=0.85)],
                context=rule.get("keywords", []),
            )
        )

    return recognizers
```

```python
# kloak/extras/gitleaks/__init__.py
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
```

**Step 4: Run test to verify it passes**

Run: `uv run pytest tests/test_gitleaks.py -v`
Expected: PASS (all tests)

**Step 5: Commit**

```bash
git add kloak/extras/gitleaks/ tests/test_gitleaks.py
git commit -m "feat(extras/gitleaks): add TOML parser and recognizer loader"
```

---

### Task 13: Regex-Only Mode Tests

**Files:**
- Create: `tests/test_core_regex_only.py`

**Step 1: Write the tests**

```python
# tests/test_core_regex_only.py
"""Tests that verify kloak works with zero NLP dependencies (regex-only mode)."""

import os

import pytest

from kloak.engine import KloakEngine


@pytest.fixture(autouse=True)
def force_regex_mode(monkeypatch):
    monkeypatch.setenv("KLOAK_NLP_BACKEND", "regex")


@pytest.fixture
def engine():
    return KloakEngine()


def test_backend_is_regex_only(engine):
    assert engine.backend == "regex-only"


def test_email_detected(engine):
    result = engine.redact("Contact ahmad@mail.com")
    assert "<EMAIL_ADDRESS>" in result.text


def test_credit_card_detected(engine):
    result = engine.redact("Card: 4111111111111111")
    assert "4111111111111111" not in result.text


def test_ip_address_detected(engine):
    result = engine.redact("Server: 10.0.0.1")
    assert "10.0.0.1" not in result.text


def test_url_detected(engine):
    result = engine.redact("Go to https://secret.internal.com/admin")
    assert "secret.internal.com" not in result.text


def test_no_crash_on_empty_text(engine):
    result = engine.redact("")
    assert result.text == ""
    assert result.entities == []


def test_no_crash_on_unicode(engine):
    result = engine.redact("こんにちは ahmad@mail.com 你好")
    assert "<EMAIL_ADDRESS>" in result.text


def test_no_crash_on_manglish(engine):
    """Manglish/code-switched text should not crash."""
    result = engine.redact("Eh bro, nak transfer ke akaun 112233445566 tak?")
    # May or may not detect — but must not crash
    assert isinstance(result.text, str)


def test_multiple_entities(engine):
    result = engine.redact("Email ahmad@mail.com, IP 192.168.1.1")
    assert "<EMAIL_ADDRESS>" in result.text
    assert "192.168.1.1" not in result.text
    assert len(result.entities) >= 2
```

**Step 2: Run tests**

Run: `uv run pytest tests/test_core_regex_only.py -v`
Expected: PASS (all tests)

**Step 3: Commit**

```bash
git add tests/test_core_regex_only.py
git commit -m "test: add regex-only mode tests (no spaCy dependency)"
```

---

### Task 14: CLAUDE.md

**Files:**
- Create: `CLAUDE.md`

**Step 1: Write CLAUDE.md**

```markdown
# kloak

PII + secrets redaction library for Python. Built on Microsoft Presidio. Apache 2.0.

## Architecture
- `kloak/` — flat layout, package at repo root
- `kloak/engine.py` — KloakEngine wraps Presidio AnalyzerEngine + AnonymizerEngine
- `kloak/nlp_backend.py` — auto-detects spaCy, falls back to NullNlpEngine (regex-only)
- `kloak/extras/malaysian/` — MyKad, MY phone, landline, SSM, bank account recognizers
- `kloak/extras/gitleaks/` — dynamic GitLeaks rule loading with file cache
- `tests/` — pytest, outside package

## Public API
- `kloak.redact(text)` → `RedactResult`
- `kloak.backend` → `"spacy:en_core_web_sm"` | `"regex-only"`
- `KloakEngine(language, score_threshold)` — for custom config

## Code style
- Python 3.11+, type hints on all public functions
- Linting: `ruff check . && ruff format .`
- Tests: `uv run pytest tests/ -x`
- Build: hatchling, managed with uv

## Extras
- `[my]` — Malaysian PII (regex-only, zero extra deps)
- `[gitleaks]` — secrets via GitLeaks TOML (requires httpx)
- `[nlp]` — spaCy NER for names/orgs/locations
```

**Step 2: Commit**

```bash
git add CLAUDE.md
git commit -m "docs: add minimal CLAUDE.md for Phase 1"
```

---

### Task 15: CI (GitHub Actions)

**Files:**
- Create: `.github/workflows/test.yml`

**Step 1: Write CI config**

```yaml
# .github/workflows/test.yml
name: Tests

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  test-core:
    name: Core (Python ${{ matrix.python-version }})
    runs-on: ubuntu-latest
    strategy:
      matrix:
        python-version: ["3.11", "3.12", "3.13"]
    steps:
      - uses: actions/checkout@v4
      - uses: astral-sh/setup-uv@v4
        with:
          version: "latest"
      - run: uv python install ${{ matrix.python-version }}
      - run: uv sync --extra dev --python ${{ matrix.python-version }}
      - run: uv run ruff check .
      - run: uv run ruff format --check .
      - run: uv run pytest tests/test_core.py tests/test_core_regex_only.py tests/test_include_exclude.py tests/test_types.py tests/test_api.py tests/test_nlp_backend.py -v

  test-full:
    name: Full (Python ${{ matrix.python-version }})
    runs-on: ubuntu-latest
    strategy:
      matrix:
        python-version: ["3.11", "3.12", "3.13"]
    steps:
      - uses: actions/checkout@v4
      - uses: astral-sh/setup-uv@v4
        with:
          version: "latest"
      - run: uv python install ${{ matrix.python-version }}
      - run: uv sync --extra dev --extra my --extra gitleaks --python ${{ matrix.python-version }}
      - run: uv run pytest tests/ -v --cov=kloak --cov-report=term-missing
```

**Step 2: Commit**

```bash
mkdir -p .github/workflows
git add .github/workflows/test.yml
git commit -m "ci: add GitHub Actions test matrix (core + full, Python 3.11-3.13)"
```

---

### Task 16: Lint & Final Verification

**Step 1: Run ruff**

```bash
uv run ruff check . --fix
uv run ruff format .
```

**Step 2: Run full test suite**

```bash
uv run pytest tests/ -v --tb=short
```

Expected: ALL PASS

**Step 3: Fix any issues, then commit**

```bash
git add -u
git commit -m "chore: lint and format"
```

---

### Task 17: Update README

**Files:**
- Modify: `README.md`

**Step 1: Write README with quickstart**

```markdown
# kloak

> Kloak your data before it touches AI. Local-first PII & secrets redaction for Python.

[![Tests](https://github.com/klovr/kloak/actions/workflows/test.yml/badge.svg)](https://github.com/klovr/kloak/actions)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-Apache%202.0-green.svg)](LICENSE)

## Quickstart

```bash
pip install kloak
```

```python
import kloak

result = kloak.redact("Email me at ahmad@mail.com")
print(result.text)
# → 'Email me at <EMAIL_ADDRESS>'
```

```python
# With gitleaks extra installed
result = kloak.redact("key is sk-proj-abc123xyz")
print(result.text)
# → 'key is <OPENAI_API_KEY>'
```

## Install what you need

```bash
pip install kloak                # Core (regex-only, zero NLP deps)
pip install kloak[nlp]           # + spaCy NER (name/org/location detection)
pip install kloak[my]            # + Malaysian recognizers (MyKad, phones, bank accounts)
pip install kloak[gitleaks]      # + GitLeaks API key detection
```

## Local-first

All redaction runs locally on your machine. Core mode makes zero network calls. Optional `gitleaks` mode may refresh rule definitions from the configured URL; input text is still processed locally.

## License

Apache 2.0
```

**Step 2: Commit**

```bash
git add README.md
git commit -m "docs: update README with quickstart and install options"
```
