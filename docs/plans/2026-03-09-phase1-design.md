# Phase 1.0 Design — Core + [my] + [gitleaks]

## Scope

Phase 1.0 delivers `kloak.redact()` with Malaysian PII and GitLeaks secrets detection. Tokenization (`tokenize()` + `deanonymize()`) deferred to Phase 1.1.

**Deliverables:**
- Core `redact()` API with `include`/`exclude` filtering
- NLP auto-detection (spaCy if available, regex-only fallback)
- Malaysian recognizers (shipped in core package, also exposed as `kloak[my]` marker extra)
- `kloak[gitleaks]` — dynamic GitLeaks rule loading with resilient caching
- CI on GitHub Actions (Python 3.11/3.12/3.13 × core/full)
- Minimal CLAUDE.md

---

## Architecture

### Layout

Flat layout following presidio/httpx/pydantic conventions:

```
kloak/
├── __init__.py          # Public API: redact(), backend — explicit imports + __all__
├── engine.py            # KloakEngine class
├── nlp_backend.py       # Auto-detect spaCy → NullNlpEngine fallback
├── null_nlp.py          # NullNlpEngine stub for regex-only mode
├── config.py            # Env vars, defaults
├── types.py             # RedactResult, EntityMatch dataclasses
├── extras/
│   ├── __init__.py
│   ├── malaysian/
│   │   ├── __init__.py
│   │   ├── recognizers.py      # MyKad, MY phone, landline, SSM, bank accounts
│   │   ├── mykad.py            # MyKad validator (date + state codes)
│   │   └── test_fixtures.json
│   └── gitleaks/
│       ├── __init__.py
│       ├── loader.py           # Fetch + parse TOML → recognizers
│       └── cache.py            # File cache + refresh logic

tests/
├── conftest.py
├── test_core.py
├── test_core_regex_only.py
├── test_malaysian.py
├── test_mykad_validation.py
├── test_gitleaks.py
└── test_include_exclude.py

pyproject.toml
CLAUDE.md
README.md
LICENSE
```

### Two-layer design

```
User code              kloak public API           Presidio internals
─────────              ────────────────           ──────────────────
kloak.redact(text) ──→ KloakEngine                AnalyzerEngine
                       ├─ auto-detects NLP        ├─ NullNlpEngine (regex-only)
                       ├─ loads extras             │  OR SpacyNlpEngine
                       ├─ builds operators         ├─ RecognizerRegistry
                       └─ returns RedactResult     │  ├─ built-in regex recognizers
                                                   │  ├─ [my] recognizers
                                                   │  └─ [gitleaks] recognizers
                                                   └─ AnonymizerEngine
                                                      └─ replace → <ENTITY_TYPE>
```

Kloak is a thin wrapper — it configures Presidio correctly, adds recognizers, and presents a clean API.

---

## Core Engine

### KloakEngine (`engine.py`)

Central class. Lazy init on first call, holds configured Presidio engines.

```python
from threading import Lock

class KloakEngine:
    def __init__(self, *, language="en", score_threshold=0.35):
        self._analyzer: AnalyzerEngine | None = None
        self._anonymizer: AnonymizerEngine | None = None
        self._language = language
        self._score_threshold = score_threshold
        self._backend: str | None = None
        self._init_lock = Lock()

    def _ensure_initialized(self):
        """Lazy init — build Presidio engines on first use."""
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

    def redact(self, text, *, include=None, exclude=None) -> RedactResult:
        self._ensure_initialized()
        entities = self._resolve_entities(include, exclude)
        analyzer_results = self._analyzer.analyze(
            text=text, language=self._language,
            entities=entities, score_threshold=self._score_threshold,
        )
        anonymizer_result = self._anonymizer.anonymize(
            text=text, analyzer_results=analyzer_results,
        )
        return RedactResult(
            text=anonymizer_result.text,
            entities=[EntityMatch.from_presidio(r) for r in analyzer_results],
        )
```

### include / exclude logic

- `include=["EMAIL_ADDRESS", "MY_IC"]` → only detect those types
- `exclude=["PERSON"]` → detect everything except PERSON
- Both passed → `include` wins
- `None` for both → detect all registered entities
- Unknown entity names in `include`/`exclude` raise `ValueError` (fail-safe, no silent typo no-op)

### Lazy init rationale

spaCy model load takes ~2s. Users who import kloak but don't call `redact()` shouldn't pay that cost.

---

## NLP Backend Auto-Detection (`nlp_backend.py`)

```python
def detect_backend() -> tuple[NlpEngine, str]:
    # KLOAK_NLP_BACKEND values:
    # - regex: force regex-only
    # - spacy: force spaCy, raise RuntimeError if unavailable
    # - auto: prefer spaCy, fallback to regex-only
    # Model order: KLOAK_SPACY_MODEL override, else en_core_web_lg -> en_core_web_sm
```

- Info log, not warning — regex-only is first-class
- Prefers `lg` over `sm` if both installed
- `KLOAK_NLP_BACKEND=regex` forces regex-only even if spaCy installed
- `KLOAK_NLP_BACKEND=spacy` is strict mode and must fail loudly if spaCy/model is unavailable
- `KLOAK_NLP_BACKEND=auto` never crashes and gracefully falls back to regex-only

### NullNlpEngine (`null_nlp.py`)

Minimal `NlpEngine` stub: returns empty `NlpArtifacts`, no NER entities. Presidio has no built-in null engine, so we provide one.

---

## Types (`types.py`)

```python
@dataclass(frozen=True)
class EntityMatch:
    type: str      # "EMAIL_ADDRESS", "MY_IC", "OPENAI_API_KEY"
    start: int     # char offset in original text
    end: int       # char offset in original text
    score: float   # 0.0–1.0 confidence

@dataclass(frozen=True)
class RedactResult:
    text: str                    # "My email is <EMAIL_ADDRESS>"
    entities: list[EntityMatch]  # positions reference original text
```

Frozen dataclasses — immutable, hashable, stdlib only.

---

## Malaysian Extra (`kloak[my]`)

### Recognizers

| Entity | Pattern | Validation | Base Score |
|--------|---------|------------|------------|
| `MY_IC` | `\d{6}-?\d{2}-?\d{4}` | Date (YYMMDD) + 58 valid state codes | 0.4 → 0.85 on validation |
| `MY_MOBILE` | `(\+?60\|0)1[0-9]-?\d{7,8}` | prefix check | 0.85 |
| `MY_LANDLINE` | `(\+?60\|0)[3-9]-?\d{7,8}` | area code check | 0.7 |
| `MY_SSM` | `\d{6,7}-[A-Z]` | — | 0.6 (context boosts) |
| `MY_BANK_ACCOUNT` | Multiple patterns per bank | digit length | 0.3 (context-gated) |

### MyKad validator (`mykad.py`)

Custom `PatternRecognizer` subclass overriding `validate_result()`:

1. Strip dashes, verify 12 digits
2. Parse YYMMDD as real calendar date (leap years, month bounds)
3. Validate state code (positions 7-8) against 58 valid codes:
   - Malaysian states: 01-16, 21-59, 82
   - Foreign: 60-68, 71, 74-79, 83-93
   - Invalid: 00, 17-20, 69-70, 72-73, 80-81, 94-99
4. Regex match → score 0.4. Valid date + state → boost to 0.85

### Bank accounts — context-gated

Base score 0.3 (below default threshold 0.35). Only fires when context words present: `["account", "akaun", "bank", "maybank", "cimb", "public bank", "rhb", "hong leong", "ambank", "transfer"]`.

Bank digit lengths:
| Bank | Savings/Current | Loans/HP |
|------|----------------|----------|
| Maybank | 12 | 12 |
| CIMB | 10 or 14 | 14 |
| Public Bank | 10 | 15 |
| RHB | 14 | 12 |
| Hong Leong | 11 | 11 |
| AmBank | 13 | 14 |

### PDPA preset

Convenience shortcut, not a separate engine:
```python
kloak.redact(text, include=["MY_IC", "MY_MOBILE", "MY_LANDLINE",
                             "MY_BANK_ACCOUNT", "PERSON", "EMAIL_ADDRESS", "PHONE_NUMBER"])
```

---

## GitLeaks Extra (`kloak[gitleaks]`)

### Flow

```
First call → check cache → stale/missing? → fetch TOML → parse rules → register recognizers
                              ↓ fresh
                         use cached rules
```

### loader.py

Fetches GitLeaks TOML, parses `[[rules]]`, creates `PatternRecognizer` per rule:
- Entity type = rule `id` uppercased, dashes → underscores (e.g. `OPENAI_API_KEY`)
- Incompatible regex (Go-specific syntax) → skip with warning, never crash
- ~800 rules registered as Presidio recognizers

### cache.py — resilient fallback chain

1. Cache exists and fresh → use cached
2. Fetch succeeds → write cache, use fetched
3. Fetch fails + stale cache exists → warn, use stale
4. Fetch fails + no cache → error log, continue with empty ruleset
5. Corrupt TOML in cache/fetched content → treat as parse failure and continue fallback chain

### Dependencies

- `httpx` for fetching (modern, timeout defaults)
- `tomllib` (stdlib 3.11+) for parsing — zero extra deps

Default source should be pinned (tag or commit SHA), not a moving branch.

### Env vars

- `KLOAK_GITLEAKS_URL` — override source URL
- `KLOAK_GITLEAKS_CACHE_PATH` — default `~/.kloak/gitleaks_rules.toml`
- `KLOAK_SECRETS_REFRESH_HOURS` — default 168 (weekly)

---

## Extras Loading (Phase 1)

Hard-coded loader in `engine.py`, but only skip genuinely missing optional modules.
Do not swallow internal import/runtime bugs inside an extra.

```python
def _load_extras(self, registry):
    for module_name in ("kloak.extras.malaysian", "kloak.extras.gitleaks"):
        try:
            module = import_module(module_name)
        except ModuleNotFoundError as exc:
            # Optional module not installed -> skip quietly
            if exc.name == module_name:
                continue
            logger.exception("Extra import failed: %s", module_name)
            continue

        try:
            for recognizer in module.get_recognizers():
                registry.add_recognizer(recognizer)
        except Exception:
            logger.exception("Extra initialization failed: %s", module_name)
```

Replaced by plugin registry with entry points in Phase 3.

---

## Testing

### Test files

| Test file | Requires | Tests |
|-----------|----------|-------|
| `test_core.py` | core | `redact()` with built-in recognizers (email, phone, IP, URL, IBAN, credit card) |
| `test_core_regex_only.py` | core | Forces `KLOAK_NLP_BACKEND=regex`, verifies regex-only mode |
| `test_nlp_backend.py` | core | `auto`/`regex`/`spacy` backend mode semantics |
| `test_malaysian.py` | `[my]` | All MY recognizers — happy path + edge cases |
| `test_mykad_validation.py` | `[my]` | Exhaustive: all 58 valid state codes, all invalid codes, valid/invalid dates, with/without dashes, boundary cases |
| `test_gitleaks.py` | `[gitleaks]` | Rule loading, caching, fetch failure fallback — all network mocked |
| `test_include_exclude.py` | core | `include`/`exclude` filtering logic |

### CI (GitHub Actions)

```yaml
matrix:
  python: ["3.11", "3.12", "3.13"]
  mode: ["core", "full"]
```

- `core`: `pip install kloak` → runs `test_core` + `test_core_regex_only` + `test_include_exclude` + `test_nlp_backend`
- `full`: `pip install kloak[my,gitleaks,nlp]` → runs all tests

Two CI modes ensures the "zero NLP deps" promise is tested.

---

## Build Config (`pyproject.toml`)

- Build backend: **hatchling**
- Package manager: **uv**
- Linter/formatter: **ruff** (line-length 99)
- Test: **pytest**
- Python: **>=3.11**

### Extras

```toml
[project.optional-dependencies]
nlp = ["spacy>=3.7", "en-core-web-sm>=3.7"]
my = []                          # marker extra (recognizers ship in core package)
gitleaks = ["httpx>=0.27"]
dev = ["pytest>=8.0", "pytest-cov", "ruff"]
```

---

## CLAUDE.md (Minimal)

~30 lines. Project overview, architecture, public API, code style. No plugin system docs (Phase 3).

---

## Environment Variables

``` 
KLOAK_NLP_BACKEND=auto          # auto | spacy | regex
# spacy mode is strict (raise if unavailable), auto mode falls back to regex-only
KLOAK_SPACY_MODEL=en_core_web_sm
KLOAK_GITLEAKS_URL=<PINNED_TAG_OR_COMMIT_URL>
KLOAK_GITLEAKS_CACHE_PATH=~/.kloak/gitleaks_rules.toml
KLOAK_SECRETS_REFRESH_HOURS=168
KLOAK_LOG_LEVEL=INFO
```

---

## What Phase 1.0 does NOT include

- `tokenize()` / `deanonymize()` / session consistency → Phase 1.1
- Plugin base class / registry / entry points → Phase 3
- CLI (`kloak new-plugin`, `kloak validate`) → Phase 3
- WhatsApp parser → Phase 2
- LangChain integration → Phase 2
- Compliance / audit logging → Phase 5
- Pre-commit hook → Phase 4
