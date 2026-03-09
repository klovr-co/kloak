# kloak

PII + secrets redaction library for Python. Built on Microsoft Presidio. Apache 2.0.

## Architecture
- `kloak/` — flat layout, package at repo root
- `kloak/engine.py` — KloakEngine wraps Presidio AnalyzerEngine + AnonymizerEngine
- `kloak/nlp_backend.py` — auto-detects spaCy, falls back to NullNlpEngine (regex-only)
- `kloak/extras/malaysian/` — MyKad, MY phone, landline, SSM, bank account recognizers
- `kloak/extras/gitleaks/` — dynamic GitLeaks rule loading with file cache
- `kloak/integrations/langchain.py` — KloakAnonymizer (DocumentTransformer) + KloakLangSmith (trace masking) + KloakMiddleware (agent middleware)
- `tests/` — pytest, outside package; core tests flat, extras tests in `tests/extras/<name>/`

## Public API
- `kloak.redact(text)` → `RedactResult`
- `kloak.backend` → `"spacy:en_core_web_sm"` | `"regex-only"`
- `KloakEngine(language, score_threshold)` — for custom config

## Code style
- Python 3.11+, type hints on all public functions
- Linting: `ruff check . && ruff format .` (format auto-fixes; CI uses `--check`)
- Tests: `uv run pytest tests/ -x`
- Build: hatchling, managed with uv

## Extras
- `[malaysian]` — Malaysian PII (regex-only, zero extra deps)
- `[gitleaks]` — secrets via GitLeaks TOML (requires httpx)
- `[nlp]` — spaCy NER for names/orgs/locations
- `[langchain]` — LangChain DocumentTransformer + LangSmith trace masking + agent middleware (requires langchain>=0.3)

**Every extra must have a matching example in `examples/<extra-name>.py`.**
Current: `examples/malaysian.py`, `examples/gitleaks.py`, `examples/langchain_integration.py`
Note: the langchain example is named `langchain_integration.py` (not `langchain.py`) to avoid
shadowing the `langchain` PyPI package when Python adds `examples/` to `sys.path`.

**Every extra must have tests under `tests/extras/<extra-name>/`.**
Current: `tests/extras/malaysian/`, `tests/extras/gitleaks/`, `tests/extras/langchain/`
