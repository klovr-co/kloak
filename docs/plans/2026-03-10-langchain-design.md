# Phase 2B Design — LangChain Integration (`kloak[langchain]`)

## Problem

LangChain users who want PII redaction today have two options:

1. **`langchain_experimental.data_anonymizer.PresidioAnonymizer`** — faker-based replacement only, requires spaCy + `en_core_web_lg`, no secrets detection, no regional PII.
2. **LangSmith trace masking** — users copy-paste ~30 lines of raw Presidio boilerplate into `Client(hide_inputs=..., hide_outputs=...)`.

Neither supports secrets detection (API keys, tokens) or regional PII (Malaysian MyKad, phone numbers). Both require manual Presidio setup.

## Solution

A new `kloak[langchain]` extra that provides two classes:

- **`KloakAnonymizer`** — `BaseDocumentTransformer` implementation, drop-in replacement for `PresidioAnonymizer`. Redacts PII in document pipelines.
- **`KloakLangSmith`** — factory that returns a LangSmith-compatible anonymizer for trace masking. One-liner setup.

## Public API

```python
from kloak.integrations.langchain import KloakAnonymizer, KloakLangSmith

# --- Surface B: Document pipeline anonymizer ---

# Auto-detects installed extras (malaysian, gitleaks, nlp)
anonymizer = KloakAnonymizer()

# Entity filtering (same as kloak.redact())
anonymizer = KloakAnonymizer(include=["PERSON", "EMAIL_ADDRESS"])
anonymizer = KloakAnonymizer(exclude=["MY_MYKAD"])

# Forward-compatible mode parameter (only "redact" supported now)
anonymizer = KloakAnonymizer(mode="redact")  # default

# Works like any LangChain DocumentTransformer
redacted_docs = anonymizer.transform_documents(documents)

# Also works as a Runnable (inherited from BaseDocumentTransformer)
chain = loader | anonymizer | vectorstore


# --- Surface A: LangSmith trace masking ---

from langsmith import Client

client = Client(anonymizer=KloakLangSmith())
client = Client(anonymizer=KloakLangSmith(include=["PERSON", "EMAIL_ADDRESS"]))
```

## Design Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Package location | `kloak[langchain]` extra | Consistent with existing extras pattern (`kloak[malaysian]`, `kloak[gitleaks]`). One repo, one CI. |
| Extras auto-detection | Auto-detect by default, override via `include`/`exclude` | Matches `KloakEngine` behavior. Install the extra, get the detection. |
| Mode parameter | `mode="redact"` now, `"tokenize"` later | Forward-compatible. Raises `ValueError` on unknown modes today. |
| Reversibility | Not in scope | Ships in a future phase with `tokenize()` + `deanonymize()` core API. |
| Faker replacement | Not in scope | Future phase. |

## Internals

### KloakAnonymizer

```python
class KloakAnonymizer(BaseDocumentTransformer):
    def __init__(self, *, mode="redact", language="en",
                 score_threshold=0.35, include=None, exclude=None):
        if mode != "redact":
            raise ValueError(f"Unsupported mode: {mode!r}. Only 'redact' is supported.")
        self._engine = KloakEngine(language=language,
                                    score_threshold=score_threshold)
        self._include = include
        self._exclude = exclude

    def transform_documents(self, documents, **kwargs):
        # Returns new Document objects with redacted page_content
        # Preserves all metadata untouched
        ...
```

- Delegates to `KloakEngine.redact()` — no new engine logic
- Returns **new** `Document` objects (immutable pattern, doesn't mutate inputs)
- Metadata is preserved as-is (only `page_content` is redacted)

### KloakLangSmith

```python
class KloakLangSmith:
    def __init__(self, *, language="en", score_threshold=0.35,
                 include=None, exclude=None):
        self._engine = KloakEngine(language=language,
                                    score_threshold=score_threshold)
        self._include = include
        self._exclude = exclude

    def __call__(self, data):
        # Walks LangSmith data dict (messages/choices format)
        # Calls engine.redact() on each content string
        # Returns modified dict
        ...
```

- Compatible with both `Client(hide_inputs=fn)` and `Client(anonymizer=fn)`
- Recursively walks nested dicts/lists to find string content
- Handles both input format (`{"messages": [...]}`) and output format (`{"choices": [{"message": ...}]}`)

## File Layout

```
kloak/integrations/__init__.py              # empty
kloak/integrations/langchain.py             # KloakAnonymizer + KloakLangSmith
examples/langchain.py                       # usage example (both surfaces)
tests/extras/langchain/test_langchain.py    # unit tests
```

## Dependencies

```toml
# pyproject.toml addition
[project.optional-dependencies]
langchain = ["langchain-core>=0.2"]
```

`langchain-core` is the minimal dependency — it provides `BaseDocumentTransformer` and `Document`. No need for `langchain` or `langchain-community`.

## Tests

All tests run in regex-only mode (no spaCy required), consistent with other extras tests.

| Test | What it verifies |
|------|-----------------|
| `test_transform_documents_redacts_pii` | Basic PII redaction through `transform_documents` |
| `test_transform_documents_preserves_metadata` | Metadata dict passes through unchanged |
| `test_include_filter` | Only specified entity types are redacted |
| `test_exclude_filter` | Specified entity types are skipped |
| `test_mode_redact_default` | Default mode is "redact" |
| `test_mode_invalid_raises` | Unknown mode raises `ValueError` |
| `test_langsmith_hide_inputs` | `KloakLangSmith` correctly walks message dicts |
| `test_langsmith_hide_outputs` | Handles LLM output format (choices/message) |
| `test_extras_auto_detection` | Malaysian/GitLeaks entities detected when extras installed |

## Example (`examples/langchain.py`)

Demonstrates both surfaces:
1. `KloakAnonymizer` transforming a list of `Document` objects
2. `KloakLangSmith` used with `Client(anonymizer=...)` for trace masking

## Not In Scope

- Reversible tokenization (`mode="tokenize"`) — future phase
- Faker-based replacement — future phase
- Streaming support — future phase
- Async `atransform_documents` — add when needed
- PR to `langchain-community` — once battle-tested
