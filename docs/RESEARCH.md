# Requirements: `kloak`

Kloak your data before it touches AI. Local-first PII + secrets redaction that runs entirely on your machine — nothing leaves your infrastructure, ever.

Built on Microsoft Presidio with a modular extras system. Apache 2.0. pip-installable.

---

## Design Philosophy: Local-First, Always

Kloak exists because the moment you send text to an LLM API, you've lost control of it. Training data opt-outs, privacy policies, DPAs — none of that matters if the data shouldn't have left your infra in the first place.

**The kloak principle:** redact locally, *then* send to AI. Not the other way around.

This means:
- **All processing happens on your machine.** Kloak is a Python library, not a SaaS. No API keys to manage. No third-party servers. `pip install kloak` and everything runs in your process
- **No network calls in the core package.** The only extra that makes a network call is `[gitleaks]` (to fetch the GitLeaks rules TOML), and even that caches locally and works offline after first fetch
- **No telemetry, no phone-home, no usage tracking.** Zero outbound connections. You can run kloak in an air-gapped environment
- **Input text never touches disk.** Kloak processes in memory and returns results. The only thing written to disk is the compliance audit log (opt-in, entity types + counts only, never original values)
- **NLP models run locally.** When you install `kloak[nlp]`, spaCy runs on your CPU. No cloud NER endpoints. No "send text to detect PII" irony (looking at you, LlamaIndex `PIINodePostprocessor`)
- **Token maps stay with you.** Kloak gives you the map, you store it however you want. We don't manage it, we don't see it, we don't sync it anywhere

**What this enables:**
- Healthcare / finance teams that can't send patient or client data to any external service — kloak runs inside their VPC
- Malaysian companies under PDPA that need to prove data never left Malaysian jurisdiction
- Developers using Claude/GPT/Gemini APIs who want to strip PII *before* it hits the API, not rely on the provider's privacy policy
- Air-gapped / on-prem deployments where internet access is restricted or nonexistent
- CI pipelines that scan for leaked secrets without sending code to external services

**What local-first is NOT:**
- It doesn't mean kloak is a server. It's a library. You import it and call `redact()`. No Docker, no microservice (though you can wrap it in FastAPI if you want — that's documented separately)
- It doesn't mean kloak replaces your LLM provider's data policies. It means you send them less sensitive data in the first place
- It doesn't mean kloak does end-to-end encryption or secure enclaves. It strips data pre-flight. Encryption in transit to the LLM is your transport layer's job

---

## Package Install Targets

```bash
pip install kloak                              # Core (regex-only, zero NLP deps)
pip install kloak[nlp]                         # + spaCy NER (name/org/location detection)
pip install kloak[my]                          # + Malaysian recognizers + PDPA preset
pip install kloak[whatsapp]                    # + WhatsApp message parsing
pip install kloak[gitleaks]                     # + Dynamic GitLeaks API key detection
pip install kloak[compliance]                  # + Audit logging + compliance reports
pip install kloak[my,whatsapp]                 # Klovr internal stack
pip install kloak[nlp,my,whatsapp,gitleaks,compliance]  # Full enterprise
```

---

## NLP Backend Strategy

### Tiered NLP support

The core package (`pip install kloak`) ships with **zero NLP dependencies**. It uses regex-based recognizers only — catches emails, phones, credit cards, IPs, URLs, IBANs, and all pattern-matchable PII. This gives users a <10 second install and instant gratification.

For name/org/location detection (NER), users install the `[nlp]` extra:

```bash
pip install kloak[nlp]       # Installs spaCy + en_core_web_sm (~12MB)
```

**NLP backend options (all via Presidio's NLP engine interface):**

| Backend | Install | Model Size | Accuracy | Use Case |
|---------|---------|-----------|----------|----------|
| None (regex-only) | `pip install kloak` | 0 MB | Structured PII only | Quick eval, secrets-only, CI pipelines |
| spaCy `sm` (default) | `pip install kloak[nlp]` | ~12 MB | Good | Most users — names, orgs, locations |
| spaCy `lg` | Manual: `python -m spacy download en_core_web_lg` | ~500 MB | Better | High-accuracy production |

**Auto-detection:** On import, kloak checks what's available and uses the best backend found. If no NLP backend is installed, it runs in regex-only mode and logs an info message (not a warning — this is a valid operating mode).

```python
import kloak

# Regex-only mode (no spaCy installed)
result = kloak.redact("My name is Ahmad, email ahmad@mail.com, key sk-abc123")
# → "My name is Ahmad, email <EMAIL_ADDRESS>, key <OPENAI_API_KEY>"
# Note: "Ahmad" not caught — no NER available

# With spaCy installed
result = kloak.redact("My name is Ahmad, email ahmad@mail.com, key sk-abc123")
# → "My name is <PERSON>, email <EMAIL_ADDRESS>, key <OPENAI_API_KEY>"
```

---

## Package Structure

```
kloak/
├── core/                        # pip install kloak
│   ├── __init__.py
│   ├── redactor.py              # Main redact() / tokenize() interface
│   ├── tokenizer.py             # Tokenization + de-anonymization
│   ├── presidio_engine.py       # Presidio analyzer + anonymizer setup
│   ├── nlp_backend.py           # Auto-detect and load NLP backend (spaCy/none)
│   ├── registry.py              # Plugin registry — auto-discover and load extras
│   └── config.py                # Base config, env vars

├── extras/
│   ├── _base.py                 # KloakPlugin base class — all plugins inherit from this
│   ├── _template/               # Cookiecutter-style template for new plugins
│   │   ├── __init__.py.tpl
│   │   ├── recognizers.py.tpl
│   │   ├── tests.py.tpl
│   │   └── PLUGIN_GUIDE.md      # Step-by-step: "How to build a kloak plugin"
│   │
│   ├── malaysian/               # pip install kloak[my]
│   │   ├── __init__.py          # Exports plugin class + entity list
│   │   ├── recognizers.py       # MyKad, MY phone, MY bank accounts, SSM reg
│   │   ├── pdpa.py              # PDPA preset — one flag enables all MY-required entities
│   │   └── test_fixtures.json   # Sample texts + expected redactions for validation
│   │
│   ├── whatsapp/                # pip install kloak[whatsapp]
│   │   ├── __init__.py
│   │   ├── parser.py            # Strip timestamps, forwarded labels, system messages
│   │   └── recognizers.py       # WA-specific: contact cards, location shares, WA links
│   │
│   ├── gitleaks/                # pip install kloak[gitleaks]
│   │   ├── __init__.py
│   │   ├── gitleaks_loader.py   # Fetch + parse GitLeaks TOML → Presidio recognizers
│   │   └── cache.py             # Local file cache + refresh logic
│   │
│   └── compliance/              # pip install kloak[compliance]
│       ├── __init__.py
│       ├── audit_log.py         # Log entity types + counts only, never values
│       └── report.py            # Batch compliance summary report

├── integrations/                # Framework integrations
│   ├── langchain.py             # KloakTransformer, KloakRedact, KloakDeanonymize, KloakCallbackHandler
│   ├── llamaindex.py            # Phase 4 — KloakNodePostprocessor (deferred)
│   └── precommit.py             # Pre-commit hook entry point

├── cli/                         # Developer tools
│   ├── scaffold.py              # `kloak new-plugin sg` → generates plugin from template
│   └── validate.py              # `kloak validate extras/singaporean/` → runs plugin checks

├── tests/
│   ├── test_core.py
│   ├── test_core_regex_only.py  # Tests that pass WITHOUT spaCy installed
│   ├── test_malaysian.py
│   ├── test_whatsapp.py
│   ├── test_gitleaks.py
│   ├── test_compliance.py
│   └── test_plugin_contract.py  # Validates any plugin against the base contract

├── CLAUDE.md                    # Claude Code project context (at repo root per convention)
├── .claude/
│   └── commands/
│       ├── new-plugin.md        # /new-plugin — scaffold a regional plugin
│       ├── add-recognizer.md    # /add-recognizer — add entity to existing plugin
│       └── prep-pr.md           # /prep-pr — lint, test, format, generate PR description

├── AGENTS.md                    # Universal AI agent context (Cursor, Copilot, Windsurf, Cline, Aider)
├── pyproject.toml
├── README.md
├── CONTRIBUTING.md
└── .pre-commit-hooks.yaml       # Pre-commit hook definition
```

---

## Build Phases

The build order is dictated by Klovr's own stack needs first, then growth:

| Phase | What | Why | Target |
|-------|------|-----|--------|
| **Phase 1** | Core + `[my]` + `[gitleaks]` | Klovr needs MY PII + secrets. Core proves the DX. GitLeaks is the "wow" differentiator | Week 1–3 |
| **Phase 2** | `[whatsapp]` + LangChain integration | Klovr's WhatsApp pipeline. LangChain = biggest ecosystem, #1 growth lever | Week 4–5 |
| **Phase 3** | Plugin system + AGENTS.md + CLI scaffolding | Opens the contribution flywheel. AI agent friendliness is the moat | Week 6–7 |
| **Phase 4** | Pre-commit + GitHub Action + LlamaIndex (if demand) | Expands discovery surfaces. DevSecOps crowd | Week 8+ |
| **Phase 5** | `[compliance]` + other framework integrations | Only when enterprise prospects ask for it | When needed |

---

## Functional Requirements

### FR1 — Core (`kloak`) · Phase 1

- `redact(text, language="en") -> RedactResult` — irreversible anonymization
- `tokenize(text, session_id, language="en") -> TokenizeResult` — reversible, returns token map
- `deanonymize(text, token_map) -> str` — restore original values from token map
- Redacted placeholders formatted as `<ENTITY_TYPE>` e.g. `<PERSON>`, `<EMAIL_ADDRESS>`
- Tokenized placeholders formatted as `ENTITY_TYPE_001` e.g. `PERSON_001`, `EMAIL_001`
- **Session consistency:** same entity value always maps to the same token within a `session_id`. "Ahmad" → `PERSON_001` in message 1, message 5, and message 50. This allows LLMs to reason about entity relationships across a conversation without seeing real PII
- **Token map merging:** multiple `tokenize()` calls with the same `session_id` produce a cumulative `token_map`. Caller can merge maps across calls or retrieve the full session map
- Return detected entities with type, character position, confidence score
- **Regex-only mode (no NLP deps):** email, phone, credit card (Luhn validated), IBAN, IP address, URL, date patterns, SSN patterns
- **With NLP backend:** adds names, orgs, locations, date of birth, passport via spaCy NER
- Auto-detect available NLP backend on import — no user config needed
- Configurable confidence threshold per entity type
- `exclude: List[str]` param — skip specific entity types per call (e.g. `exclude=["PERSON", "EMAIL_ADDRESS"]`)
- `include: List[str]` param — only redact specified entity types, ignore everything else
- `include` takes priority over `exclude` if both are passed
- Both params work on `redact()`, `tokenize()`, and at engine init level for persistent config
- Graceful degradation on Manglish / code-switched text — never raises on unexpected input

### FR2 — Malaysian Extra (`kloak[my]`) · Phase 1

Custom `PatternRecognizer` objects for:
- MyKad IC: `\d{6}-\d{2}-\d{4}`
- Malaysian mobile: `(\+?60|0)[1][0-9]-?\d{7,8}`
- Malaysian landline: `(\+?60|0)[3-9]\d{7,8}`
- SSM company registration: `\d{6,7}-[A-Z]`
- Malaysian bank account numbers (Maybank, CIMB, Public Bank formats)

PDPA preset (`mode="pdpa"`):
- Enables all MY recognizers + name + phone + email + IC + bank account
- Single flag to be compliant with Malaysian Personal Data Protection Act 2010
- Returns a `pdpa_entities_found` summary in result

### FR3 — WhatsApp Extra (`kloak[whatsapp]`) · Phase 2

Pre-processing layer before redaction:
- Strip WhatsApp timestamp prefixes: `[DD/MM/YYYY, HH:MM:SS]`
- Strip forwarded message labels: `Forwarded many times`, `Forwarded`
- Strip system messages: `Messages and calls are end-to-end encrypted`, `<name> added <name>`
- Strip WhatsApp Web export headers
- Handle contact card blocks (vCard format embedded in chat exports)
- Handle location share messages: `Location: https://maps.google.com/?q=...`
- Expose `parse_whatsapp(raw_text) -> ParsedChat` with messages as structured objects before passing to redactor

### FR4 — GitLeaks Extra (`kloak[gitleaks]`) · Phase 1

Dynamic GitLeaks rule loading:
- On first use, fetch GitLeaks TOML from:
  `https://raw.githubusercontent.com/gitleaks/gitleaks/main/config/gitleaks.toml`
- Parse all `[[rules]]` entries → register as Presidio `PatternRecognizer`
- Skip rules with incompatible regex (log warning, continue)
- Cache to local file at configurable path (default: `~/.kloak/gitleaks_rules.toml`)
- Auto-refresh if cache is older than `KLOAK_SECRETS_REFRESH_HOURS` (default: 168h / weekly)
- Fetch failure must not crash — fall back to cached rules, log warning
- If no cache exists and fetch fails, continue with empty secrets ruleset, log error

Must cover at minimum:
- AWS Access Key (`AKIA...`)
- OpenAI API key (`sk-...`)
- Google API key (`AIza...`)
- GitHub tokens (`gh[pousr]_...`)
- PEM private keys (`-----BEGIN ... PRIVATE KEY-----`)
- Stripe keys (`sk_live_...`, `pk_live_...`)
- Twilio tokens
- Generic high-entropy strings (entropy threshold configurable via `KLOAK_ENTROPY_THRESHOLD`)

### FR5 — Compliance Extra (`kloak[compliance]`) · Phase 5

> **Ship when needed.** Not until an enterprise prospect asks for it.

Audit logging:
- Log entity types + counts per redaction call — never log original values
- Structured JSON log format: `{ timestamp, session_id, entity_counts: { PERSON: 2, PHONE: 1 } }`
- Pluggable log sink: file, stdout, or custom handler

Compliance report:
- `generate_report(results: List[RedactResult]) -> ComplianceReport`
- Summarises: total texts processed, entity type breakdown, top entity types, date range
- Output formats: JSON, Markdown, plain text
- Designed for audit trail submission

### FR6 — Plugin System · Phase 3

Plugin registration and discovery:
- All extras (regional, gitleaks, whatsapp, compliance) implement `KloakPlugin` base class
- Plugins register via Python entry points (`kloak.plugins` group in `pyproject.toml`)
- `core/registry.py` auto-discovers all installed plugins on import — no manual registration
- Third-party plugins (e.g. `pip install kloak-plugin-brazil`) auto-register on install
- Failed plugin loads log a warning and continue — never crash the core

Plugin base contract (`extras/_base.py`):
- `plugin_name: str` — short identifier (e.g. `"my"`, `"sg"`)
- `supported_entities: List[str]` — entity types this plugin adds
- `get_recognizers() -> List[EntityRecognizer]` — return Presidio recognizer instances
- `get_presets() -> dict` — optional named presets (e.g. `{"pdpa": [...]}`)
- `get_test_fixtures() -> List[dict]` — optional test cases for validation

Plugin CLI tools:
- `kloak new-plugin <code>` — scaffold a new plugin from template with stubs
- `kloak validate <path>` — check plugin meets contract (class, entities, recognizers, tests)
- `kloak list-plugins` — show all installed plugins and their entities

Plugin template (`extras/_template/`):
- Cookiecutter-style templates for `__init__.py`, `recognizers.py`, `test_fixtures.json`
- `PLUGIN_GUIDE.md` — step-by-step guide for building a plugin
- Template generates working code that passes `kloak validate` out of the box (with stub patterns)

### FR7 — Framework Integrations · Phase 2 (LangChain), Phase 4 (rest)

#### LangChain Integration · Phase 2

This is the primary framework integration. Kloak plugs into LangChain at three levels:

**1. DocumentTransformer — redact documents before indexing or retrieval**

```python
from kloak.integrations.langchain import KloakTransformer

# Mode: redact (irreversible, for indexing/storage)
transformer = KloakTransformer(mode="redact")
clean_docs = transformer.transform_documents(documents)
# All PII stripped from documents before they hit your vector store

# Mode: tokenize (reversible, for query-time redaction)
transformer = KloakTransformer(mode="tokenize", session_id="query-001")
tokenized_docs = transformer.transform_documents(documents)
# Documents have PERSON_001 etc. — token map stored on transformer instance
```

**2. Runnable — drop into any LCEL chain**

```python
from kloak.integrations.langchain import KloakRedact, KloakDeanonymize
from langchain_openai import ChatOpenAI
from langchain_core.prompts import ChatPromptTemplate

llm = ChatOpenAI(model="gpt-4")
prompt = ChatPromptTemplate.from_template("Summarise this: {text}")

# Full chain: kloak strips PII → LLM processes clean text → kloak restores names
chain = (
    KloakRedact(mode="tokenize")      # Step 1: tokenize PII locally
    | prompt
    | llm                              # Step 2: LLM sees PERSON_001, not Ahmad
    | KloakDeanonymize()               # Step 3: swap real names back in
)

result = chain.invoke({"text": "Ahmad called Siti about the Bangsar unit"})
# LLM never saw "Ahmad" or "Siti" — but the final output has real names
```

**3. Callback handler — redact all LLM inputs transparently**

```python
from kloak.integrations.langchain import KloakCallbackHandler

# Attach to any LLM — automatically redacts all inputs before they leave
handler = KloakCallbackHandler(mode="redact")
llm = ChatOpenAI(model="gpt-4", callbacks=[handler])

# Every prompt sent through this LLM instance gets kloaked automatically
# No changes to your existing chains needed
```

**What this fills that LangChain's built-in Presidio wrapper doesn't:**
- `mode="redact"` → simple `<PERSON>` placeholders. LangChain's `PresidioAnonymizer` only does faker-based replacement (GitHub issue #14328)
- `mode="tokenize"` → reversible `PERSON_001` tokens with deanonymize step. LangChain's `PresidioReversibleAnonymizer` exists but doesn't support redaction mode
- Secrets detection via `[gitleaks]` — not available in any LangChain privacy integration
- Regional PII via `[my]` — MyKad, Malaysian phones, PDPA preset. Not available anywhere in LangChain
- `include` / `exclude` entity filtering per call — more granular than LangChain's `analyzed_fields`
- Local-first, zero network calls — unlike OpaquePrompts integration which sends data to a third party

**LangChain integration implementation notes:**
- `KloakTransformer` implements `BaseDocumentTransformer` — works with any LangChain retrieval pipeline
- `KloakRedact` and `KloakDeanonymize` implement `Runnable` — composable in LCEL chains
- `KloakCallbackHandler` implements `BaseCallbackHandler` — transparent redaction on any LLM
- Token maps are stored in-memory on the runnable instance. For multi-turn conversations, pass `session_id` to maintain consistency across calls
- Target: submit to `langchain-community` package after v0.1 release

#### LlamaIndex Integration · Phase 4

> **Deferred.** Build after LangChain integration is stable. Will be a `NodePostprocessor` following the same patterns. LlamaIndex already has a basic Presidio postprocessor — kloak's version will add secrets, regional PII, and redact mode.

#### Pre-commit Hook · Phase 4

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/klovr/kloak
    rev: v0.1.0
    hooks:
      - id: kloak-secrets
        name: Scan for secrets
        entry: kloak-scan
        language: python
        types: [text]
```

Scans staged files for API keys, tokens, and secrets. Zero NLP deps required — uses regex-only mode for speed. Outputs file, line number, and entity type. Non-zero exit on findings.

#### GitHub Action · Phase 4

```yaml
# .github/workflows/kloak.yml
- uses: klovr/kloak-action@v1
  with:
    scan-mode: secrets        # or 'pii' or 'all'
    fail-on-findings: true
```

Wraps the pre-commit hook logic for CI. Published to GitHub Actions Marketplace.

---

## API / Interface

### Core usage

**Two modes:** `redact()` strips PII permanently. `tokenize()` replaces PII with consistent tokens so you can swap originals back in after the LLM responds.

```python
import kloak

# ── Mode 1: Redact (irreversible) ──────────────────────────────
# Use when you don't need the original values back
result = kloak.redact("My name is Ahmad, call me at 012-3456789")
# result.redacted_text → "My name is <PERSON>, call me at <MY_PHONE>"
# result.entities → [{ type: "PERSON", start: 11, end: 16, score: 0.85 }, ...]

# ── Mode 2: Tokenize + Deanonymize (reversible) ────────────────
# Use when the LLM response needs real names/values restored
result = kloak.tokenize("My name is Ahmad", session_id="abc123")
# result.redacted_text → "My name is PERSON_001"
# result.token_map → { "PERSON_001": "Ahmad" }

# Send tokenized text to LLM...
llm_response = call_llm(result.redacted_text)
# LLM says: "Follow up with PERSON_001 about their inquiry"

# Swap real names back in
restored = kloak.deanonymize(llm_response, result.token_map)
# → "Follow up with Ahmad about their inquiry"
```

### The full LLM pipeline flow

This is the core use case — redact before sending to AI, restore after:

```python
import kloak

# Step 1: Tokenize (local, nothing leaves your machine)
result = kloak.tokenize(
    "Ahmad called Siti about the Bangsar unit. His IC is 880101-01-1234.",
    session_id="deal-789"
)
# LLM will see: "PERSON_001 called PERSON_002 about the Bangsar unit.
#                His IC is MY_IC_001."
# Token map:    { "PERSON_001": "Ahmad", "PERSON_002": "Siti",
#                 "MY_IC_001": "880101-01-1234" }

# Step 2: Send clean text to LLM (no PII leaves your infra)
llm_response = openai.chat.completions.create(
    model="gpt-4",
    messages=[{"role": "user", "content": result.redacted_text}]
)

# Step 3: Deanonymize (local, swap originals back in)
final = kloak.deanonymize(llm_response.choices[0].message.content, result.token_map)
# If LLM said: "PERSON_001 should follow up with PERSON_002 about the unit."
# You get:     "Ahmad should follow up with Siti about the unit."
```

### Session consistency (same person = same token across messages)

When processing a conversation (e.g. a WhatsApp thread), the same entity always maps to the same token within a session. The LLM sees a coherent conversation — it knows PERSON_001 and PERSON_002 are distinct people — without ever seeing real names.

```python
# Message 1
r1 = kloak.tokenize("Ahmad: Hey, is the unit still available?", session_id="chat-456")
# → "PERSON_001: Hey, is the unit still available?"

# Message 5
r2 = kloak.tokenize("Siti: Yes! Ahmad can view tomorrow at 3pm", session_id="chat-456")
# → "PERSON_002: Yes! PERSON_001 can view tomorrow at 3pm"

# Message 12
r3 = kloak.tokenize("Ahmad: Great, I'll bring my wife Fatimah", session_id="chat-456")
# → "PERSON_001: Great, I'll bring my wife PERSON_003"

# Ahmad = PERSON_001 everywhere. Siti = PERSON_002 everywhere.
# The LLM can reason about relationships without seeing real names.

# Combined token map across all messages:
# { "PERSON_001": "Ahmad", "PERSON_002": "Siti", "PERSON_003": "Fatimah" }
```

> **Note:** Name detection requires `pip install kloak[nlp]` (spaCy NER). The regex-only core catches structured PII (phones, ICs, emails, API keys) but can't detect that "Ahmad" is a person's name.

### Filtering — control what gets redacted

```python
# Exclude specific entity types
result = kloak.redact(
    "My name is Ahmad, email me at ahmad@gmail.com, key is sk-abc123",
    exclude=["PERSON", "EMAIL_ADDRESS"]
)
# → "My name is Ahmad, email me at ahmad@gmail.com, key is <OPENAI_API_KEY>"

# Whitelist — only redact what you specify
result = kloak.redact(text, include=["OPENAI_API_KEY", "AWS_ACCESS_KEY"])

# include takes priority if both are passed
# Works on tokenize() too
result = kloak.tokenize(text, session_id="abc123", exclude=["PERSON"])

# Check what mode you're running in
print(kloak.backend)  # "spacy:en_core_web_sm" / "spacy:en_core_web_lg" / "regex-only"
```

### Entity filtering at engine level

```python
# Set once, applies to all calls on that engine instance
engine = MalaysianEngine(
    mode="pdpa",
    exclude=["PERSON", "EMAIL_ADDRESS"]
)
```

### With extras

```python
# Malaysian + WhatsApp
from kloak.extras.whatsapp import parse_whatsapp
from kloak.extras.malaysian import MalaysianEngine

chat = parse_whatsapp(raw_export)
engine = MalaysianEngine(mode="pdpa")
for message in chat.messages:
    result = engine.redact(message.text)

# Secrets
from kloak.extras.gitleaks import SecretsEngine
engine = SecretsEngine()  # loads GitLeaks rules on init
result = engine.redact("my openai key is sk-abc123...")

# Compliance
from kloak.extras.compliance import AuditLogger, generate_report
logger = AuditLogger(sink="file", path="/var/log/kloak/audit.jsonl")
results = [logger.redact(text) for text in texts]
report = generate_report(results)
```

---

## Non-Functional Requirements

### NFR1 — Performance
- Core redact (regex-only) p95 < 50ms for texts up to 2,000 chars
- Core redact (with NLP) p95 < 200ms for texts up to 2,000 chars
- Core redact (with NLP) p95 < 500ms for texts up to 10,000 chars
- GitLeaks rule load on startup < 3s (cached path)
- Pre-commit hook: < 2s per file scan

### NFR2 — System Requirements

Kloak runs on anything from a Raspberry Pi (regex-only) to a production server (full NLP). The install tier determines what you need:

| Install | Disk | RAM (idle) | RAM (processing) | CPU | GPU | Notes |
|---------|------|------------|-----------------|-----|-----|-------|
| `pip install kloak` | ~50 MB | ~30 MB | ~50 MB | Any | No | Regex-only. Runs anywhere Python runs. CI runners, lambdas, Raspberry Pi, air-gapped servers |
| `pip install kloak[my]` | ~50 MB | ~30 MB | ~50 MB | Any | No | Same as core — MY recognizers are just regex patterns, zero additional overhead |
| `pip install kloak[gitleaks]` | ~55 MB + ~2 MB cache | ~35 MB | ~60 MB | Any | No | Adds httpx. First run fetches GitLeaks TOML (~2 MB), then works offline |
| `pip install kloak[whatsapp]` | ~50 MB | ~30 MB | ~50 MB | Any | No | Same as core — parser is pure Python string processing |
| `pip install kloak[nlp]` | ~200 MB | ~200 MB | ~300–400 MB | 2+ cores recommended | No | spaCy `en_core_web_sm` loads ~150 MB into memory. This is where name/org/location detection lives |
| `kloak[nlp]` with `en_core_web_lg` | ~700 MB | ~600 MB | ~800 MB–1 GB | 2+ cores recommended | No | Manually installed large model. Better accuracy, much heavier |

**Practical guidance by deployment scenario:**

**CI pipeline / pre-commit hook (secrets + structured PII only)**
- `pip install kloak[gitleaks]`
- 512 MB RAM, 1 vCPU, no GPU
- GitHub Actions free tier works fine
- First run needs internet (to fetch GitLeaks TOML), then cache is reused

**Developer laptop (full PII + name detection)**
- `pip install kloak[nlp,my,gitleaks]`
- 1 GB free RAM, any modern laptop
- spaCy `en_core_web_sm` loads in ~2s, stays in memory
- MacBook Air M1 / any i5+ handles this easily

**Production API (high throughput)**
- `pip install kloak[nlp,my,gitleaks,whatsapp]`
- 2 GB+ RAM, 2+ vCPUs
- If wrapping in FastAPI: use spaCy's `Language.memory_zone` to control memory growth over time
- For >100 requests/sec: consider multiple workers with pre-loaded models
- spaCy's memory can grow slowly under sustained load due to internal vocab caching — monitor and restart workers periodically, or use `memory_zone` context manager

**Air-gapped / restricted environment**
- `pip install kloak` (regex-only) — zero internet required at any point
- Or pre-cache the GitLeaks TOML and spaCy model on a machine with internet, then transfer to the air-gapped system
- Set `KLOAK_GITLEAKS_CACHE_PATH` to point to the pre-cached file

**Raspberry Pi / edge device**
- `pip install kloak` (regex-only) — ~50 MB disk, ~50 MB RAM
- Don't try to run spaCy on a Pi — it'll work but be painfully slow
- Regex-only mode catches emails, phones, ICs, API keys, which covers most edge use cases

### NFR3 — Dependencies (keep core light)
- **Core (regex-only):** `presidio-analyzer`, `presidio-anonymizer` — NO spaCy, NO NLP models
- **`[nlp]`:** `spacy`, `en_core_web_sm` (~12MB)
- `[my]`: no additional deps beyond core
- `[whatsapp]`: no additional deps beyond core
- `[gitleaks]`: `httpx`, `tomllib` (stdlib 3.11+)
- `[compliance]`: no additional deps beyond core

### NFR4 — Compatibility
- Python 3.11+
- Works standalone (no server required) — pure library mode
- Optional FastAPI wrapper for microservice deployment (documented separately)

### NFR5 — Privacy (Local-First Guarantees)
- **Zero network calls in core.** The core package and all extras except `[gitleaks]` make no outbound network requests, ever
- **`[gitleaks]` network behavior:** single HTTPS GET to fetch GitLeaks TOML on first use. Caches locally. Works fully offline after first fetch. Fetch failure falls back to cache or continues with empty ruleset — never blocks
- No telemetry, no phone-home, no usage tracking, no analytics
- Input text is never written to disk by core package — all processing in memory
- Token maps are returned to caller, never persisted by kloak
- Audit logger (compliance extra) only writes entity types + counts, never original values
- Can run in air-gapped environments with zero internet access (regex-only mode + cached gitleaks rules)

### NFR6 — Open Source
- Apache 2.0 license
- CONTRIBUTING.md with guide for adding new regional recognizer packs (e.g. `kloak[sg]`, `kloak[id]`)
- Each extras module is independently testable and contributable

### NFR7 — AI Coding Agent Friendliness

The entire codebase should be optimized for AI coding agents (Claude Code, Cursor, Copilot, Windsurf, Cline, Aider) to read, understand, modify, and extend. This is a first-class design constraint, not an afterthought.

**Project context files:**
- `CLAUDE.md` at repo root — Claude Code reads this automatically on every session. Contains architecture overview, plugin contract, code style, PR checklist, commit conventions
- `AGENTS.md` at repo root — identical project context for all other AI agents
- Both follow skill-creator progressive disclosure: metadata → core instructions → reference material. Under 500 lines each
- `.claude/commands/` — Claude Code slash commands for `/new-plugin`, `/add-recognizer`, `/prep-pr`

**Code patterns that help AI agents:**
- **Explicit type hints** on all public functions — agents use these to infer correct usage
- **Docstrings with examples** on all public classes — agents copy-paste from these into generated code
- **Single-file plugins** — each plugin is self-contained in one directory, no cross-module dependencies. An agent can read one directory and understand everything
- **JSON test fixtures** — structured, machine-readable test cases (not hardcoded strings in test files). Agents can generate new fixtures in the same format
- **Strict naming conventions** — entity types are always `UPPER_SNAKE`, plugin names are always lowercase short codes, file names are predictable. Agents don't have to guess
- **Entry points for registration** — plugins auto-register, so an agent generating a new plugin only needs to add one line to `pyproject.toml`, not modify core code
- **`kloak validate`** — deterministic pass/fail check that an agent can run to verify its own output before committing

**What this enables:**
- A contributor can say "add Thailand support" to any AI coding agent and get a working, PR-ready plugin
- An agent can read `CLAUDE.md` / `AGENTS.md` + one existing plugin directory and generate a new plugin without asking follow-up questions
- The `kloak validate` CLI gives agents a ground-truth check — they can iterate until it passes
- The plugin contract (`KloakPlugin` base class) is the API boundary agents code against — it never changes without a major version bump

---

## Environment Variables

```
KLOAK_NLP_BACKEND=auto                # auto | spacy | regex
KLOAK_SPACY_MODEL=en_core_web_sm      # override spaCy model name
KLOAK_ENTROPY_THRESHOLD=3.5
KLOAK_SECRETS_REFRESH_HOURS=168
KLOAK_GITLEAKS_URL=https://raw.githubusercontent.com/gitleaks/gitleaks/main/config/gitleaks.toml
KLOAK_GITLEAKS_CACHE_PATH=~/.kloak/gitleaks_rules.toml
KLOAK_LOG_LEVEL=INFO
```

---

## Competitive Landscape

### Direct competitors (self-hosted, open-source PII libraries)

**LLM Guard** (Protect AI) — 2.5k stars, MIT, Python 3.10+
- Broadest scope: 15 input scanners + 20 output scanners (prompt injection, toxicity, PII, secrets, banned topics)
- PII anonymization uses Presidio + BERT NER under the hood
- Has a "Vault" for reversible anonymization and faker-based replacement
- Secrets scanner exists but is basic — no GitLeaks integration, no dynamic rule updates
- No regional PII support. No chat/messaging pre-processing
- Positioning: security suite (35 scanners). Heavy for teams that just need PII/secrets redaction
- **kloak angle:** "LLM Guard is a security suite. kloak is a redaction library. If you just need to strip PII and secrets, you don't need 35 scanners."

**LangChain `langchain_experimental.data_anonymizer`** — built-in
- `PresidioAnonymizer` (irreversible) and `PresidioReversibleAnonymizer` (with deanonymize + mapping save/load)
- Thin wrapper around raw Presidio — no secrets, no regional PII, no pre-processing
- **Does not support simple redaction** (`<PERSON>` style) — open GitHub issue #14328 requesting exactly this
- Only supports anonymization (replace with fake data via Faker)
- **kloak angle:** Build a `DocumentTransformer` that does what their wrapper can't — redaction, secrets, regional PII

**LlamaIndex PII postprocessors** — built-in
- `PIINodePostprocessor` (uses an LLM to find PII — ironic), `NERPIINodePostprocessor` (HuggingFace NER)
- `llama-index-postprocessor-presidio` added after a Presidio maintainer filed a feature request
- Basic Presidio wrapper. No secrets, no regional, no chat pre-processing
- **kloak angle:** Build a `NodePostprocessor` with secrets + regional support. Fill the gap Presidio's own maintainer identified

**anonLLM** — small project, pip-installable
- Anonymizes names, emails, phones with country-specific formats. Reversible
- Thin, limited entity types, no secrets, no compliance, no framework integrations
- Not a serious threat but proves the "simple pip-installable PII tool" market exists

**Guardrails AI `guardrails_pii`** — plugin
- Combines Presidio + GLiNER for detection. Runs as a validator within Guardrails ecosystem
- Locked into Guardrails framework — not standalone
- **kloak angle:** Standalone library that works everywhere, not just inside one framework

### Cloud / SaaS services (different category)

**OpaquePrompts** — SaaS, LangChain integration
- Privacy layer between data and LLM using confidential computing
- Not configurable — all-or-nothing PII masking, can't choose entity types
- English only. API key takes weeks to get. Still sends PII to a third party (theirs instead of the LLM's)
- **kloak angle:** Self-hosted, configurable, include/exclude per entity type, no third-party data sharing

**AWS Comprehend / Google Cloud DLP** — cloud APIs
- Powerful, high accuracy, many entity types
- Closed-source, no transparency into detection logic, requires sending data to cloud provider
- Can be regulatory violations for healthcare/finance (data sovereignty)
- **kloak angle:** Self-hosted, open-source, auditable, no data leaves your infra

**Private AI** — SaaS/on-prem, commercial
- ML-based PII detection, confidential computing, LangChain integration
- Enterprise pricing, not open-source
- **kloak angle:** Apache 2.0, free, community-driven

### Infrastructure-layer tools (complementary, not competitive)

**LiteLLM** — LLM proxy with Presidio callback for PII masking at gateway level
**Kong AI Gateway** — API gateway with PII sanitization plugin
These operate at different layers (proxy/gateway vs application). kloak could integrate with both as the detection engine.

### Gap analysis — what nobody does

| Capability | LLM Guard | LangChain Presidio | LlamaIndex | OpaquePrompts | kloak |
|---|---|---|---|---|---|
| Simple `redact()` → `<ENTITY>` | Via scanner config | **No** (open issue) | Via Presidio postprocessor | No (replaces with fake) | **Yes — core API** |
| Reversible tokenize + deanonymize | Vault system | Yes (reversible anonymizer) | Yes (mapping in metadata) | Yes | **Yes — core API** |
| Secrets (API keys, tokens) | Basic scanner | No | No | No | **Yes — GitLeaks dynamic rules** |
| Regional PII (MyKad, PDPA, etc.) | No | No | No | No | **Yes — extras system** |
| Chat/WhatsApp pre-processing | No | No | No | No | **Yes — whatsapp extra** |
| Zero-NLP regex-only mode | No (requires models) | No (requires spaCy) | No (requires NER model) | N/A (SaaS) | **Yes — core install** |
| Pre-commit hook | No | No | No | No | **Yes** |
| `include`/`exclude` entity filtering | Per-scanner config | `analyzed_fields` list | Limited | No (all-or-nothing) | **Yes — per-call or engine-level** |
| Local-first, zero network calls | Mostly (downloads models) | Mostly (downloads spaCy) | Mostly (downloads models) | **No** (SaaS) | **Yes — core makes zero outbound requests** |
| Air-gap compatible | No | No | No | No | **Yes (regex-only + cached rules)** |
| pip install → working in <10 seconds | No (~500MB+ deps) | No (spaCy required) | No (models required) | N/A | **Yes (regex-only core)** |

### Positioning statement

> **Kloak your data before it touches AI.**
> 
> For developers building LLM pipelines: kloak is the PII + secrets redaction library that works out of the box. Unlike LLM Guard (a 35-scanner security suite), kloak does one thing well: strip sensitive data from text before it hits a model. Unlike LangChain's built-in Presidio wrapper (which doesn't even support simple redaction), kloak gives you `redact()`, `tokenize()`, and `deanonymize()` in three lines. Unlike cloud APIs (AWS Comprehend, Google DLP), your data never leaves your infrastructure.
>
> `pip install kloak`. Kloak it. Send it. Done.

---

## Distribution & Growth Strategy

### README Structure (critical for star velocity)

The README is the #1 conversion surface. Structure it for maximum "star within 30 seconds" probability:

```
1. Hero section
   - One-line value prop: "Kloak your data before it touches AI. PII + secrets redaction. Self-hosted. pip install. Done."
   - Animated GIF showing: raw text → kloak.redact() → clean output (terminal recording via asciinema/vhs)
   - Badges: PyPI version, Python 3.11+, Apache 2.0, tests passing, downloads

2. 10-second quickstart
   pip install kloak
   >>> import kloak
   >>> kloak.redact("My API key is sk-abc123 and email is max@klovr.co")
   'My API key is <OPENAI_API_KEY> and email is <EMAIL_ADDRESS>'

3. Why kloak?
   - **Local-first:** zero network calls, zero telemetry, runs in your process.
     Your text never leaves your machine. Not to kloak, not to anyone
   - Comparison table: kloak vs LLM Guard vs LangChain Presidio vs cloud APIs
   - Position as: "local-first redaction library" not "security suite"
   - Key differentiators: local-first, instant install (zero NLP deps), secrets via GitLeaks,
     regional PII extras, include/exclude filtering, air-gap compatible
   - Honest about what kloak doesn't do: prompt injection, toxicity, content moderation,
     business context redaction, real-time audio, token map storage

4. Install what you need (extras table)

5. Framework integrations (LangChain — DocumentTransformer, LCEL Runnable, Callback Handler)

6. Full API reference (collapsible)

7. Contributing — "Add your country" regional pack template

8. Comparison with alternatives (expanded, for people who scroll)
   - vs LLM Guard: "security suite vs redaction library"
   - vs LangChain Presidio wrapper: "kloak does redaction, secrets, and regional PII — they don't"
   - vs AWS Comprehend / Google DLP: "self-hosted, no data leaves your infra"
   - vs OpaquePrompts: "self-hosted, configurable, no third-party data sharing"
```

**README rules:**
- First code example must work with `pip install kloak` only (regex mode) — no spaCy required
- GIF must show real terminal output, not mockup
- Comparison table must be honest — show what kloak doesn't do (business context redaction, real-time audio)

### Hero GIF / Terminal Recording

Create using [VHS](https://github.com/charmbracelet/vhs) or [asciinema](https://asciinema.org):

```
# Script for VHS tape file
Type "pip install kloak"
Enter
Sleep 3
Type "python"
Enter
Type 'import kloak'
Enter
Type 'kloak.redact("Email me at ahmad@mail.com, key is sk-proj-abc123xyz")'
Enter
Sleep 2
# Shows: 'Email me at <EMAIL_ADDRESS>, key is <OPENAI_API_KEY>'
```

The GIF should be under 5 seconds of "wow" — install → import → redact → done.

### Launch Playbook

#### Pre-launch (1 week before)
- [ ] PyPI package published and installable
- [ ] README with GIF, quickstart, comparison table
- [ ] LangChain integration working (DocumentTransformer + LCEL Runnable)
- [ ] Pre-commit hook working
- [ ] 3-5 beta testers have used it and given feedback
- [ ] Blog post draft: "Why we built kloak" (technical, not marketing)

#### Launch day targets (pick 2-3, don't spam all at once)
- **Hacker News:** "Show HN: kloak — kloak your data before it touches AI. pip-installable PII + secrets redaction"
  - Post at 9am EST Tuesday/Wednesday (peak HN traffic)
  - Title should include "Show HN" + concrete value prop
  - First comment: technical context on why you built it, link to blog post
- **Reddit:** r/Python, r/MachineLearning, r/LocalLLaMA, r/SelfHosted
  - r/Python: focus on clean API design and DX
  - r/LocalLLaMA: focus on "redact before sending to any LLM"
  - r/SelfHosted: focus on "no data leaves your infra"
  - Tailor framing per subreddit — same tool, different angle
- **Twitter/X:** Thread showing the GIF + "built this to solve our own problem at Klovr"
- **Dev.to / Hashnode:** Cross-post the blog

#### Post-launch (week 1-4)
- Submit PR to LangChain community integrations (gets you into their docs — this is the #1 post-launch priority)
- Answer StackOverflow questions about PII redaction in LangChain → link to kloak
- Post in LangChain Discord channels
- Write "How to redact PII in your LangChain RAG pipeline" tutorial (SEO play)
- Submit to awesome-lists: `awesome-privacy`, `awesome-python`, `awesome-langchain`, `awesome-security`

#### Timing (news cycle alignment)
- Launch near any AI privacy news (data breach, regulation announcement, GDPR fine)
- If a major LLM provider has a data incident, that's your launch window
- PDPA enforcement actions in Malaysia = perfect for [my] extra visibility

### Ecosystem Integration Strategy

The fastest path to organic stars is being **inside other popular tools' ecosystems**, not competing with them.

**Priority 1 — LangChain (160k+ stars) — THIS IS THE MAIN INTEGRATION**

LangChain is where kloak's growth strategy lives. Three integration surfaces:

1. **`DocumentTransformer`** — plugs into any retrieval pipeline. Submit to `langchain-community` package
2. **LCEL `Runnable`** — `KloakRedact | prompt | llm | KloakDeanonymize` as a composable chain step
3. **`CallbackHandler`** — transparent redaction on any LLM instance, zero code changes to existing chains

**Specific gaps kloak fills in LangChain's ecosystem:**
- LangChain's `PresidioAnonymizer` lives in `langchain_experimental` and does NOT support simple redaction — GitHub issue #14328. It only does faker-based replacement. Kloak offers `mode="redact"` (→ `<PERSON>`) and `mode="tokenize"` (→ `PERSON_001`, reversible)
- No secrets detection anywhere in LangChain's privacy integrations — kloak's `[gitleaks]` is the only option
- No regional PII in LangChain — kloak's `[my]` adds MyKad, Malaysian phones, PDPA preset
- No `include`/`exclude` entity filtering — kloak offers per-call and engine-level filtering
- LangChain's `OpaquePrompts` integration sends data to a third-party SaaS — kloak is local-first

**Launch plan for LangChain:**
- Pre-launch: working integration with tests, documented in kloak README
- Week 1: submit PR to `langchain-community` with all three integration surfaces
- Week 2: write "How to redact PII in your LangChain RAG pipeline" tutorial
- Week 3: post in LangChain Discord, answer SO questions about PII in LangChain
- Goal: appear in LangChain's docs under "Privacy & Safety" alongside (and eventually replacing) the `PresidioAnonymizer`

**Priority 2 — Pre-commit / CI (DevSecOps crowd)**
- Pre-commit hook for secrets scanning
- GitHub Action on the marketplace
- **Specific positioning:** sit alongside `detect-secrets` (Yelp, 3.7k stars) and `trufflehog` (Truffle Security, 18k stars) but with PII detection added — they only do secrets, kloak does secrets + PII
- Goal: show up in `awesome-security` lists and CI/CD guides

**Priority 3 — LiteLLM / AI Gateways**
- LiteLLM already has a Presidio callback — kloak could be an alternative engine with secrets + regional PII
- Kong AI Gateway just launched PII sanitization — kloak could be the detection backend
- These are complementary relationships, not competitive

**Future — LlamaIndex, CrewAI, AutoGen**
- LlamaIndex `NodePostprocessor` after LangChain integration is stable
- Agent framework middleware once the agent ecosystem consolidates
- Not worth building until Phase 4+

### Plugin Architecture

The entire extras system is built on a single base class. Every plugin — regional, messaging, secrets — follows the same contract. This makes it trivial for Claude Code (or any AI coding agent) to generate a working plugin from a natural language description.

#### Base plugin contract

```python
# kloak/extras/_base.py

from abc import ABC, abstractmethod
from typing import List
from presidio_analyzer import PatternRecognizer, EntityRecognizer

class KloakPlugin(ABC):
    """Base class for all kloak plugins."""

    @property
    @abstractmethod
    def plugin_name(self) -> str:
        """Short identifier, e.g. 'my', 'sg', 'id'."""
        ...

    @property
    @abstractmethod
    def supported_entities(self) -> List[str]:
        """Entity types this plugin adds, e.g. ['MY_IC', 'MY_PHONE']."""
        ...

    @abstractmethod
    def get_recognizers(self) -> List[EntityRecognizer]:
        """Return list of Presidio recognizer instances."""
        ...

    def get_presets(self) -> dict:
        """Optional named presets, e.g. {'pdpa': [...entity_types]}."""
        return {}

    def get_test_fixtures(self) -> List[dict]:
        """Return test cases: [{'input': '...', 'expected_entities': [...]}]."""
        return []
```

#### How plugins register

Plugins register via Python entry points in `pyproject.toml`. When kloak loads, `core/registry.py` auto-discovers all installed plugins — no manual import needed:

```toml
# In a plugin's pyproject.toml (or kloak's own for built-in extras)
[project.entry-points."kloak.plugins"]
my = "kloak.extras.malaysian:MalaysianPlugin"
sg = "kloak.extras.singaporean:SingaporeanPlugin"
gitleaks = "kloak.extras.gitleaks:GitLeaksPlugin"
```

```python
# core/registry.py
from importlib.metadata import entry_points

def discover_plugins():
    """Auto-discover all installed kloak plugins."""
    plugins = {}
    for ep in entry_points(group="kloak.plugins"):
        try:
            plugin_cls = ep.load()
            plugin = plugin_cls()
            plugins[plugin.plugin_name] = plugin
        except Exception as e:
            logger.warning(f"Failed to load plugin {ep.name}: {e}")
    return plugins
```

This means third-party plugins work too — anyone can publish `kloak-plugin-brazil` to PyPI and it auto-registers on install.

#### Plugin scaffolding CLI

```bash
# Generate a new regional plugin from template
kloak new-plugin sg --country "Singapore" --entities "NRIC,FIN,SG_PHONE,UEN"

# Output:
# Created kloak/extras/singaporean/
# ├── __init__.py          ← Plugin class with metadata
# ├── recognizers.py       ← Empty recognizer stubs for NRIC, FIN, SG_PHONE, UEN
# ├── test_fixtures.json   ← Empty fixture file with schema
# └── tests/
#     └── test_singaporean.py  ← Test skeleton that runs fixtures

# Validate a plugin meets the contract
kloak validate extras/singaporean/

# Output:
# ✓ Plugin class found: SingaporeanPlugin
# ✓ Inherits from KloakPlugin
# ✓ supported_entities: ['NRIC', 'FIN', 'SG_PHONE', 'UEN']
# ✓ get_recognizers() returns 4 recognizers
# ✓ All test fixtures pass
# ✓ Ready for PR
```

#### Plugin template (what gets generated)

```python
# kloak/extras/singaporean/__init__.py (generated)

from kloak.extras._base import KloakPlugin
from .recognizers import get_recognizers

class SingaporeanPlugin(KloakPlugin):
    plugin_name = "sg"
    supported_entities = ["NRIC", "FIN", "SG_PHONE", "UEN"]

    def get_recognizers(self):
        return get_recognizers()

    def get_presets(self):
        return {
            "pdpa": self.supported_entities  # Singapore PDPA compliance
        }
```

```python
# kloak/extras/singaporean/recognizers.py (generated with stubs)

from presidio_analyzer import Pattern, PatternRecognizer

def get_recognizers():
    return [
        PatternRecognizer(
            supported_entity="NRIC",
            name="Singapore NRIC Recognizer",
            patterns=[
                Pattern(
                    name="sg_nric",
                    regex=r"[STFGM]\d{7}[A-Z]",
                    score=0.85
                )
            ],
            context=["nric", "ic", "identity", "identification"]
        ),
        # ... stubs for FIN, SG_PHONE, UEN
    ]
```

```json
// kloak/extras/singaporean/test_fixtures.json (generated)
[
    {
        "input": "My NRIC is S1234567D and phone is +65 9123 4567",
        "expected_entities": ["NRIC", "SG_PHONE"],
        "language": "en"
    },
    {
        "input": "Company UEN: 201912345K",
        "expected_entities": ["UEN"],
        "language": "en"
    }
]
```

### AI-Assisted Contribution Workflow (Claude Code / Cursor / Copilot)

The plugin architecture is deliberately designed so an AI coding agent can generate a complete, PR-ready plugin from a single prompt. This is the contribution flywheel.

#### AGENTS.md — universal AI agent context

The repo ships with both `AGENTS.md` and `CLAUDE.md` at the root. `AGENTS.md` is the universal entry point for any AI coding agent (Cursor, Copilot, Windsurf, Cline, Aider, etc.). `CLAUDE.md` is the Claude Code-specific entry point — it includes the same project context plus pointers to Claude Code slash commands in `.claude/commands/`.

```markdown
# kloak — AGENTS.md

> Claude Code users: see also `CLAUDE.md` at project root for
> slash commands in `.claude/commands/`.

## What this project is
PII + secrets redaction library for Python. Built on Microsoft Presidio
with a modular plugin system. Apache 2.0. pip-installable.

## Architecture
- `core/` — main redact/tokenize/deanonymize API
- `extras/` — plugins that add recognizers (regional PII, secrets, chat parsing)
- `extras/_base.py` — `KloakPlugin` base class. All plugins inherit from this
- `core/registry.py` — auto-discovers plugins via Python entry points
- Plugins register in `pyproject.toml` under `[project.entry-points."kloak.plugins"]`

## How to add a new regional plugin
1. Run `kloak new-plugin <code>` or copy `extras/_template/`
2. Implement recognizers as Presidio `PatternRecognizer` objects in `recognizers.py`
3. Add test fixtures in `test_fixtures.json`
4. Add entry point to `pyproject.toml`
5. Run `kloak validate extras/<name>/` to check contract
6. Run `pytest tests/ -x` to verify nothing breaks

## Plugin contract (extras/_base.py)
Every plugin must:
- Inherit from `KloakPlugin`
- Define `plugin_name: str` (e.g. "sg")
- Define `supported_entities: List[str]` (e.g. ["NRIC", "SG_PHONE"])
- Implement `get_recognizers() -> List[EntityRecognizer]`
- Optionally implement `get_presets()` and `get_test_fixtures()`

## Recognizer patterns — how to build them
Each recognizer is a Presidio `PatternRecognizer` with:
- `supported_entity`: uppercase entity name (e.g. "NRIC")
- `patterns`: list of `Pattern(name, regex, score)` — score 0.0–1.0
- `context`: list of context words that boost confidence (e.g. ["nric", "ic number"])

Common PII types by country:
- National ID: usually alphanumeric, fixed length, sometimes check digit
- Phone numbers: country code + carrier prefix + subscriber number
- Tax IDs: alphanumeric, country-specific format
- Bank accounts: vary by country, sometimes IBAN

## Code style
- Python 3.11+
- Type hints on all public functions
- Docstrings on all public classes and methods
- Test fixtures as JSON, not hardcoded strings
- One recognizer per entity type
- Linting: `ruff check . && ruff format .`
- Tests: `pytest tests/ -x`

## PR checklist
- [ ] Plugin class inherits from KloakPlugin
- [ ] All entities listed in supported_entities
- [ ] Test fixtures cover happy path + edge cases (min 3 per entity)
- [ ] `kloak validate` passes
- [ ] Entry point added to pyproject.toml
- [ ] No new dependencies (regional plugins must be dep-free)
- [ ] `ruff check` and `ruff format` pass
- [ ] All existing tests still pass

## Commit convention
feat(extras): add <country> regional plugin
feat(extras/<code>): add <entity> recognizer
fix(extras/<code>): improve <entity> regex accuracy
docs: update README with <country> support
```

#### CLAUDE.md — Claude Code specific (project root)

`CLAUDE.md` lives at the project root (where Claude Code expects it). It contains the same project context as `AGENTS.md` plus explicit pointers to the slash commands in `.claude/commands/`:

#### Claude Code slash commands

```markdown
# .claude/commands/new-plugin.md
# Usage: /new-plugin

Generate a new kloak regional plugin. Ask me:
1. Country code (e.g. 'sg', 'id', 'th', 'ph', 'in', 'eu')
2. What PII entities to cover (national ID, phone, tax ID, bank accounts, etc.)
3. Any compliance presets (e.g. Singapore PDPA, Indonesia PDP Law, EU GDPR)

Then:
1. Run `kloak new-plugin <code>` to scaffold
2. Research the country's PII formats (ID patterns, phone formats, etc.)
3. Implement each recognizer with correct regex + context words
4. Write test fixtures with realistic (but fake) examples
5. Run `kloak validate` to verify
6. Run `pytest` to verify nothing breaks
7. Stage all files and prepare a PR description
```

```markdown
# .claude/commands/add-recognizer.md
# Usage: /add-recognizer

Add a new entity recognizer to an existing plugin. Ask me:
1. Which plugin (e.g. 'my', 'sg')
2. What entity to detect (e.g. 'MY_PASSPORT', 'SG_DRIVING_LICENSE')
3. Known format/pattern if available

Then:
1. Add the PatternRecognizer to the plugin's recognizers.py
2. Add the entity to supported_entities in __init__.py
3. Add test fixtures
4. Run `kloak validate` + `pytest`
```

```markdown
# .claude/commands/prep-pr.md
# Usage: /prep-pr

Prepare the current branch for a pull request:
1. Run `ruff check --fix .` and `ruff format .`
2. Run `kloak validate extras/<current-plugin>/`
3. Run `pytest tests/ -x`
4. Generate a PR description from the diff:
   - Title: "feat(extras): add <country> regional plugin"
   - Body: entities covered, regex patterns used, test coverage, compliance presets
5. Create a conventional commit
6. Push branch and output the PR creation command
```

#### Example: contributor uses Claude Code to add Singapore plugin

```
Human: I want to contribute a Singapore PII plugin to kloak.
       Singapore has NRIC (S/T/F/G + 7 digits + letter),
       FIN (same format), phone numbers (+65),
       and UEN (company registration).

Claude Code:
> Running: kloak new-plugin sg --country "Singapore" --entities "NRIC,FIN,SG_PHONE,UEN"
> Created extras/singaporean/ with scaffolding

> Implementing recognizers...
> - NRIC: [STFGM]\d{7}[A-Z] with Luhn-like check digit validation
> - FIN: same pattern, differentiated by prefix (F/G/M)
> - SG_PHONE: (\+?65)?[689]\d{7}
> - UEN: \d{8,9}[A-Z] (old format) | T\d{2}[A-Z]{2}\d{4}[A-Z] (new format)

> Writing test fixtures with realistic fake data...
> Running: kloak validate extras/singaporean/
> ✓ All checks pass

> Running: pytest tests/ -x
> ✓ 47 tests passed

> Preparing PR...
> Branch: feat/extras-sg
> Title: feat(extras): add Singapore regional plugin (NRIC, FIN, phone, UEN)
> Ready to push. Run: gh pr create --fill
```

Total time: ~3 minutes. Zero prior knowledge of the codebase required.

#### Why this matters for growth

- **Lowest-friction OSS contribution possible**: an AI agent does the scaffolding, regex research, test writing, and PR prep. Contributor just provides domain knowledge ("Singapore NRIC format is...")
- **Every country is a potential contributor**: there are 195 countries × ~4 PII types each = ~780 recognizers that could exist. Each is a small, self-contained PR
- **Each new plugin is a launch moment**: "kloak now supports Singapore! Thanks @contributor" → tweet, changelog, regional tech community pickup
- **AI agents as first-class contributors**: `AGENTS.md` at the repo root gives any AI coding agent (Claude Code, Cursor, Copilot, Windsurf, Cline, Aider) full project context. Claude Code gets bonus slash commands via `.claude/commands/`. Any agent can generate a complete plugin without human handholding
- **Plugin marketplace potential**: once there are 10+ regional plugins, the "kloak supports X countries" becomes a moat. No competitor has this

### Contribution Flywheel

The regional extras system (`kloak[my]`, `kloak[sg]`, `kloak[id]`, `kloak[eu]`) is designed to attract contributors globally:

- Each region is an independent, self-contained module
- Low barrier: just regex patterns + a test file
- AI-assisted: Claude Code / Cursor can generate a complete plugin from a description
- `kloak new-plugin` CLI scaffolds everything — contributor fills in regex patterns
- `kloak validate` checks plugin contract before PR
- CONTRIBUTING.md has a "Add your country" template with step-by-step
- Recognise contributors prominently in README ("Regional packs by...")
- Each new regional pack is a mini-launch moment (tweet, changelog, regional community)

### Implementation Note: Build Agent Workflows as Skills

The Claude Code slash commands (`/new-plugin`, `/add-recognizer`, `/prep-pr`) and `CLAUDE.md` project context should be built and validated using the **skill-creator** framework (see `/mnt/skills/examples/skill-creator/SKILL.md`). This means:

- **Treat each slash command as a skill** — with a clear trigger description, structured workflow steps, and expected output format
- **Write test prompts** for each command: e.g. "I want to add a Singapore NRIC recognizer", "Generate a Thailand plugin with national ID and phone", "Prep my current branch for PR"
- **Run evals** — use the skill-creator's eval loop to verify that Claude Code actually produces working, contract-compliant plugins from natural language prompts. Test against `kloak validate` as the ground truth
- **Optimize trigger descriptions** — use the skill-creator's description optimization loop (`run_loop.py`) to make sure the slash commands trigger reliably on the right user inputs
- **The AGENTS.md and CLAUDE.md files are themselves skills** — they should follow the skill-creator's progressive disclosure pattern: metadata (what this project is) → core instructions (how to add a plugin) → reference material (regex patterns, code style, PR checklist). Keep the main body under 500 lines, link to deeper references
- **Plugin template (`extras/_template/`) is a skill artifact** — it should be validated by generating plugins from it across multiple countries and verifying they pass the contract

This ensures the AI-assisted contribution workflow isn't just documented — it's tested and tuned for reliability. A contributor saying "add Indonesia support" to Claude Code should produce a working PR 9 times out of 10, not 5 out of 10.

---

## What Kloak Does NOT Do

Being clear about boundaries is as important as being clear about features. Kloak does one thing well — local PII + secrets redaction — and explicitly does NOT do the following:

### Not a security suite
- **No prompt injection detection.** Kloak doesn't scan for adversarial prompts. Use LLM Guard, Lakera, or NeMo Guardrails for that
- **No toxicity filtering.** Kloak doesn't judge content. It strips PII and secrets, full stop
- **No content moderation.** Kloak won't block harmful, abusive, or off-topic content
- **No output scanning.** Kloak runs pre-flight (before text goes to the LLM). It doesn't scan what the LLM returns. If you need output guards, pair kloak with a guardrails framework
- Kloak is the redaction layer, not the full security stack. It composes with security tools, doesn't replace them

### Not a SaaS / cloud service
- **No hosted API.** Kloak is a library. `pip install` and it runs in your process. There's no kloak.io endpoint to send data to
- **No accounts, API keys, or signup.** Import it and use it
- **No data collection of any kind.** Zero telemetry, zero analytics, zero usage tracking
- If you want kloak-as-a-service, wrap it in FastAPI yourself (documented separately). But the library itself will never phone home

### Not a context-aware redaction engine
- **No business-context sensitivity.** Kloak won't know that "our Q3 target is RM2M" is commercially sensitive. It detects PII patterns (names, ICs, phones, API keys), not business secrets. Policy-layer redaction is a separate concern
- **No semantic understanding of sensitivity.** Kloak uses regex + NER, not LLM-based judgment. It won't infer that "the patient in room 302" is sensitive unless it matches a PII pattern. This is deliberate — deterministic > probabilistic for a redaction layer
- **No custom "sensitive topic" detection.** If you need to block discussion of trade secrets or internal projects, that's a topic filter, not a PII redactor

### Not a real-time processing engine
- **No streaming / real-time audio redaction.** Kloak processes text in batch. It doesn't hook into voice calls, live transcription, or streaming chat
- **No video / image redaction.** Text only. For image PII, see Presidio Image Redactor

### Not a storage or key management system
- **No token map storage.** When you `tokenize()`, kloak gives you the `token_map` dict. You store it. In Redis, in a database, in a file — your choice, your responsibility. Kloak never persists maps
- **No multi-tenant session management.** You pass `session_id`, kloak namespaces the tokens. But session lifecycle, token map expiry, and access control are your app's concern
- **No encryption.** Kloak redacts (removes/replaces). It doesn't encrypt. If you need encrypted PII transit, use Presidio's encrypt operator directly or handle at the transport layer

### Not a fine-tuned multilingual NER model
- **Manglish / code-switched text gets best-effort treatment.** spaCy's English model will miss some Malay-English NER. Kloak degrades gracefully (never crashes), but don't expect perfect name detection on "Eh Ahmad nak jumpa kat mana?"
- **A fine-tuned Malaysian NER model is a separate future extra** (`kloak[my-nlp]`), not part of the current scope. The `[my]` extra uses regex patterns for structured PII (IC, phone, bank accounts) which works reliably regardless of language

### The line is clear

Kloak's job is: **text in → PII and secrets stripped → clean text out.** Everything before (how you collect the text) and everything after (how you send it to the LLM, what the LLM does with it, how you handle the response) is not kloak's concern.

```
Your app → [kloak.redact()] → Clean text → LLM API → Response
              ↑                                          ↑
         Kloak's job                              Not kloak's job
```
