# kloak

> Kloak your data before it touches AI.

[![Tests](https://github.com/klovr-co/kloak/actions/workflows/test.yml/badge.svg)](https://github.com/klovr-co/kloak/actions)
[![PyPI](https://img.shields.io/pypi/v/kloak.svg)](https://pypi.org/project/kloak/)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-Apache%202.0-green.svg)](LICENSE)

Local-first PII + secrets redaction for Python. Built on Microsoft Presidio. `pip install` and go — no API keys, no cloud, no data leaving your machine.

```python
import kloak

result = kloak.redact("Email me at ahmad@mail.com, my key is sk-proj-abc123xyz")
print(result.text)
# → 'Email me at <EMAIL_ADDRESS>, my key is <OPENAI_API_KEY>'
```

---

## Why kloak?

The moment you send text to an LLM API, you've lost control of it. Kloak strips PII and secrets **locally, before the API call** — not after.

| | kloak | LLM Guard | LangChain Presidio | AWS Comprehend |
|---|---|---|---|---|
| Simple `redact()` → `<ENTITY>` | ✅ core API | via scanner config | ❌ [open issue #14328](https://github.com/langchain-ai/langchain/issues/14328) | ✅ |
| Secrets (API keys, tokens) | ✅ GitLeaks rules | basic | ❌ | partial |
| Regional PII (MyKad, PDPA…) | ✅ extras system | ❌ | ❌ | ❌ |
| Zero-dep regex-only mode | ✅ `pip install kloak` | ❌ | ❌ | N/A |
| Local-first, zero network | ✅ | mostly | mostly | ❌ sends to cloud |
| Air-gap compatible | ✅ | ❌ | ❌ | ❌ |
| `pip install` → works in <10s | ✅ | ❌ (~500 MB deps) | ❌ (needs spaCy) | N/A |

---

## Install

```bash
pip install kloak                # Core — regex-only, zero NLP deps, works anywhere
pip install kloak[nlp]           # + spaCy NER (names, orgs, locations)
pip install kloak[malaysian]            # + Malaysian PII (MyKad, phones, bank accounts, SSM)
pip install kloak[gitleaks]      # + GitLeaks secrets detection (API keys, tokens)
pip install kloak[nlp,malaysian,gitleaks]  # Full stack
```

The core install is ~50 MB, no NLP models, no compilation. Catches emails, phones, credit cards, IPs, IBANs, URLs, and more via regex.

---

## Usage

### Redact (irreversible)

```python
import kloak

result = kloak.redact("My IC is 880101-01-1234 and email is ahmad@mail.com")
print(result.text)
# → 'My IC is <MY_IC> and email is <EMAIL_ADDRESS>'

# Inspect what was detected
for e in result.entities:
    print(e.type, e.start, e.end, e.score)
# → MY_IC 6 23 0.85
# → EMAIL_ADDRESS 37 53 1.0
```

### Filter what gets redacted

```python
# Only redact specific types
result = kloak.redact(text, include=["EMAIL_ADDRESS", "MY_IC"])

# Skip specific types
result = kloak.redact(text, exclude=["PERSON"])

# include takes priority over exclude if both are passed
```

### Check which backend is active

```python
print(kloak.backend)
# → "spacy:en_core_web_sm"   (if kloak[nlp] installed)
# → "regex-only"             (core install, no spaCy)
```

### KloakEngine for repeated calls

```python
from kloak import KloakEngine

engine = KloakEngine(language="en", score_threshold=0.6)
for text in my_texts:
    result = engine.redact(text)
```

---

## Extras

### Malaysian PII (`kloak[malaysian]`)

Zero extra dependencies — just regex patterns for Malaysian-specific PII:

```python
result = kloak.redact("IC: 880101-01-1234, phone: 012-3456789, SSM: 123456-A")
# → 'IC: <MY_IC>, phone: <MY_PHONE_NUMBER>, SSM: <MY_SSM>'
```

Entities: `MY_IC`, `MY_PHONE_NUMBER`, `MY_LANDLINE`, `MY_SSM`, `MY_BANK_ACCOUNT`

### Secrets detection (`kloak[gitleaks]`)

Dynamically loads [GitLeaks](https://github.com/gitleaks/gitleaks) rules on first use, caches locally at `~/.kloak/gitleaks_rules.toml`, refreshes weekly. Works offline after first fetch.

```python
result = kloak.redact("stripe key: sk_live_abc123, github: ghp_xyz456")
# → 'stripe key: <STRIPE_ACCESS_TOKEN>, github: <GITHUB_PAT>'
```

Covers: Stripe, OpenAI, GitHub, GitLab, AWS, GCP, Shopify, Twilio, PEM private keys, and [250+ more rules](https://github.com/gitleaks/gitleaks/blob/main/config/gitleaks.toml).

### NLP / NER (`kloak[nlp]`)

Adds spaCy `en_core_web_sm` for name, organisation, and location detection:

```python
# Without [nlp]: names are missed
kloak.redact("Ahmad called the office").text
# → 'Ahmad called the office'

# With [nlp]: NER catches the name
kloak.redact("Ahmad called the office").text
# → '<PERSON> called the office'
```

---

## Local-first guarantees

- **Zero network calls in core.** Emails, phones, ICs, credit cards — all processed in-memory on your machine.
- **`[gitleaks]` fetches one file on first use**, then works fully offline. Fetch failure falls back to cached rules — never crashes.
- **No telemetry, no phone-home, no usage tracking.** Ever.
- **Input text never touches disk.** Processing is in-memory; nothing is logged by default.
- **Air-gap compatible.** Run `pip install kloak` with zero internet. Pre-cache the GitLeaks TOML if needed and point `KLOAK_GITLEAKS_CACHE_PATH` at it.

---

## Configuration

```bash
KLOAK_NLP_BACKEND=auto                    # auto | spacy | regex
KLOAK_SPACY_MODEL=en_core_web_sm          # override spaCy model
KLOAK_SECRETS_REFRESH_HOURS=168           # gitleaks cache TTL (default: weekly)
KLOAK_GITLEAKS_CACHE_PATH=~/.kloak/gitleaks_rules.toml
KLOAK_LOG_LEVEL=INFO
```

---

## What kloak does NOT do

- **No prompt injection detection** — use [LLM Guard](https://github.com/protectai/llm-guard) or [NeMo Guardrails](https://github.com/NVIDIA/NeMo-Guardrails)
- **No output scanning** — kloak runs pre-flight, before text reaches the LLM
- **No token map storage** — `redact()` strips permanently; if you need reversible tokenisation, that's a future extra
- **No business-context sensitivity** — kloak detects PII patterns, not confidential business information
- **No streaming / audio** — text only, processed in batch
- **No encryption** — kloak redacts (removes/replaces), not encrypts

Kloak's job: **text in → PII and secrets stripped → clean text out.**

---

## Contributing

Kloak is built on a modular extras system — there are many ways to contribute beyond the core:

- **Add your country's PII** — regional extras are self-contained regex patterns + tests. Copy `kloak/extras/malaysian/` as a starting point. Singapore, Indonesia, Thailand, EU — each country is a standalone PR.
- **Add a new recognizer** to an existing extra — e.g. Malaysian passport numbers, additional bank formats.
- **Add a new extra** — messaging platforms (Telegram, Signal), compliance logging, new secret sources. Each extra is an independent module under `kloak/extras/`.
- **Improve detection accuracy** — better regex patterns, context word tuning, edge case handling.
- **Core improvements** — performance, new API features, better NLP backend support.

Every extra follows the same structure:

```
kloak/extras/<name>/
├── __init__.py
├── recognizers.py          # PatternRecognizer objects
└── test_fixtures.json      # Sample inputs + expected entities
```

Every recognizer is a [Presidio `PatternRecognizer`](https://microsoft.github.io/presidio/analyzer/adding_recognizers/):

```python
from presidio_analyzer import Pattern, PatternRecognizer

PatternRecognizer(
    supported_entity="SG_NRIC",
    patterns=[Pattern("sg_nric", r"[STFGM]\d{7}[A-Z]", score=0.85)],
    context=["nric", "ic", "identity"],
)
```

Add tests under `tests/extras/<name>/` and open a PR. See `CLAUDE.md` for the full checklist.

---

## License

Apache 2.0 — use it anywhere, including commercial projects.
