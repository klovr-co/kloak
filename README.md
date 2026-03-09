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
