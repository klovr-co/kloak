from __future__ import annotations

import os
from pathlib import Path

# NLP backend
NLP_BACKEND = os.environ.get("KLOAK_NLP_BACKEND", "auto")
SPACY_MODEL = os.environ.get("KLOAK_SPACY_MODEL", "")

# GitLeaks — pinned to a specific tag to avoid breaking changes from moving branches
GITLEAKS_URL = os.environ.get(
    "KLOAK_GITLEAKS_URL",
    "https://raw.githubusercontent.com/gitleaks/gitleaks/v8.21.2/config/gitleaks.toml",
)
GITLEAKS_CACHE_PATH = Path(
    os.environ.get("KLOAK_GITLEAKS_CACHE_PATH", "~/.kloak/gitleaks_rules.toml")
).expanduser()
SECRETS_REFRESH_HOURS = int(os.environ.get("KLOAK_SECRETS_REFRESH_HOURS", "168"))

# Engine defaults
DEFAULT_LANGUAGE = "en"
DEFAULT_SCORE_THRESHOLD = 0.35
