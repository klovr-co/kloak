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
