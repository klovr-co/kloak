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
