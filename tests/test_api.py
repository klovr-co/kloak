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
