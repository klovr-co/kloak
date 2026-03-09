"""Tests that verify kloak works with zero NLP dependencies (regex-only mode)."""

import pytest

from kloak.engine import KloakEngine


@pytest.fixture(autouse=True)
def force_regex_mode(monkeypatch):
    monkeypatch.setenv("KLOAK_NLP_BACKEND", "regex")


@pytest.fixture
def engine():
    return KloakEngine()


def test_backend_is_regex_only(engine):
    assert engine.backend == "regex-only"


def test_email_detected(engine):
    result = engine.redact("Contact ahmad@mail.com")
    assert "<EMAIL_ADDRESS>" in result.text


def test_credit_card_detected(engine):
    result = engine.redact("Card: 4111111111111111")
    assert "4111111111111111" not in result.text


def test_ip_address_detected(engine):
    result = engine.redact("Server: 10.0.0.1")
    assert "10.0.0.1" not in result.text


def test_url_detected(engine):
    result = engine.redact("Go to https://secret.internal.com/admin")
    assert "secret.internal.com" not in result.text


def test_no_crash_on_empty_text(engine):
    result = engine.redact("")
    assert result.text == ""
    assert result.entities == []


def test_no_crash_on_unicode(engine):
    result = engine.redact("こんにちは ahmad@mail.com 你好")
    assert "<EMAIL_ADDRESS>" in result.text


def test_no_crash_on_manglish(engine):
    """Manglish/code-switched text should not crash."""
    result = engine.redact("Eh bro, nak transfer ke akaun 112233445566 tak?")
    # May or may not detect — but must not crash
    assert isinstance(result.text, str)


def test_multiple_entities(engine):
    result = engine.redact("Email ahmad@mail.com, IP 192.168.1.1")
    assert "<EMAIL_ADDRESS>" in result.text
    assert "192.168.1.1" not in result.text
    assert len(result.entities) >= 2
