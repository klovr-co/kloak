import pytest

from kloak.engine import KloakEngine


@pytest.fixture(autouse=True)
def force_regex_mode(monkeypatch):
    monkeypatch.setenv("KLOAK_NLP_BACKEND", "regex")


@pytest.fixture
def engine():
    return KloakEngine()


class TestInclude:
    def test_include_only_email(self, engine):
        text = "Email ahmad@mail.com, IP 192.168.1.1"
        result = engine.redact(text, include=["EMAIL_ADDRESS"])
        assert "<EMAIL_ADDRESS>" in result.text
        assert "192.168.1.1" in result.text  # IP not redacted

    def test_include_empty_list_redacts_nothing(self, engine):
        text = "Email ahmad@mail.com"
        result = engine.redact(text, include=[])
        assert result.text == text


class TestExclude:
    def test_exclude_email(self, engine):
        text = "Email ahmad@mail.com, IP 192.168.1.1"
        result = engine.redact(text, exclude=["EMAIL_ADDRESS"])
        # No EMAIL_ADDRESS entity detected (URL recognizer may still fire on domain)
        assert not any(e.type == "EMAIL_ADDRESS" for e in result.entities)
        # IP still redacted
        assert "192.168.1.1" not in result.text

    def test_exclude_empty_list_redacts_all(self, engine):
        text = "Email ahmad@mail.com"
        result = engine.redact(text, exclude=[])
        assert "<EMAIL_ADDRESS>" in result.text


class TestIncludeExcludePriority:
    def test_include_takes_priority(self, engine):
        text = "Email ahmad@mail.com, IP 192.168.1.1"
        result = engine.redact(text, include=["EMAIL_ADDRESS"], exclude=["EMAIL_ADDRESS"])
        # include wins — email IS redacted despite being in exclude
        assert "<EMAIL_ADDRESS>" in result.text


class TestValidation:
    def test_unknown_include_raises(self, engine):
        with pytest.raises(ValueError):
            engine.redact("Email ahmad@mail.com", include=["EMAIL"])
