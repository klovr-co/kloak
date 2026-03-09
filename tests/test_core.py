import pytest


@pytest.fixture(autouse=True)
def force_regex_mode(monkeypatch):
    """Force regex-only mode for core tests — no spaCy dependency."""
    monkeypatch.setenv("KLOAK_NLP_BACKEND", "regex")


class TestRedactBuiltins:
    """Test redaction of Presidio built-in regex entities."""

    def test_redact_email(self):
        from kloak.engine import KloakEngine

        engine = KloakEngine()
        result = engine.redact("Contact me at ahmad@mail.com")
        assert "<EMAIL_ADDRESS>" in result.text
        assert "ahmad@mail.com" not in result.text
        assert any(e.type == "EMAIL_ADDRESS" for e in result.entities)

    def test_redact_phone(self):
        from kloak.engine import KloakEngine

        engine = KloakEngine()
        result = engine.redact("Call 555-123-4567 now")
        assert "555-123-4567" not in result.text

    def test_redact_ip_address(self):
        from kloak.engine import KloakEngine

        engine = KloakEngine()
        result = engine.redact("Server at 192.168.1.1 is down")
        assert "192.168.1.1" not in result.text

    def test_redact_url(self):
        from kloak.engine import KloakEngine

        engine = KloakEngine()
        result = engine.redact("Visit https://secret.example.com/admin")
        assert "secret.example.com" not in result.text

    def test_redact_credit_card(self):
        from kloak.engine import KloakEngine

        engine = KloakEngine()
        result = engine.redact("Card number 4111111111111111")
        assert "4111111111111111" not in result.text

    def test_no_pii_unchanged(self):
        from kloak.engine import KloakEngine

        engine = KloakEngine()
        text = "The weather is nice today"
        result = engine.redact(text)
        assert result.text == text
        assert result.entities == []

    def test_redact_result_type(self):
        from kloak.engine import KloakEngine
        from kloak.types import RedactResult

        engine = KloakEngine()
        result = engine.redact("Email: test@example.com")
        assert isinstance(result, RedactResult)

    def test_entity_positions_reference_original_text(self):
        from kloak.engine import KloakEngine

        engine = KloakEngine()
        text = "Email: ahmad@mail.com"
        result = engine.redact(text)
        entity = next(e for e in result.entities if e.type == "EMAIL_ADDRESS")
        assert text[entity.start : entity.end] == "ahmad@mail.com"


class TestBackendProperty:
    def test_backend_regex_only(self):
        from kloak.engine import KloakEngine

        engine = KloakEngine()
        engine._ensure_initialized()
        assert engine.backend == "regex-only"
