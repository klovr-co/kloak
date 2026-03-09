import pytest

from kloak.engine import KloakEngine


@pytest.fixture(autouse=True)
def force_regex_mode(monkeypatch):
    monkeypatch.setenv("KLOAK_NLP_BACKEND", "regex")


@pytest.fixture
def engine():
    return KloakEngine()


class TestMyKadRedaction:
    def test_mykad_with_dashes(self, engine):
        result = engine.redact("IC saya 880101-01-1234")
        assert "<MY_IC>" in result.text
        assert "880101-01-1234" not in result.text

    def test_mykad_without_dashes(self, engine):
        result = engine.redact("IC number: 880101011234")
        assert "<MY_IC>" in result.text

    def test_invalid_mykad_not_redacted(self, engine):
        # Invalid state code 00
        result = engine.redact("Number 880101001234")
        assert "MY_IC" not in result.text or result.entities == []


class TestMyMobile:
    def test_mobile_with_plus60(self, engine):
        result = engine.redact("Call +60121234567")
        assert "+60121234567" not in result.text

    def test_mobile_with_zero(self, engine):
        result = engine.redact("Nombor 012-3456789")
        assert "012-3456789" not in result.text

    def test_mobile_019(self, engine):
        result = engine.redact("Phone 019-1234567")
        assert "019-1234567" not in result.text


class TestMyLandline:
    def test_kl_landline(self, engine):
        result = engine.redact("Office 03-12345678")
        assert "03-12345678" not in result.text

    def test_state_landline(self, engine):
        result = engine.redact("Call 04-1234567")
        assert "04-1234567" not in result.text


class TestMySSM:
    def test_ssm_registration(self, engine):
        result = engine.redact("SSM registration 1234567-A")
        assert "1234567-A" not in result.text


class TestMyBankAccount:
    def test_maybank_with_context(self, engine):
        result = engine.redact("Maybank account 112233445566")
        assert "112233445566" not in result.text

    def test_digits_without_context_not_matched(self, engine):
        """12 random digits without banking context should NOT be redacted as bank account."""
        result = engine.redact("Reference number 112233445566")
        # Should NOT match — no banking context words
        has_bank = any(e.type == "MY_BANK_ACCOUNT" for e in result.entities)
        assert not has_bank
