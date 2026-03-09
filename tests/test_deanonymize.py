import pytest


@pytest.fixture(autouse=True)
def force_regex_mode(monkeypatch):
    monkeypatch.setenv("KLOAK_NLP_BACKEND", "regex")


@pytest.fixture
def engine():
    from kloak.engine import KloakEngine

    return KloakEngine()


class TestDeanonymize:
    def test_basic_round_trip(self, engine):
        text = "Contact ahmad@mail.com"
        tokenized = engine.tokenize(text)
        restored = engine.deanonymize(tokenized.text, tokenized.mapping)
        assert restored == text

    def test_multiple_entities_round_trip(self, engine):
        text = "Email ahmad@mail.com and bob@mail.com"
        tokenized = engine.tokenize(text)
        restored = engine.deanonymize(tokenized.text, tokenized.mapping)
        assert restored == text

    def test_strict_matching_no_case_insensitive(self, engine):
        text = "Hello <email_address_1>"
        mapping = {"<EMAIL_ADDRESS_1>": "ahmad@mail.com"}
        result = engine.deanonymize(text, mapping)
        # Strict: lowercase token not replaced
        assert result == "Hello <email_address_1>"

    def test_strict_matching_no_brackets_ignored(self, engine):
        text = "Hello EMAIL_ADDRESS_1"
        mapping = {"<EMAIL_ADDRESS_1>": "ahmad@mail.com"}
        result = engine.deanonymize(text, mapping)
        assert result == "Hello EMAIL_ADDRESS_1"

    def test_empty_mapping(self, engine):
        text = "Hello world"
        result = engine.deanonymize(text, {})
        assert result == "Hello world"

    def test_empty_text(self, engine):
        result = engine.deanonymize("", {"<EMAIL_ADDRESS_1>": "x"})
        assert result == ""

    def test_token_not_in_text(self, engine):
        text = "Hello world"
        mapping = {"<EMAIL_ADDRESS_1>": "ahmad@mail.com"}
        result = engine.deanonymize(text, mapping)
        assert result == "Hello world"

    def test_longest_token_first(self, engine):
        """Ensure <EMAIL_ADDRESS_10> is replaced before <EMAIL_ADDRESS_1>."""
        text = "A: <EMAIL_ADDRESS_1>, B: <EMAIL_ADDRESS_10>"
        mapping = {
            "<EMAIL_ADDRESS_1>": "a@x.com",
            "<EMAIL_ADDRESS_10>": "j@x.com",
        }
        result = engine.deanonymize(text, mapping)
        assert result == "A: a@x.com, B: j@x.com"


class TestRoundTrip:
    def test_tokenize_then_deanonymize_preserves_text(self, engine):
        """Full round-trip: tokenize → (simulate LLM) → deanonymize."""
        original = "Email ahmad@mail.com, IP 192.168.1.1"
        tokenized = engine.tokenize(original)

        # Simulate LLM echoing the tokenized text
        llm_response = f"I see your email is {tokenized.text.split(', ')[0].split(' ')[-1]}"

        # Won't match full original, but deanonymize should replace the token
        result = engine.deanonymize(llm_response, tokenized.mapping)
        assert "ahmad@mail.com" in result
