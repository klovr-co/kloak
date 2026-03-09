import pytest


@pytest.fixture(autouse=True)
def force_regex_mode(monkeypatch):
    monkeypatch.setenv("KLOAK_NLP_BACKEND", "regex")


class TestTokenizeResultType:
    def test_tokenize_result_fields(self):
        from kloak.types import EntityMatch, TokenizeResult

        result = TokenizeResult(
            text="Hello <EMAIL_ADDRESS_1>",
            mapping={"<EMAIL_ADDRESS_1>": "ahmad@mail.com"},
            entities=[EntityMatch(type="EMAIL_ADDRESS", start=6, end=20, score=1.0)],
        )
        assert result.text == "Hello <EMAIL_ADDRESS_1>"
        assert result.mapping == {"<EMAIL_ADDRESS_1>": "ahmad@mail.com"}
        assert len(result.entities) == 1

    def test_tokenize_result_is_frozen(self):
        from kloak.types import TokenizeResult

        result = TokenizeResult(text="x", mapping={}, entities=[])
        with pytest.raises(AttributeError):
            result.text = "y"
