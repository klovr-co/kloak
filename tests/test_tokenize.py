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


@pytest.fixture
def engine():
    from kloak.engine import KloakEngine

    return KloakEngine()


class TestTokenize:
    def test_tokenize_single_email(self, engine):
        result = engine.tokenize("Contact ahmad@mail.com")
        assert "<EMAIL_ADDRESS_1>" in result.text
        assert "ahmad@mail.com" not in result.text
        assert result.mapping["<EMAIL_ADDRESS_1>"] == "ahmad@mail.com"
        assert any(e.type == "EMAIL_ADDRESS" for e in result.entities)

    def test_tokenize_multiple_same_type(self, engine):
        result = engine.tokenize("Email ahmad@mail.com and bob@mail.com")
        assert "<EMAIL_ADDRESS_1>" in result.text
        assert "<EMAIL_ADDRESS_2>" in result.text
        assert "ahmad@mail.com" not in result.text
        assert "bob@mail.com" not in result.text
        assert len(result.mapping) == 2

    def test_tokenize_different_types(self, engine):
        result = engine.tokenize("Email ahmad@mail.com, IP 192.168.1.1")
        assert "<EMAIL_ADDRESS_1>" in result.text
        # IP may be detected — just check mapping has entries
        assert len(result.mapping) >= 1

    def test_tokenize_no_pii(self, engine):
        result = engine.tokenize("The weather is nice today")
        assert result.text == "The weather is nice today"
        assert result.mapping == {}
        assert result.entities == []

    def test_tokenize_empty_text(self, engine):
        result = engine.tokenize("")
        assert result.text == ""
        assert result.mapping == {}
        assert result.entities == []

    def test_tokenize_include_filter(self, engine):
        result = engine.tokenize(
            "Email ahmad@mail.com, IP 192.168.1.1",
            include=["EMAIL_ADDRESS"],
        )
        assert "<EMAIL_ADDRESS_1>" in result.text
        assert "192.168.1.1" in result.text  # IP not tokenized

    def test_tokenize_exclude_filter(self, engine):
        result = engine.tokenize(
            "Email ahmad@mail.com, IP 192.168.1.1",
            exclude=["EMAIL_ADDRESS"],
        )
        assert not any(e.type == "EMAIL_ADDRESS" for e in result.entities)

    def test_tokenize_returns_tokenize_result(self, engine):
        from kloak.types import TokenizeResult

        result = engine.tokenize("Email ahmad@mail.com")
        assert isinstance(result, TokenizeResult)

    def test_entities_reference_original_text(self, engine):
        text = "Email ahmad@mail.com"
        result = engine.tokenize(text)
        entity = next(e for e in result.entities if e.type == "EMAIL_ADDRESS")
        assert text[entity.start : entity.end] == "ahmad@mail.com"

    def test_tokenize_left_to_right_numbering(self, engine):
        text = "Email ahmad@mail.com and bob@mail.com"
        result = engine.tokenize(text)
        # First email in text gets _1, second gets _2
        assert result.mapping.get("<EMAIL_ADDRESS_1>") == "ahmad@mail.com"
        assert result.mapping.get("<EMAIL_ADDRESS_2>") == "bob@mail.com"


class TestModuleLevelTokenize:
    def test_module_tokenize(self):
        import kloak

        result = kloak.tokenize("Email ahmad@mail.com")
        assert "<EMAIL_ADDRESS_1>" in result.text
        assert result.mapping["<EMAIL_ADDRESS_1>"] == "ahmad@mail.com"

    def test_module_deanonymize(self):
        import kloak

        result = kloak.tokenize("Email ahmad@mail.com")
        restored = kloak.deanonymize(result.text, result.mapping)
        assert restored == "Email ahmad@mail.com"

    def test_module_tokenize_result_exported(self):
        from kloak import TokenizeResult

        assert TokenizeResult is not None
