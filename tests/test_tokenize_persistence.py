import json

import pytest


@pytest.fixture(autouse=True)
def force_regex_mode(monkeypatch):
    monkeypatch.setenv("KLOAK_NLP_BACKEND", "regex")


class TestToJson:
    def test_to_json_returns_string(self):
        from kloak.types import TokenizeResult

        result = TokenizeResult(
            text="<EMAIL_ADDRESS_1>",
            mapping={"<EMAIL_ADDRESS_1>": "ahmad@mail.com"},
            entities=[],
        )
        json_str = result.to_json()
        assert json_str is not None
        parsed = json.loads(json_str)
        assert parsed == {"<EMAIL_ADDRESS_1>": "ahmad@mail.com"}

    def test_to_json_writes_file(self, tmp_path):
        from kloak.types import TokenizeResult

        result = TokenizeResult(
            text="<EMAIL_ADDRESS_1>",
            mapping={"<EMAIL_ADDRESS_1>": "ahmad@mail.com"},
            entities=[],
        )
        filepath = tmp_path / "mapping.json"
        ret = result.to_json(str(filepath))
        assert ret is None
        parsed = json.loads(filepath.read_text())
        assert parsed == {"<EMAIL_ADDRESS_1>": "ahmad@mail.com"}

    def test_to_json_empty_mapping(self):
        from kloak.types import TokenizeResult

        result = TokenizeResult(text="hello", mapping={}, entities=[])
        json_str = result.to_json()
        assert json.loads(json_str) == {}


class TestLoadMapping:
    def test_load_mapping_from_file(self, tmp_path):
        from kloak.types import TokenizeResult

        filepath = tmp_path / "mapping.json"
        data = {"<EMAIL_ADDRESS_1>": "ahmad@mail.com"}
        filepath.write_text(json.dumps(data))

        mapping = TokenizeResult.load_mapping(str(filepath))
        assert mapping == data

    def test_load_mapping_file_not_found(self):
        from kloak.types import TokenizeResult

        with pytest.raises(FileNotFoundError):
            TokenizeResult.load_mapping("/nonexistent/mapping.json")
