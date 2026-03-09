import time
from unittest.mock import patch

from kloak.extras.gitleaks.cache import get_toml
from kloak.extras.gitleaks.loader import load_gitleaks_recognizers

SAMPLE_TOML = """
title = "gitleaks config"

[[rules]]
id = "openai-api-key"
description = "OpenAI API Key"
regex = '''sk-[a-zA-Z0-9]{20,}'''
keywords = ["sk-"]

[[rules]]
id = "aws-access-key"
description = "AWS Access Key"
regex = '''AKIA[0-9A-Z]{16}'''
keywords = ["AKIA"]
"""


class TestCache:
    def test_fresh_cache_used(self, tmp_path):
        cache_file = tmp_path / "rules.toml"
        cache_file.write_text(SAMPLE_TOML)

        result = get_toml(cache_path=cache_file, refresh_hours=168)
        assert "rules" in result
        assert len(result["rules"]) == 2

    def test_stale_cache_triggers_fetch(self, tmp_path):
        cache_file = tmp_path / "rules.toml"
        cache_file.write_text(SAMPLE_TOML)
        # Make file old
        old_time = time.time() - (200 * 3600)
        import os

        os.utime(cache_file, (old_time, old_time))

        with patch("kloak.extras.gitleaks.cache._fetch_toml") as mock_fetch:
            mock_fetch.return_value = SAMPLE_TOML
            get_toml(cache_path=cache_file, refresh_hours=168)
            mock_fetch.assert_called_once()

    def test_fetch_failure_uses_stale_cache(self, tmp_path):
        cache_file = tmp_path / "rules.toml"
        cache_file.write_text(SAMPLE_TOML)
        old_time = time.time() - (200 * 3600)
        import os

        os.utime(cache_file, (old_time, old_time))

        with patch("kloak.extras.gitleaks.cache._fetch_toml") as mock_fetch:
            mock_fetch.side_effect = Exception("network error")
            result = get_toml(cache_path=cache_file, refresh_hours=168)
            assert len(result["rules"]) == 2  # stale cache used

    def test_no_cache_no_network_returns_empty(self, tmp_path):
        cache_file = tmp_path / "nonexistent.toml"

        with patch("kloak.extras.gitleaks.cache._fetch_toml") as mock_fetch:
            mock_fetch.side_effect = Exception("network error")
            result = get_toml(cache_path=cache_file, refresh_hours=168)
            assert result.get("rules", []) == []

    def test_corrupt_cache_falls_back_to_fetch(self, tmp_path):
        cache_file = tmp_path / "rules.toml"
        cache_file.write_text("not-valid-toml = [")

        with patch("kloak.extras.gitleaks.cache._fetch_toml") as mock_fetch:
            mock_fetch.return_value = SAMPLE_TOML
            result = get_toml(cache_path=cache_file, refresh_hours=168)
            assert len(result["rules"]) == 2


SAMPLE_TOML_DICT = {
    "rules": [
        {
            "id": "openai-api-key",
            "description": "OpenAI API Key",
            "regex": r"sk-[a-zA-Z0-9]{20,}",
            "keywords": ["sk-"],
        },
        {
            "id": "aws-access-key",
            "description": "AWS Access Key",
            "regex": r"AKIA[0-9A-Z]{16}",
            "keywords": ["AKIA"],
        },
    ],
}


class TestLoader:
    def test_load_creates_recognizers(self):
        recognizers = load_gitleaks_recognizers(SAMPLE_TOML_DICT)
        assert len(recognizers) == 2

    def test_recognizer_entity_names_uppercased(self):
        recognizers = load_gitleaks_recognizers(SAMPLE_TOML_DICT)
        entities = {r.supported_entities[0] for r in recognizers}
        assert "OPENAI_API_KEY" in entities
        assert "AWS_ACCESS_KEY" in entities

    def test_incompatible_regex_skipped(self):
        toml_data = {
            "rules": [
                {
                    "id": "good-rule",
                    "regex": r"sk-[a-zA-Z0-9]+",
                },
                {
                    "id": "bad-rule",
                    "regex": r"(?!invalid(?P<broken)",  # broken regex
                },
            ],
        }
        recognizers = load_gitleaks_recognizers(toml_data)
        assert len(recognizers) == 1

    def test_empty_rules(self):
        recognizers = load_gitleaks_recognizers({"rules": []})
        assert recognizers == []

    def test_missing_rules_key(self):
        recognizers = load_gitleaks_recognizers({})
        assert recognizers == []


class TestEndToEnd:
    def test_gitleaks_redacts_openai_key(self, monkeypatch):
        monkeypatch.setenv("KLOAK_NLP_BACKEND", "regex")

        # Patch where get_toml is used (not where defined) — standard mock.patch rule
        with patch(
            "kloak.extras.gitleaks.get_toml",
            return_value={
                "rules": [
                    {
                        "id": "openai-api-key",
                        "description": "OpenAI API Key",
                        "regex": r"sk-[a-zA-Z0-9]{20,}",
                        "keywords": ["sk-"],
                    }
                ]
            },
        ):
            from kloak.engine import KloakEngine

            engine = KloakEngine()
            result = engine.redact("My key is sk-abcdefghijklmnopqrstuvwxyz")
            assert "sk-abcdefghijklmnopqrstuvwxyz" not in result.text
