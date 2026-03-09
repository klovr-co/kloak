from kloak.null_nlp import NullNlpEngine


def test_null_engine_loads():
    engine = NullNlpEngine()
    assert engine.is_loaded()


def test_null_engine_returns_empty_artifacts():
    engine = NullNlpEngine()
    artifacts = engine.process_text("Hello world", "en")
    assert artifacts.entities == []


def test_null_engine_supported_languages():
    engine = NullNlpEngine()
    assert "en" in engine.get_supported_languages()


def test_null_engine_no_ner_entities():
    engine = NullNlpEngine()
    assert engine.get_supported_entities() == []
