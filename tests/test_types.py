from kloak.types import EntityMatch, RedactResult


def test_entity_match_is_frozen():
    e = EntityMatch(type="EMAIL_ADDRESS", start=0, end=5, score=0.85)
    assert e.type == "EMAIL_ADDRESS"
    assert e.start == 0
    assert e.end == 5
    assert e.score == 0.85


def test_entity_match_from_presidio():
    from presidio_analyzer import RecognizerResult

    pr = RecognizerResult(entity_type="PERSON", start=10, end=15, score=0.9)
    e = EntityMatch.from_presidio(pr)
    assert e.type == "PERSON"
    assert e.start == 10
    assert e.end == 15
    assert e.score == 0.9


def test_redact_result():
    r = RedactResult(
        text="Hello <PERSON>",
        entities=[EntityMatch(type="PERSON", start=6, end=11, score=0.85)],
    )
    assert r.text == "Hello <PERSON>"
    assert len(r.entities) == 1
