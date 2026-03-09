"""Malaysian PII recognizers — MyKad, phone, landline, SSM, bank accounts."""

from __future__ import annotations

from presidio_analyzer import Pattern, PatternRecognizer

from kloak.extras.malaysian.mykad import validate_mykad


class MyKadRecognizer(PatternRecognizer):
    """Malaysian IC (MyKad) recognizer with date + state code validation."""

    def __init__(self) -> None:
        patterns = [
            Pattern(
                name="mykad_with_dashes",
                regex=r"\b\d{6}-\d{2}-\d{4}\b",
                score=0.4,
            ),
            Pattern(
                name="mykad_without_dashes",
                regex=r"\b\d{12}\b",
                score=0.1,
            ),
        ]
        super().__init__(
            supported_entity="MY_IC",
            name="MyKad IC Recognizer",
            patterns=patterns,
            context=["ic", "mykad", "kad pengenalan", "nric", "identity card", "no kp"],
        )

    def validate_result(self, pattern_text: str) -> bool | None:
        return validate_mykad(pattern_text)


def _my_mobile_recognizer() -> PatternRecognizer:
    return PatternRecognizer(
        supported_entity="MY_MOBILE",
        name="Malaysian Mobile Recognizer",
        patterns=[
            Pattern(
                name="my_mobile_plus60",
                regex=r"\b\+?601[0-9]-?\d{7,8}\b",
                score=0.85,
            ),
            Pattern(
                name="my_mobile_zero",
                regex=r"\b01[0-9]-?\d{7,8}\b",
                score=0.75,
            ),
        ],
        context=["phone", "mobile", "telefon", "nombor", "call", "whatsapp"],
    )


def _my_landline_recognizer() -> PatternRecognizer:
    return PatternRecognizer(
        supported_entity="MY_LANDLINE",
        name="Malaysian Landline Recognizer",
        patterns=[
            Pattern(
                name="my_landline_plus60",
                regex=r"\b\+?60[3-9]-?\d{7,8}\b",
                score=0.7,
            ),
            Pattern(
                name="my_landline_zero",
                regex=r"\b0[3-9]-?\d{7,8}\b",
                score=0.6,
            ),
        ],
        context=["phone", "office", "landline", "telefon", "pejabat"],
    )


def _my_ssm_recognizer() -> PatternRecognizer:
    return PatternRecognizer(
        supported_entity="MY_SSM",
        name="Malaysian SSM Registration Recognizer",
        patterns=[
            Pattern(
                name="my_ssm",
                regex=r"\b\d{6,7}-[A-Z]\b",
                score=0.6,
            ),
        ],
        context=["ssm", "registration", "company", "syarikat", "pendaftaran"],
    )


def _my_bank_account_recognizer() -> PatternRecognizer:
    return PatternRecognizer(
        supported_entity="MY_BANK_ACCOUNT",
        name="Malaysian Bank Account Recognizer",
        patterns=[
            Pattern(name="maybank_12", regex=r"\b\d{12}\b", score=0.3),
            Pattern(name="cimb_10", regex=r"\b\d{10}\b", score=0.3),
            Pattern(name="cimb_rhb_14", regex=r"\b\d{14}\b", score=0.3),
            Pattern(name="hlb_11", regex=r"\b\d{11}\b", score=0.3),
            Pattern(name="ambank_13", regex=r"\b\d{13}\b", score=0.3),
            Pattern(name="pub_bank_15", regex=r"\b\d{15}\b", score=0.3),
        ],
        context=[
            "account",
            "akaun",
            "bank",
            "maybank",
            "cimb",
            "public bank",
            "rhb",
            "hong leong",
            "ambank",
            "transfer",
            "deposit",
        ],
    )


def get_recognizers() -> list[PatternRecognizer]:
    """Return all Malaysian PII recognizers."""
    return [
        MyKadRecognizer(),
        _my_mobile_recognizer(),
        _my_landline_recognizer(),
        _my_ssm_recognizer(),
        _my_bank_account_recognizer(),
    ]
