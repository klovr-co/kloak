import pytest

from kloak.extras.malaysian.mykad import validate_mykad

# --- All 58 valid state/place-of-birth codes ---
VALID_STATE_CODES = [
    # Malaysian states
    "01",
    "02",
    "03",
    "04",
    "05",
    "06",
    "07",
    "08",
    "09",
    "10",
    "11",
    "12",
    "13",
    "14",
    "15",
    "16",
    # Extended state codes
    "21",
    "22",
    "23",
    "24",
    "25",
    "26",
    "27",
    "28",
    "29",
    "30",
    "31",
    "32",
    "33",
    "34",
    "35",
    "36",
    "37",
    "38",
    "39",
    "40",
    "41",
    "42",
    "43",
    "44",
    "45",
    "46",
    "47",
    "48",
    "49",
    "50",
    "51",
    "52",
    "53",
    "54",
    "55",
    "56",
    "57",
    "58",
    "59",
    # Foreign country codes
    "60",
    "61",
    "62",
    "63",
    "64",
    "65",
    "66",
    "67",
    "68",
    "71",
    "74",
    "75",
    "76",
    "77",
    "78",
    "79",
    "82",
    "83",
    "84",
    "85",
    "86",
    "87",
    "88",
    "89",
    "90",
    "91",
    "92",
    "93",
]

INVALID_STATE_CODES = [
    "00",
    "17",
    "18",
    "19",
    "20",
    "69",
    "70",
    "72",
    "73",
    "80",
    "81",
    "94",
    "95",
    "96",
    "97",
    "98",
    "99",
]


class TestValidStateCodes:
    @pytest.mark.parametrize("code", VALID_STATE_CODES)
    def test_valid_state_code(self, code):
        ic = f"880101{code}1234"
        assert validate_mykad(ic), f"State code {code} should be valid"


class TestInvalidStateCodes:
    @pytest.mark.parametrize("code", INVALID_STATE_CODES)
    def test_invalid_state_code(self, code):
        ic = f"880101{code}1234"
        assert not validate_mykad(ic), f"State code {code} should be invalid"


class TestValidDates:
    @pytest.mark.parametrize(
        "date_part,desc",
        [
            ("880101", "Jan 1 1988"),
            ("960531", "May 31 1996"),
            ("000229", "Feb 29 2000 — leap year"),
            ("040229", "Feb 29 2004 — leap year"),
            ("251231", "Dec 31 2025"),
            ("010101", "Jan 1 2001"),
        ],
    )
    def test_valid_date(self, date_part, desc):
        ic = f"{date_part}011234"
        assert validate_mykad(ic), f"Date {desc} should be valid"


class TestInvalidDates:
    @pytest.mark.parametrize(
        "date_part,desc",
        [
            ("881301", "month 13"),
            ("880230", "Feb 30"),
            ("880000", "month 0"),
            ("880100", "day 0"),
            ("880132", "Jan 32"),
            ("890229", "Feb 29 non-leap 1989"),
            ("000631", "Jun 31"),
        ],
    )
    def test_invalid_date(self, date_part, desc):
        ic = f"{date_part}011234"
        assert not validate_mykad(ic), f"Date {desc} should be invalid"


class TestFormat:
    def test_with_dashes(self):
        assert validate_mykad("880101-01-1234")

    def test_without_dashes(self):
        assert validate_mykad("880101011234")

    def test_wrong_length_short(self):
        assert not validate_mykad("88010101123")

    def test_wrong_length_long(self):
        assert not validate_mykad("8801010112345")

    def test_non_numeric(self):
        assert not validate_mykad("88010A011234")

    def test_empty_string(self):
        assert not validate_mykad("")
