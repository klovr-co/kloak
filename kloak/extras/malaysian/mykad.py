"""MyKad (Malaysian IC) validation — date + state/place-of-birth codes."""

from __future__ import annotations

import calendar

VALID_PB_CODES: frozenset[int] = frozenset(
    list(range(1, 17))  # 01-16: Malaysian states
    + list(range(21, 60))  # 21-59: extended state codes
    + list(range(60, 69))  # 60-68: ASEAN countries
    + [71]  # UK
    + list(range(74, 80))  # 74-79: Asian countries
    + [82]  # unknown state
    + list(range(83, 94))  # 83-93: regions/continents
)


def validate_mykad(value: str) -> bool:
    """Validate a MyKad IC number beyond regex.

    Checks:
    1. Exactly 12 digits (dashes stripped)
    2. Valid calendar date (YYMMDD)
    3. Valid state/place-of-birth code (positions 7-8)
    """
    digits = value.replace("-", "")

    if len(digits) != 12:
        return False

    if not digits.isdigit():
        return False

    # Parse date
    yy = int(digits[0:2])
    mm = int(digits[2:4])
    dd = int(digits[4:6])

    if mm < 1 or mm > 12:
        return False

    # Determine full year (assume age < 100)
    # 2000-based for 00-25, 1900-based for 26-99 (as of 2026)
    year = 2000 + yy if yy <= 25 else 1900 + yy

    max_day = calendar.monthrange(year, mm)[1]
    if dd < 1 or dd > max_day:
        return False

    # Validate state/place-of-birth code
    pb = int(digits[6:8])
    if pb not in VALID_PB_CODES:
        return False

    return True
