"""Parse GitLeaks TOML rules into Presidio recognizers."""

from __future__ import annotations

import logging
import re

from presidio_analyzer import Pattern, PatternRecognizer

logger = logging.getLogger("kloak")

# ---------------------------------------------------------------------------
# PCRE → Python regex portability fixes
# ---------------------------------------------------------------------------

# Mid-pattern (?i) — Python requires global flags at position 0.
# Rewrite e.g. `prefix(?i)[a-z]{32}` → `prefix(?i:[a-z]{32})`.
_MID_PATTERN_FLAG = re.compile(r"(?<!^)\(\?i\)")


def _fix_mid_pattern_flag(regex: str) -> str:
    """Hoist mid-pattern ``(?i)`` flags to the start of the pattern.

    Some rules have multiple ``(?i)`` in different branches which can't
    be individually group-scoped without a full regex parser.  Hoisting
    to the front is safe — the few rules that use ``(?-i:...)`` to
    explicitly disable case-insensitivity for a sub-group still work
    because group-scoped negation overrides the global flag.
    """
    if not _MID_PATTERN_FLAG.search(regex):
        return regex
    # Strip all mid-pattern (?i) and add a single one at the start.
    regex = _MID_PATTERN_FLAG.sub("", regex)
    return f"(?i){regex}"


def _pcre_to_python(regex: str) -> str:
    """Best-effort PCRE/RE2 → Python ``re`` conversion."""
    # \z (PCRE end-of-string) → \Z (Python equivalent)
    regex = regex.replace(r"\z", r"\Z")
    # Mid-pattern (?i) → group-scoped (?i:...)
    regex = _fix_mid_pattern_flag(regex)
    return regex


def _normalize_entity_name(rule_id: str) -> str:
    """Convert 'openai-api-key' → 'OPENAI_API_KEY'."""
    return rule_id.replace("-", "_").upper()


def load_gitleaks_recognizers(toml_data: dict) -> list[PatternRecognizer]:
    """Convert GitLeaks TOML rules to Presidio PatternRecognizer list.

    Applies PCRE→Python regex fixes, then skips any rule that still
    fails to compile (logs warning, never crashes).
    """
    recognizers: list[PatternRecognizer] = []

    for rule in toml_data.get("rules", []):
        rule_id = rule.get("id", "")
        regex = rule.get("regex", "")

        if not rule_id or not regex:
            continue

        regex = _pcre_to_python(regex)

        # Validate regex compiles in Python
        try:
            re.compile(regex)
        except re.error:
            logger.warning("Skipping GitLeaks rule '%s': incompatible regex", rule_id)
            continue

        entity_name = _normalize_entity_name(rule_id)

        recognizers.append(
            PatternRecognizer(
                supported_entity=entity_name,
                name=rule.get("description", rule_id),
                patterns=[Pattern(name=rule_id, regex=regex, score=0.85)],
                context=rule.get("keywords", []),
            )
        )

    return recognizers
