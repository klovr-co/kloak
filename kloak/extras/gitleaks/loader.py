"""Parse GitLeaks TOML rules into Presidio recognizers."""

from __future__ import annotations

import logging
import re

from presidio_analyzer import Pattern, PatternRecognizer

logger = logging.getLogger("kloak")


def _normalize_entity_name(rule_id: str) -> str:
    """Convert 'openai-api-key' → 'OPENAI_API_KEY'."""
    return rule_id.replace("-", "_").upper()


def load_gitleaks_recognizers(toml_data: dict) -> list[PatternRecognizer]:
    """Convert GitLeaks TOML rules to Presidio PatternRecognizer list.

    Skips rules with incompatible regex (logs warning, never crashes).
    """
    recognizers: list[PatternRecognizer] = []

    for rule in toml_data.get("rules", []):
        rule_id = rule.get("id", "")
        regex = rule.get("regex", "")

        if not rule_id or not regex:
            continue

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
