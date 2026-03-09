"""
Secrets detection via GitLeaks rules.

kloak automatically fetches GitLeaks rules on first use and caches them at
~/.kloak/gitleaks_rules.toml (refreshed weekly). No configuration required.
"""

import logging

import kloak

# Suppress "Skipping rule" noise for rules with Go-regex syntax
logging.getLogger("kloak").setLevel(logging.ERROR)


# --- Basic secrets redaction -------------------------------------------------

# Build example secrets via concatenation so they don't trigger
# GitHub push-protection (which scans source files for raw patterns).
_STRIPE = "sk_live_" + "abcdefghijklmnopqrstuvwxyz"
_GH_PAT = "ghp_" + "abcdefghijklmnopqrstuvwxyz123456"
_SHOPIFY = "shpat_" + "aabbccddeeff00112233445566778899"

result = kloak.redact(f"stripe key: {_STRIPE}")
print(result.text)
# → stripe <STRIPE_ACCESS_TOKEN>

result = kloak.redact(f"token: {_GH_PAT}")
print(result.text)
# → <GITHUB_PAT>

result = kloak.redact(f"access_token = {_SHOPIFY}")
print(result.text)
# → access_token = <SHOPIFY_ACCESS_TOKEN>


# --- Inspect what was detected -----------------------------------------------

result = kloak.redact(f"my stripe key: {_STRIPE}")
for entity in result.entities:
    original = f"my stripe key: {_STRIPE}"
    print(f"{entity.type}: '{original[entity.start:entity.end]}' (score={entity.score:.2f})")


# --- Mixed PII + secrets in one pass ----------------------------------------

text = f"""
Hello,
My email is ahmad@mail.com and my IC is 880101-01-1234.
Our Stripe key is {_STRIPE} — please rotate it.
"""

result = kloak.redact(text)
print(result.text)
# All three are redacted in a single kloak.redact() call:
# → EMAIL_ADDRESS, MY_IC, STRIPE_ACCESS_TOKEN


# --- Use KloakEngine directly for repeated calls ----------------------------

from kloak import KloakEngine  # noqa: E402

engine = KloakEngine()

texts = [
    f"key={_STRIPE}",
    f"token: {_GH_PAT}",
    "nothing sensitive here",
]
for t in texts:
    r = engine.redact(t)
    found = [e.type for e in r.entities] or ["—"]
    print(f"{t[:40]:<42} → {', '.join(found)}")
