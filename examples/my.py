"""
Malaysian PII detection — MyKad, phones, landlines, SSM.

Included in kloak core (no extra install needed).

Note: use include=MY_ENTITIES to avoid false positives from Presidio's built-in
recognizers (e.g. UK_NHS matching Malaysian 01x numbers).
"""

import logging

import kloak

logging.getLogger("kloak").setLevel(logging.ERROR)

MY_ENTITIES = ["MY_IC", "MY_MOBILE", "MY_LANDLINE", "MY_SSM", "MY_BANK_ACCOUNT"]


# --- MyKad (IC) --------------------------------------------------------------

result = kloak.redact("IC saya: 880101-01-1234")
print(result.text)
# → IC saya: <MY_IC>

result = kloak.redact("NRIC: 880101011234")
print(result.text)
# → NRIC: <MY_IC>

# Invalid IC (bad state code 00) — passes through unchanged
result = kloak.redact("Number: 880101001234")
print(result.text)
# → Number: 880101001234


# --- Mobile numbers ----------------------------------------------------------

result = kloak.redact("Call me at +60121234567", include=MY_ENTITIES)
print(result.text)
# → Call me at +<MY_MOBILE>

result = kloak.redact("Nombor saya: 012-3456789", include=MY_ENTITIES)
print(result.text)
# → Nombor saya: <MY_MOBILE>

result = kloak.redact("WhatsApp: 019-1234567", include=MY_ENTITIES)
print(result.text)
# → WhatsApp: <MY_MOBILE>


# --- Landlines ---------------------------------------------------------------

result = kloak.redact("Office: 03-12345678", include=MY_ENTITIES)
print(result.text)
# → Office: <MY_LANDLINE>

result = kloak.redact("Pejabat kami: 04-1234567", include=MY_ENTITIES)
print(result.text)
# → Pejabat kami: <MY_LANDLINE>


# --- SSM company registration ------------------------------------------------

result = kloak.redact("SSM registration 1234567-A")
print(result.text)
# → SSM registration <MY_SSM>


# --- Mixed Manglish / real-world message ------------------------------------

text = (
    "IC saya 880101-01-1234. "
    "Hubungi 012-3456789 atau pejabat 03-12345678 kalau ada soalan."
)
result = kloak.redact(text, include=MY_ENTITIES)
print(result.text)
# → IC saya <MY_IC>. Hubungi <MY_MOBILE> atau pejabat <MY_LANDLINE> kalau ada soalan.

print("Entities found:")
for entity in result.entities:
    print(f"  {entity.type}: '{text[entity.start:entity.end]}'")
