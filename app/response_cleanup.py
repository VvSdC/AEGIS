"""Remove governance boilerplate that models sometimes echo into chat replies."""

from __future__ import annotations

import re

_CAN_FULFILL = re.compile(
    r"^\s*I can fulfill this request\.?\s*$",
    re.IGNORECASE | re.MULTILINE,
)
_COMPLIANCE_STATEMENT = re.compile(
    r"^\s*Compliance Statement:\s*\n+([\s\S]*?)(?=\n\n\S|\Z)",
    re.IGNORECASE | re.MULTILINE,
)
_REGULATION_ECHO = re.compile(
    r"^\s*(?:NITI Aayog|Digital Personal Data Protection|DPDPA|Information Technology Act|"
    r"RBI Data Localization|GDPR|PIPL|EU AI Act)[^\n]*:.*$",
    re.IGNORECASE | re.MULTILINE,
)


def strip_visible_compliance_boilerplate(text: str) -> str:
    """Drop common compliance echoes; keep the substantive answer."""
    if not text:
        return text
    cleaned = text
    cleaned = _CAN_FULFILL.sub("", cleaned)
    cleaned = _COMPLIANCE_STATEMENT.sub("", cleaned)
    cleaned = _REGULATION_ECHO.sub("", cleaned)
    cleaned = re.sub(r"\n{3,}", "\n\n", cleaned)
    return cleaned.strip()
