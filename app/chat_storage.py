"""Content storage policy for governed chat messages."""

from typing import Optional, Tuple

from .engines.guardrails import FilterResult
from .input_pii_consent import tier1_has_pii


def resolve_user_storage(
    tier1_filter: FilterResult,
    *,
    pii_consent_pending: bool = False,
    chat_input: bool = False,
) -> Tuple[Optional[str], str, bool]:
    """
    Decide what user message content may be persisted.

    Returns:
        stored_content: text to save (None if withheld)
        storage_mode: full | redacted | withheld
        has_pii_soft: whether soft PII redaction was applied
    """
    if tier1_filter.blocked:
        return None, "withheld", False

    # Chat never auto-redacts PII — user must choose via consent first.
    if chat_input and (pii_consent_pending or tier1_has_pii(tier1_filter)):
        return None, "withheld", False

    if pii_consent_pending:
        return None, "withheld", False

    has_soft = any(m.category == "pii_soft_block" for m in tier1_filter.matches)
    if has_soft:
        return tier1_filter.filtered_text, "redacted", True

    return tier1_filter.filtered_text, "full", False
