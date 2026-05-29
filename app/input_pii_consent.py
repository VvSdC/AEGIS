"""Input PII consent: user chooses how to handle detected personal details before sending."""

from __future__ import annotations

from typing import Any, Iterable, List, Set

from .schemas import InputPiiConsentState, InputPiiEntity
from .telemetry import entity_label_from_filter, pii_type_from_filter

PII_CATEGORIES = frozenset({"pii_hard_block", "pii_soft_block", "pii"})


def is_pii_match(match) -> bool:
    category = (match.category if hasattr(match, "category") else match.get("category", "") or "").lower()
    if category in PII_CATEGORIES or category.startswith("pii"):
        return True
    filter_name = match.filter_name if hasattr(match, "filter_name") else match.get("filter_name", "")
    fn = (filter_name or "").lower()
    return fn.startswith("pii_") or fn.startswith("yara_pii")


def tier1_has_pii(tier1_filter) -> bool:
    return any(is_pii_match(m) for m in (tier1_filter.matches or []))


def has_non_pii_block(tier1_filter) -> bool:
    """True when tier1 blocked for jailbreak/injection, not PII alone."""
    if not tier1_filter.blocked:
        return False
    return any(not is_pii_match(m) for m in (tier1_filter.matches or []))


def chat_needs_pii_consent(tier1_filter, *, original_text: str = "") -> bool:
    """
    True when chat should show the PII consent UI.

    Any Tier-1 PII hit triggers consent unless blocked for a non-PII reason.
    Also triggers if legacy soft-redaction changed the text (e.g. phone numbers).
    """
    if has_non_pii_block(tier1_filter):
        return False
    if tier1_has_pii(tier1_filter):
        return True
    if original_text and tier1_filter.filtered_text != original_text:
        return True
    return False


def prepare_tier1_for_pii_consent(tier1_filter, original_text: str) -> None:
    """Clear PII hard-block flags so chat can ask the user instead of rejecting."""
    tier1_filter.blocked = False
    tier1_filter.block_reason = None
    tier1_filter.filtered_text = original_text

PII_HARMS_EXPLANATION = (
    "Personal details can identify you or someone else. If they are sent to an AI service, "
    "they may be stored, logged, or used in ways you did not intend. Sharing them can increase "
    "the risk of identity theft, fraud, harassment, or privacy violations."
)


def _entity_id_from_match(filter_name: str) -> str:
    label = pii_type_from_filter(filter_name) or filter_name
    return "pii_" + label.lower().replace(" ", "_")


def _kind_label_from_match(filter_name: str, category: str) -> str:
    """Short label for a single PII match type (shown under the entity name)."""
    base = entity_label_from_filter(filter_name, category)
    fn = (filter_name or "").lower()
    if "hard" in fn or (category or "").lower() == "pii_hard_block":
        return f"{base} — detected as sensitive (requires your OK to send)"
    if "soft" in fn or (category or "").lower() == "pii_soft_block":
        return f"{base} — may be redacted if not selected"
    if category:
        return f"{base} ({category.replace('_', ' ')})"
    return base


def build_input_pii_entities(
    matches: Iterable[Any],
    *,
    original_text: str = "",
) -> tuple[List[InputPiiEntity], List[dict]]:
    """
    Build user-visible entity list (names only) and internal findings with spans for redaction.

    Entity names are always listed when a PII match exists, even if matched_text was stripped
    from API payloads. Spans are filled when available for allow-some redaction.
    """
    internal: dict[str, dict] = {}
    for m in list(matches or []):
        if not is_pii_match(m):
            continue
        category = m.category if hasattr(m, "category") else m.get("category", "")
        filter_name = m.filter_name if hasattr(m, "filter_name") else m.get("filter_name", "")
        matched = (m.matched_text if hasattr(m, "matched_text") else m.get("matched_text", "")) or ""
        entity_id = _entity_id_from_match(filter_name)
        entity_name = entity_label_from_filter(filter_name, category)
        kind_label = _kind_label_from_match(filter_name, category)
        if entity_id not in internal:
            internal[entity_id] = {
                "id": entity_id,
                "entity_name": entity_name,
                "spans": [],
                "kinds": [],
            }
        kinds: list = internal[entity_id]["kinds"]
        if kind_label and kind_label not in kinds:
            kinds.append(kind_label)
        if matched and matched not in internal[entity_id]["spans"]:
            internal[entity_id]["spans"].append(matched)

    entities = [
        InputPiiEntity(
            id=v["id"],
            entity_name=v["entity_name"],
            kinds=list(v.get("kinds") or []),
        )
        for v in internal.values()
    ]
    entities.sort(key=lambda e: e.entity_name.lower())
    return entities, list(internal.values())


def scan_pii_for_consent(guardrail_engine, text: str, region: str) -> tuple[List[InputPiiEntity], List[dict]]:
    """Run a consent-mode PII scan and return entities + internal findings with spans."""
    _, pii_matches, _, _ = guardrail_engine._run_pii_filter(
        text,
        region=region,
        consent_on_detect=True,
    )
    return build_input_pii_entities(pii_matches, original_text=text)


def ensure_consent_findings(
    guardrail_engine,
    text: str,
    region: str,
    matches: Iterable[Any],
) -> tuple[List[InputPiiEntity], List[dict]]:
    """Prefer live scan; fall back to any tier-1 matches."""
    entities, internal = scan_pii_for_consent(guardrail_engine, text, region)
    if entities:
        return entities, internal
    entities, internal = build_input_pii_entities(matches, original_text=text)
    if entities:
        return entities, internal
    return [], []


def apply_input_pii_redaction(text: str, internal_findings: List[dict], allowed_ids: Set[str]) -> str:
    """Redact spans for entity types not in allowed_ids."""
    spans: List[str] = []
    for finding in internal_findings:
        if finding["id"] in allowed_ids:
            continue
        spans.extend(finding.get("spans") or [])
    if not spans:
        return text
    spans.sort(key=len, reverse=True)
    result = text
    for span in spans:
        if span:
            result = result.replace(span, "[REDACTED]")
    return result


def format_input_pii_consent_message(entities: List[InputPiiEntity]) -> str:
    names = ", ".join(e.entity_name for e in entities)
    return (
        "We found personal details in your message"
        + (f" ({names})" if names else "")
        + ".\n\n"
        + PII_HARMS_EXPLANATION
        + "\n\n"
        "Choose **Don't allow** to keep your message private, **Allow some** to pick what may be sent, "
        "or **Allow all** to send your message unchanged."
    )


def consent_state_for_api(meta: dict, message_id: int) -> InputPiiConsentState | None:
    raw = meta.get("pii_consent")
    if not raw:
        return None
    entities = [InputPiiEntity(**e) for e in (raw.get("entities") or [])]
    status = raw.get("status", "pending")
    return InputPiiConsentState(
        status=status,
        entities=entities,
        requires_user_action=status == "pending",
        user_message_id=message_id,
    )
