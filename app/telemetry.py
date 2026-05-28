"""Shared helpers for guardrail match telemetry in audit logs."""

from collections import defaultdict
from typing import Any, Iterable, Optional


def pii_type_from_filter(name: str) -> Optional[str]:
    if not name or not name.startswith("pii_"):
        return None
    core = name[4:]
    if core.endswith("_hard"):
        core = core[:-5]
    elif core.endswith("_soft"):
        core = core[:-5]
    return core.replace("_", " ").title()


def threat_category_from_filter(name: str) -> Optional[str]:
    lower = (name or "").lower()
    if lower.startswith("pii_"):
        return "pii"
    if "jailbreak" in lower or lower.startswith("yara_jailbreak"):
        return "jailbreak"
    if "injection" in lower:
        return "injection"
    if "toxicity" in lower:
        return "toxicity"
    if lower.startswith("code_") or "insecure_code" in lower:
        return "insecure_code"
    if lower.startswith("tier2_"):
        return "tier2"
    return None


def entity_label_from_filter(filter_name: str, category: str = "") -> str:
    """Human-readable entity label without exposing matched content."""
    pii = pii_type_from_filter(filter_name)
    if pii:
        return pii
    name = (filter_name or "").strip()
    if not name:
        return (category or "Unknown").replace("_", " ").title()
    if name.startswith("yara_"):
        return name[5:].replace("_", " ").title()
    if name.startswith("code_"):
        return name[5:].replace("_", " ").title()
    if name.startswith("tier2_"):
        return name[6:].replace("_", " ").title()
    return name.replace("_", " ").title()


def entities_from_matches(matches: Iterable[Any]) -> list[str]:
    """Unique identified entity labels for UI when content is withheld."""
    labels: list[str] = []
    seen: set[str] = set()
    for m in list(matches or []):
        if isinstance(m, dict):
            filter_name = m.get("filter_name", "")
            category = m.get("category", "")
        else:
            filter_name = getattr(m, "filter_name", "") or ""
            category = getattr(m, "category", "") or ""
        label = entity_label_from_filter(filter_name, category)
        if label not in seen:
            seen.add(label)
            labels.append(label)
    return labels


def summarize_guardrail_matches(matches: Iterable[Any]) -> dict:
    """Build compact telemetry from tier1/tier2 filter matches."""
    match_list = list(matches or [])
    pii_types: set[str] = set()
    threat_counts: dict[str, int] = defaultdict(int)

    for m in match_list:
        if isinstance(m, dict):
            filter_name = m.get("filter_name", "")
            category = m.get("category", "")
        else:
            filter_name = getattr(m, "filter_name", "") or ""
            category = getattr(m, "category", "") or ""

        pii_label = pii_type_from_filter(filter_name)
        if pii_label:
            pii_types.add(pii_label)

        cat = threat_category_from_filter(filter_name) or (
            category.split("_")[0] if category else None
        )
        if cat:
            threat_counts[cat] += 1

    return {
        "match_count": len(match_list),
        "pii_types": sorted(pii_types),
        "threat_counts": dict(threat_counts),
    }
