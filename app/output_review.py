"""Interactive output review: threshold gating, PII redaction, code regen policy."""

from __future__ import annotations

import hashlib
from typing import List, Optional, Set, Tuple

from .engines.guardrails import get_guardrail_engine
from .schemas import OutputGuardrailResult, OutputReviewFinding, OutputReviewState, OutputTier1Result

MAX_REGENERATIONS = 2
CRITICAL_CODE_FLOOR = 0.80

REGION_MAP = {
    "india": "INDIA",
    "china": "APAC",
    "europe": "EU",
    "usa": "US",
    "australia": "AUSTRALIA",
}


def _finding_id(category: str, matched_text: Optional[str], description: str, index: int) -> str:
    raw = f"{category}:{matched_text or ''}:{description}:{index}"
    return hashlib.sha256(raw.encode()).hexdigest()[:12]


def _code_requires_regen(findings: List[OutputReviewFinding], threshold: float) -> bool:
    for f in findings:
        if f.category != "insecure_code":
            continue
        if f.confidence >= threshold:
            return True
        if f.severity == "critical" and f.confidence >= CRITICAL_CODE_FLOOR:
            return True
    return False


def _pii_findings_from_text(text: str, region: str) -> List[OutputReviewFinding]:
    engine = get_guardrail_engine()
    internal_region = REGION_MAP.get(region, region)
    _, pii_matches, _, _ = engine._run_pii_filter(text, region=internal_region)
    findings: List[OutputReviewFinding] = []
    seen: Set[str] = set()
    for idx, m in enumerate(pii_matches):
        if not m.matched_text or m.matched_text in seen:
            continue
        seen.add(m.matched_text)
        label = m.filter_name.replace("pii_", "").replace("_HARD", "").replace("_SOFT", "").replace("_", " ")
        severity = "critical" if "HARD" in m.filter_name else "warning"
        findings.append(
            OutputReviewFinding(
                id=_finding_id("pii", m.matched_text, m.filter_name, idx),
                category="pii",
                severity=severity,
                description=f"Potential PII: {label}",
                matched_text=m.matched_text,
                confidence=m.confidence,
                label=label.title(),
            )
        )
    return findings


def _code_findings_from_guardrail(tier1: Optional[OutputTier1Result]) -> List[OutputReviewFinding]:
    if not tier1:
        return []
    findings: List[OutputReviewFinding] = []
    for idx, f in enumerate(tier1.findings):
        if f.category != "insecure_code":
            continue
        findings.append(
            OutputReviewFinding(
                id=_finding_id("insecure_code", f.matched_text, f.description, idx),
                category="insecure_code",
                severity=f.severity,
                description=f.description,
                matched_text=f.matched_text,
                confidence=f.confidence,
                label=f.description[:80],
            )
        )
    return findings


def evaluate_output_review(
    response_text: str,
    output_guardrail: Optional[OutputGuardrailResult],
    security_threshold: float,
    region: str,
    *,
    regenerations_used: int = 0,
) -> Tuple[OutputReviewState, Optional[str]]:
    """Decide if user review is required. Returns (review_state, preview_content)."""
    if not output_guardrail or not response_text.strip():
        return OutputReviewState(status="delivered"), response_text

    tier1 = output_guardrail.tier1
    pii_findings = _pii_findings_from_text(response_text, region)
    code_findings = _code_findings_from_guardrail(tier1)
    all_findings = pii_findings + code_findings

    has_pii = len(pii_findings) > 0
    has_code = len(code_findings) > 0
    code_regen = _code_requires_regen(code_findings, security_threshold)
    regenerations_remaining = max(0, MAX_REGENERATIONS - regenerations_used)

    trigger_reasons: List[str] = []
    if has_pii:
        trigger_reasons.append("pii")
    if code_regen:
        trigger_reasons.append("insecure_code")

    requires_action = has_pii or code_regen
    max_code_conf = max((f.confidence for f in code_findings), default=None)

    allowed_actions: List[str] = []
    if has_pii:
        allowed_actions.append("apply_pii_redaction")
    if code_regen and regenerations_remaining > 0:
        allowed_actions.append("regenerate")
    allowed_actions.append("accept")

    if not requires_action:
        return (
            OutputReviewState(
                status="delivered",
                requires_user_action=False,
                security_threshold=security_threshold,
                findings=all_findings,
                has_pii_findings=has_pii,
                has_code_findings=has_code,
                max_code_confidence=max_code_conf,
            ),
            response_text,
        )

    return (
        OutputReviewState(
            status="pending_review",
            requires_user_action=True,
            trigger_reasons=trigger_reasons,
            max_code_confidence=max_code_conf,
            security_threshold=security_threshold,
            code_regen_available=code_regen and regenerations_remaining > 0,
            regenerations_remaining=regenerations_remaining,
            regenerations_used=regenerations_used,
            findings=all_findings,
            allowed_actions=allowed_actions,
            has_pii_findings=has_pii,
            has_code_findings=has_code,
        ),
        response_text,
    )


def apply_pii_redaction(
    text: str,
    findings: List[OutputReviewFinding],
    allowed_ids: Set[str],
) -> str:
    """Redact PII spans unless the finding id is in allowed_ids."""
    pii = [f for f in findings if f.category == "pii" and f.matched_text]
    if not pii:
        return text

    redact_targets = [f.matched_text for f in pii if f.id not in allowed_ids]
    if not redact_targets:
        return text

    redact_targets.sort(key=len, reverse=True)
    result = text
    for span in redact_targets:
        result = result.replace(span, "[REDACTED]")
    return result


def build_regeneration_instruction(
    code_findings: List[OutputReviewFinding],
    recommendations: List[str],
) -> str:
    lines = [
        "Your previous response was flagged by security analysis. Regenerate the full answer and fix these issues:",
        "",
    ]
    for i, f in enumerate(code_findings, 1):
        lines.append(f"{i}. [{f.severity}] {f.description} (confidence {f.confidence:.2f})")
        if f.matched_text:
            snippet = f.matched_text[:120].replace("\n", " ")
            lines.append(f"   Snippet: {snippet}")
    if recommendations:
        lines.append("")
        lines.append("Recommendations:")
        for r in recommendations:
            lines.append(f"- {r}")
    lines.append("")
    lines.append("Produce a corrected response without introducing new vulnerabilities.")
    return "\n".join(lines)


def collect_recommendations(output_guardrail: Optional[OutputGuardrailResult]) -> List[str]:
    if not output_guardrail or not output_guardrail.tier2:
        return []
    return list(output_guardrail.tier2.recommendations or [])
